// ============================================================================
// SECURITY PoC (authorized whitehat audit) — Multi-node confirmation-halt
// (chain-halt) demonstration.
//
// Composes with the single-packet crash PoC (poc_asc_pull_dos_live.cpp): an
// attacker who can abort individual nodes with one 8-byte asc_pull packet can
// crash a quorum of representatives and stop the whole network from confirming
// transactions — upgrading the impact from per-node DoS (High) to "total network
// shutdown / unable to confirm new transactions" (Critical).
//
// QUORUM MODEL (nano/node/online_reps.cpp delta(), election.cpp):
//   delta = online_weight_quorum% * max(cached_online, cached_trended, online_weight_minimum)
//   online_weight_quorum = 67. A block confirms iff backing weight >= delta.
//
// To make the demonstration DETERMINISTIC (independent of online-weight sampling
// and trend timing), this test pins online_weight_minimum = genesis_amount (G).
// Then delta = 0.67 * G at all times, regardless of how many reps are currently
// detected online. With 3 reps each holding G/3:
//   * all 3 vote   -> tally G       >= 0.67G = delta  -> confirmations WORK
//   * 1 rep left   -> tally G/3 ≈ 0.333G < 0.67G      -> confirmations HALT
// The realistic-floor variant (survivor below the real 60M-NANO online_weight_minimum
// floor) is demonstrated end-to-end with separate daemons in poc_asc_pull_network_halt.py.
// ============================================================================

#include <nano/lib/blockbuilders.hpp>
#include <nano/node/active_elections.hpp>
#include <nano/node/backlog_scan.hpp>
#include <nano/node/election.hpp>
#include <nano/node/network.hpp>
#include <nano/node/nodeconfig.hpp>
#include <nano/node/online_reps.hpp>
#include <nano/node/vote_router.hpp>
#include <nano/secure/ledger.hpp>
#include <nano/test_common/system.hpp>
#include <nano/test_common/testutil.hpp>

#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace
{
// 3 representatives, each receives genesis_amount / num_reps voting weight.
constexpr int num_reps = 3;
}

// ============================================================================
// TEST: network halts when a quorum of representatives is crashed
// ============================================================================
TEST (poc_asc_pull_dos_chain_halt, confirmation_stops_when_reps_crash)
{
	nano::test::system system;

	// --- Prepare 3 rep keypairs and distribute genesis weight (G/3 each) ---
	std::deque<nano::keypair> rep_keys;
	for (int i = 0; i < num_reps; ++i)
	{
		rep_keys.emplace_back ();
	}
	system.ledger_initialization_set (rep_keys);

	// --- 3 nodes, each holding one rep key. Pin the quorum floor at full genesis
	//     weight so delta = 0.67 * G deterministically (no online-sampling races). ---
	nano::node_config config = system.default_config ();
	config.online_weight_minimum = nano::dev::constants.genesis_amount;
	config.backlog_scan->enable = false;

	auto & node0 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[0]);
	auto & node1 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[1]);
	auto & node2 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[2]);

	// Full-mesh peering + ledger primed (genesis + send/open per rep)
	ASSERT_TIMELY (10s, node0.network.size () == 2 && node1.network.size () == 2 && node2.network.size () == 2);
	ASSERT_TIMELY_EQ (10s, node0.ledger.block_count (), 1 + 2 * num_reps);

	nano::uint128_t const genesis_amount = nano::dev::constants.genesis_amount;
	nano::uint128_t const rep_weight = genesis_amount / num_reps; // each rep's voting weight = G/3

	// ======================================================================
	// PHASE 1: all reps online — confirmations WORK
	// ======================================================================
	auto const latest0 = node0.latest (rep_keys[0].pub);
	ASSERT_FALSE (latest0.is_zero ()) << "rep0 must have an open block";

	nano::keypair dest;
	auto send1 = nano::state_block_builder{}
				 .make_block ()
				 .account (rep_keys[0].pub)
				 .previous (latest0)
				 .representative (rep_keys[0].pub)
				 .balance (rep_weight - 1)
				 .link (dest.pub)
				 .sign (rep_keys[0].prv, rep_keys[0].pub)
				 .work (*system.work.generate (latest0))
				 .build ();

	// Put the block on every node, then start + drive the election on node0.
	nano::test::process (node0, { send1 });
	nano::test::process (node1, { send1 });
	nano::test::process (node2, { send1 });
	auto election1 = nano::test::start_election (system, node0, send1->hash ());
	ASSERT_NE (nullptr, election1) << "Election must start when all reps online";

	// All three reps vote: tally = G >= 0.67G = delta -> quorum reached.
	ASSERT_EQ (nano::vote_code::vote, node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send1 })).at (send1->hash ()));
	ASSERT_EQ (nano::vote_code::vote, node0.vote_router.vote (nano::test::make_final_vote (rep_keys[1], { send1 })).at (send1->hash ()));
	ASSERT_EQ (nano::vote_code::vote, node0.vote_router.vote (nano::test::make_final_vote (rep_keys[2], { send1 })).at (send1->hash ()));

	ASSERT_TIMELY (10s, election1->confirmed ());
	// Cementing (ledger confirmation_height update) is asynchronous after the
	// election reaches quorum, so poll block_confirmed rather than asserting it
	// synchronously.
	ASSERT_TIMELY (15s, node0.block_confirmed (send1->hash ()));
	ASSERT_TIMELY (15s, node1.block_confirmed (send1->hash ()));
	ASSERT_TIMELY (15s, node2.block_confirmed (send1->hash ()));

	// ======================================================================
	// PHASE 2: crash a quorum of reps (stop 2 of 3) — confirmations HALT
	// ======================================================================
	system.stop_node (node1);
	system.stop_node (node2);
	WAIT (3s);
	ASSERT_TRUE (node1.stopped);
	ASSERT_TRUE (node2.stopped);

	auto send2 = nano::state_block_builder{}
				 .make_block ()
				 .account (rep_keys[0].pub)
				 .previous (send1->hash ())
				 .representative (rep_keys[0].pub)
				 .balance (rep_weight - 2)
				 .link (dest.pub)
				 .sign (rep_keys[0].prv, rep_keys[0].pub)
				 .work (*system.work.generate (send1->hash ()))
				 .build ();

	nano::test::process (node0, { send2 });
	auto election2 = nano::test::start_election (system, node0, send2->hash ());
	ASSERT_NE (nullptr, election2) << "Election starts even with reps down";

	// Only the lone surviving rep can vote: G/3 < 0.67G = delta -> insufficient.
	ASSERT_EQ (nano::vote_code::vote, node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send2 })).at (send2->hash ()));
	WAIT (5s);

	// CHAIN HALT: the block cannot reach quorum and stays unconfirmed.
	ASSERT_FALSE (election2->confirmed ()) << "Chain halt: lone rep cannot reach quorum";
	ASSERT_FALSE (node0.block_confirmed (send2->hash ())) << "Chain halt: block must not confirm";
	ASSERT_TRUE (node0.block_or_pruned_exists (send2->hash ())) << "Block exists in ledger but uncemented";

	// Direct proof: quorum delta exceeds any single rep's weight, so no lone
	// surviving rep can ever confirm.
	auto const delta = node0.online_reps.delta ();
	ASSERT_GT (delta, rep_weight) << "delta=" << nano::amount{ delta }.to_string_dec ()
								  << " rep_weight=" << nano::amount{ rep_weight }.to_string_dec ();
}

// ============================================================================
// TEST: confirmations RESUME once the crashed reps are restarted
// ============================================================================
TEST (poc_asc_pull_dos_chain_halt, confirmations_resume_after_reps_recover)
{
	nano::test::system system;

	std::deque<nano::keypair> rep_keys;
	for (int i = 0; i < num_reps; ++i)
	{
		rep_keys.emplace_back ();
	}
	system.ledger_initialization_set (rep_keys);

	nano::node_config config = system.default_config ();
	config.online_weight_minimum = nano::dev::constants.genesis_amount;
	config.backlog_scan->enable = false;

	auto & node0 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[0]);
	auto & node1 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[1]);
	auto & node2 = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[2]);

	ASSERT_TIMELY (10s, node0.network.size () == 2 && node1.network.size () == 2 && node2.network.size () == 2);
	ASSERT_TIMELY_EQ (10s, node0.ledger.block_count (), 1 + 2 * num_reps);

	nano::uint128_t const genesis_amount = nano::dev::constants.genesis_amount;
	nano::uint128_t const rep_weight = genesis_amount / num_reps;

	// --- Confirm a first block with full quorum (network works) ---
	auto const latest0 = node0.latest (rep_keys[0].pub);
	ASSERT_FALSE (latest0.is_zero ());
	nano::keypair dest;
	auto send1 = nano::state_block_builder{}
				 .make_block ()
				 .account (rep_keys[0].pub)
				 .previous (latest0)
				 .representative (rep_keys[0].pub)
				 .balance (rep_weight - 1)
				 .link (dest.pub)
				 .sign (rep_keys[0].prv, rep_keys[0].pub)
				 .work (*system.work.generate (latest0))
				 .build ();
	nano::test::process (node0, { send1 });
	nano::test::process (node1, { send1 });
	nano::test::process (node2, { send1 });
	auto election1 = nano::test::start_election (system, node0, send1->hash ());
	ASSERT_NE (nullptr, election1);
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send1 }));
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[1], { send1 }));
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[2], { send1 }));
	ASSERT_TIMELY (10s, node0.block_confirmed (send1->hash ()));

	// --- Crash a quorum of reps → chain halts ---
	system.stop_node (node1);
	system.stop_node (node2);
	WAIT (3s);

	auto send2 = nano::state_block_builder{}
				 .make_block ()
				 .account (rep_keys[0].pub)
				 .previous (send1->hash ())
				 .representative (rep_keys[0].pub)
				 .balance (rep_weight - 2)
				 .link (dest.pub)
				 .sign (rep_keys[0].prv, rep_keys[0].pub)
				 .work (*system.work.generate (send1->hash ()))
				 .build ();
	nano::test::process (node0, { send2 });
	auto election2 = nano::test::start_election (system, node0, send2->hash ());
	ASSERT_NE (nullptr, election2);
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send2 }));
	WAIT (5s);
	ASSERT_FALSE (node0.block_confirmed (send2->hash ())) << "Chain must be halted while quorum is down";

	// --- Restart BOTH crashed reps (recovery) → full voting weight returns ---
	// Operators restart every crashed node; online voting weight returns to G,
	// the stalled block reaches quorum (G >= 0.67G = delta) and confirms again.
	auto & node1b = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[1]);
	auto & node2b = *system.add_node (config, nano::node_flags{}, nano::transport::transport_type::tcp, rep_keys[2]);
	ASSERT_TIMELY (15s, node0.network.find_node_id (node1b.get_node_id ()) != nullptr);
	ASSERT_TIMELY (15s, node0.network.find_node_id (node2b.get_node_id ()) != nullptr);

	// Bring recovered ledgers up to date (send1 is a gap dependency for send2).
	nano::test::process (node1b, { send1, send2 });
	nano::test::process (node2b, { send1, send2 });

	// Re-trigger the election now that the reps are back, and re-vote with full weight.
	auto election2b = nano::test::start_election (system, node0, send2->hash ());
	ASSERT_NE (nullptr, election2b) << "Election should restart on node0";
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send2 }));
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[1], { send2 }));
	node0.vote_router.vote (nano::test::make_final_vote (rep_keys[2], { send2 }));

	// Confirmations RESUME once the crashed reps are restarted.
	ASSERT_TIMELY (15s, node0.block_confirmed (send2->hash ()));
}
