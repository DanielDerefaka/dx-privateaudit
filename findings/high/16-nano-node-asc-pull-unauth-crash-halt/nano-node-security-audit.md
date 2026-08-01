# Security Audit — nano-node v29 (develop)

**Auditor:** automated whitehat hunt (enumerate-then-target methodology, find≠judge, adversarial verification, on-chain PoC)
**Date:** 2026-06-26
**Scope:** the full `nano-node` C++ codebase (ledger, consensus/ORV, crypto, networking, store)
**Build/PoC vehicle:** `core_test` gtest binary built with `-DACTIVE_NETWORK=nano_dev_network -DNANO_TEST=ON` (real ledger + `nano::test::system` dev-network harness)

---

## Executive summary

An exhaustive, adversarially-verified hunt (16 breadth/deep-dive agents + 13 skeptic refutations across value-conservation, double-spend, epoch handling, signatures/PoW, rollback, fork/cementing, vote/quorum, and network memory-safety) produced a clear, honest result:

- **No fund-loss or consensus-safety Critical exists in the core protocol logic.** Every such candidate (value inflation on receive, double-receive/replay, epoch-block value change, cemented-block rollback, two-conflicting-blocks-cemented, confirm-without-quorum, forged/replayed votes) was **refuted by a specific, quoted guard in the real code.** This is a strong positive result for Nano's ledger/consensus soundness — see "Refuted criticals" for the exact guards.
- **One genuine, remotely-triggerable vulnerability was confirmed:** an **unauthenticated single-packet remote node crash (DoS)** via an oversized `asc_pull` payload-length field. Severity **High (CVSS 3.1 ~7.5, AV:N/AC:L/PR:N/UI:N/A:H)**; for a live payment network the trivially-scriptable, network-wide liveness impact is arguably Critical. It is a clean `abort()` (the assertion prevents the out-of-bounds read), so it is **availability/DoS, not memory corruption/RCE.**

| Severity | Count | Finding |
|----------|-------|---------|
| High | 1 | H-01 — Unauthenticated single-packet remote node crash via `asc_pull` payload size |
| (Refuted) | 8 | value/consensus criticals — each blocked by a quoted guard |

---

## H-01 — Unauthenticated single-packet remote node crash (DoS)

**Severity:** High (CVSS 3.1 base ~7.5; network-wide liveness impact for a payment network)
**Class:** availability / unbounded read request vs fixed buffer → fatal assertion
**Status:** confirmed by source-level verification of the full chain; on-chain PoC: see "PoC" below.
**Location:** `nano/node/transport/tcp_server.cpp:278-283` (+ `tcp_socket.cpp:311`, `tcp_server.hpp:73`, `messages/asc_pull.cpp:107-111`, `messages/message_header.cpp:61-63,244-247`, `lib/assert.hpp:11`)

### Description

On every inbound TCP connection, `tcp_server::receive_message_impl()` reads the 8-byte message header, then reads a payload of `header.payload_length_bytes()` bytes into a **fixed 65536-byte buffer** — with **no size guard**:

```cpp
// tcp_server.cpp
auto const payload_size = header.payload_length_bytes ();           // :278  (no check that this <= buffer size)
auto payload_buffer = payload_size > 0 ? co_await read_socket (payload_size) : ...;  // :283
// read_socket -> socket->co_read(buffer, payload_size)  (buffer is the 65536-byte member)
```

```cpp
// tcp_socket.cpp  co_read_impl
release_assert (target_size <= buffer->size (), "read buffer size mismatch");   // :311  -> abort() when 65544 > 65536
```

For `asc_pull_req`/`asc_pull_ack`, the payload length is taken **directly from 16 attacker-controlled `extensions` bits** read raw off the wire:

```cpp
// messages/message_header.cpp deserialize()       (:61-63)  extensions = 16 raw wire bits, unmasked
// messages/asc_pull.cpp  asc_pull_req::size()      (:107-111)
uint16_t payload_length = nano::narrow_cast<uint16_t> (header.extensions.to_ulong ());
return partial_size /* = sizeof(asc_pull_type=1)+sizeof(id_t=uint64=8) = 9 */ + payload_length;  // up to 9 + 65535 = 65544
```

`asc_pull_req` is a valid message type (`is_valid_message_type()` → true), so the only checks preceding the payload read (type/network/version) all pass. `release_assert` is **unconditional in every build config** (`assert.hpp:11` — only `debug_assert` is gated by `NDEBUG`) and `assert_internal` is `[[noreturn]]` → `abort()`.

### Impact

- An attacker sends **8 bytes** (`type=asc_pull_req`, `extensions ≥ 0xFFF8`) as the very first packet on a new connection. The node reads the header, computes a 65544-byte payload read against its 65536-byte buffer, and **aborts before reading any payload and before any signature/PoW/handshake check** → fully **unauthenticated**.
- Trivially scriptable; re-triggerable on every restart → **persistent node-down**. Sprayable to all reachable peers → **network-wide liveness threat**.
- The abort is clean (the assert prevents the OOB read) → **DoS, not RCE**.
- Note the path asymmetry: the legacy `message_deserializer` path *accepts* this payload (`MAX_MESSAGE_SIZE = 66560`, with a `payload_size > MAX_MESSAGE_SIZE` rejection at `message_deserializer.cpp:71-74`), but the live realtime `tcp_server` buffer (65536) is **smaller** than that legal maximum — so even a *maximal honest* `asc_pull` crashes the node.

### Boundary

`payload_size = 9 + extensions`; abort iff `9 + extensions > 65536` iff `extensions ≥ 0xFFF8` (8 values, `0xFFF8..0xFFFF`).

### Recommendation

Add a size guard before the payload read, and reconcile the two paths' limits:

```cpp
// tcp_server.cpp, after computing payload_size (:278):
if (payload_size > buffer->size ()) {
    co_return nano::deserialize_message_result{ nullptr, nano::deserialize_message_status::message_size_too_big };
}
```
and make `tcp_server::max_buffer_size` (65536) ≥ the protocol's maximum legal payload (`message_deserializer::MAX_MESSAGE_SIZE` = 66560), so the realtime buffer can hold any payload a peer is permitted to send.

### PoC (build + dev-network)

Two `core_test` gtests were added (`nano/core_test/poc_asc_pull_dos.cpp`, `poc_asc_pull_dos_live.cpp`):
1. **Deterministic (mechanical proof):** constructs the real `message_header`, asserts `payload_length_bytes() == 65544` against the 65536-byte realtime buffer and the legacy/realtime asymmetry — proving the exact condition that drives the `release_assert`.
2. **Live ("regtest"):** spins up a real dev-network node, opens a raw TCP socket to `node->tcp_listener.endpoint()`, sends the 8 crafted header bytes, and asserts (via `ASSERT_DEATH`) the node `abort()`s with "read buffer size mismatch".

**Build:** `core_test` built successfully for the dev network (`-DACTIVE_NETWORK=nano_dev_network -DNANO_TEST=ON`, Debug; 128 MB binary). *(Build-env note: Apple clang 21 needed `-DFMT_CONSTEVAL=constexpr` to compile the pinned fmt/spdlog — a toolchain workaround, no logic change.)*

**Result — all 4 PoC tests PASS:**
```
[==========] Running 4 tests from 2 test suites.
[ RUN      ] poc_asc_pull_dos_DeathTest.live_dev_node_aborts_on_single_8byte_packet
[       OK ] poc_asc_pull_dos_DeathTest.live_dev_node_aborts_on_single_8byte_packet (313 ms)
[ RUN      ] poc_asc_pull_dos.payload_size_exceeds_realtime_buffer
[       OK ] poc_asc_pull_dos.payload_size_exceeds_realtime_buffer (0 ms)
[ RUN      ] poc_asc_pull_dos.realtime_vs_legacy_path_asymmetry
[       OK ] poc_asc_pull_dos.realtime_vs_legacy_path_asymmetry (0 ms)
[ RUN      ] poc_asc_pull_dos.minimal_trigger_boundary
[       OK ] poc_asc_pull_dos.minimal_trigger_boundary (0 ms)
[  PASSED  ] 4 tests.
```

**Captured live abort (real dev node, single 8-byte packet) — the smoking gun.** Running the live death test with a deliberately-wrong matcher makes gtest print the child node's actual termination message:
```
Death test: send_oversized_asc_pull_header_to_a_live_node ()
    Result: died but not with expected error.
Actual msg:
[  DEATH   ] Assertion `target_size <= buffer->size ()` failed: read buffer size mismatch
```
That is `release_assert` at `tcp_socket.cpp:311` firing inside a **live running node** because it received one 8-byte packet and computed a 65544-byte read against its 65536-byte buffer. **Confirmed on-chain (dev network): a single unauthenticated 8-byte packet crashes a running Nano node.**

**Reproduce:**
```
cmake -DACTIVE_NETWORK=nano_dev_network -DNANO_TEST=ON -DNANO_GUI=OFF .. && cmake --build . --target core_test
./core_test --gtest_filter='poc_asc_pull_dos*'
```

---

## Refuted criticals (coverage — why no fund/consensus Critical exists)

Each value/consensus candidate surfaced by the hunt was refuted by a specific guard located in the real code:

| Candidate (would be Critical if real) | Blocked by (quoted guard) |
|---|---|
| Value creation on receive (balance delta ≠ pending) | `ledger_processor.cpp:377` `result = amount == pending.value().amount ? progress : balance_mismatch;` (+ `:374 unreceivable` requires the pending to exist) |
| Double-receive / pending replay | receive consumes pending (`ledger.store.pending.del`); a second receive hits `:374 unreceivable` |
| Rollback recreates wrong pending amount | `ledger_rollback.cpp:144` recreates exactly `balance − previous_balance` (= the amount apply forced equal to the pending at `:377`); symmetric, no drift |
| Epoch block changing balance / forged epoch | `epoch_block_impl` only runs when `balance == prev_balance`; real epoch requires the `epoch_signer` signature (`epoch_block_impl`); non-epoch routes to `state_block_impl` and is independently authenticated |
| Two conflicting blocks both cemented | hash-agnostic height-gated cementing along the canonical chain (`ledger_set_cemented.cpp:63-71` via `bounded_dfs.hpp:85`); proving negative test ships as `TEST(ledger_cement, conflict_rollback_cemented)` |
| Cemented block rolled back | cement-floor rollback refusal (`ledger.cpp:592/608`) |
| Confirm without genuine quorum (stale `final_weight`) | stale gate is nested inside the fresh `have_quorum(tally_l)` gate (`election.cpp:509`/`:479`); only quorum-free consumer `try_confirm` is dead code |
| Forged/replayed votes confirm a block | votes are signature-validated before caching; cached votes route to a validated tally |

This is a genuinely valuable negative result: the core ledger/consensus invariants (value conservation, frontier uniqueness, confirmation finality, authorization) are well-guarded.

---

## Methodology & coverage

- **Enumerate-then-target:** 10 breadth agents, one per subsystem, each with a narrow invariant+mechanism-class lens; 49 candidates surfaced.
- **Find ≠ judge:** a separate adversarial skeptic refuted each High/Critical candidate by locating the exact blocking check; 8/9 refuted, 1 survived (H-01).
- **Consensus deep-dive:** 6 dedicated agents tried to *construct* a double-cement / confirm-without-quorum / cemented-rollback sequence; all 6 blocked with quoted guards.
- **Ground-truth verification:** every link of H-01 was personally re-read against source; all refutation guards were quoted from the real code.
- **Build + on-chain PoC:** `core_test` built for the dev network; PoCs run against the real ledger/transport.

## Artifacts (added to the repo for the PoC; reversible)
- `nano/core_test/poc_asc_pull_dos.cpp` — deterministic mechanical proof
- `nano/core_test/poc_asc_pull_dos_live.cpp` — live dev-node abort (regtest) death test
- `nano/core_test/CMakeLists.txt` — registers the PoC file(s)
- `CMakeLists.txt` — build-env workaround for Apple clang 21 + fmt consteval (no logic change)
