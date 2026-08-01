# ISSUE-1: Missing payload-size bound in the realtime TCP message reader (unauthenticated single-packet node crash → network confirmation halt)

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High (per-node primitive, CVSS 7.5) — credible, demonstrated escalation to Critical for the network-wide confirmation-halt composition
**Original Claimed Severity**: High (standalone) / Critical (composed)
**Pipeline Exit Point**: Step 4 (full adversarial verification; no early invalidation held)
**Confidence**: HIGH

## Summary
An inbound TCP peer can crash any nano-node with a single unauthenticated ~8-byte
packet. The live realtime receive path (`tcp_server::receive_message_impl`) derives a
payload length of up to 65544 bytes directly from the attacker-controlled 16-bit header
`extensions` field for an `asc_pull_req`/`asc_pull_ack` message, then requests a read of
that size into a fixed 65536-byte buffer with no upper-bound check. The read helper's
`release_assert(target_size <= buffer->size())` (unconditional in all builds) fires and
`abort()`s the process. Every mechanical claim in the report was verified against source.

## Location
- `nano/node/transport/tcp_server.cpp:278` — `payload_size = header.payload_length_bytes()` (no bound check)
- `nano/node/transport/tcp_server.cpp:283` — `read_socket(payload_size)` into the 65536-byte member buffer
- `nano/node/transport/tcp_socket.cpp:311` — `release_assert(target_size <= buffer->size(), "read buffer size mismatch")` → abort
- `nano/node/transport/tcp_server.hpp:73` — `max_buffer_size = 64 * 1024` (65536)
- `nano/messages/asc_pull.cpp:107-111` — `size = partial_size(9) + extensions(≤65535)` = up to 65544
- `nano/messages/message_header.cpp:61-63` — `extensions` read raw off the wire (0x0000–0xFFFF)

## Justification
Every load-bearing claim was confirmed by reading the current `develop` source:

1. **Missing bound is real.** Between computing `payload_size` (tcp_server.cpp:278) and
   issuing the read (:283), the only preceding checks are header validity (:261),
   `is_valid_message_type` (:265 — `asc_pull_req` returns true), network match (:269), and
   `version_using >= protocol_version_min` (:273). None bound the size. A grep of
   tcp_server.cpp finds no `payload_size >` / `buffer->size()` / `MAX_MESSAGE_SIZE` guard.

2. **Attacker controls the size.** `asc_pull_req::size()` returns `9 + narrow_cast<uint16_t>(extensions)`;
   `extensions` is deserialized as a raw uint16 with no masking. `extensions=0xFFFF` ⇒ 65544 > 65536.
   Boundary is `extensions >= 0xFFF8`.

3. **The abort is unconditional.** assert.hpp defines `release_assert` OUTSIDE the `NDEBUG`
   guard (only `debug_assert` is compiled out). `assert_internal` is `[[noreturn]]` and
   aborts. So the crash occurs in Debug AND Release builds.

4. **It is the LIVE inbound path.** `tcp_listener::on_connection` (tcp_listener.cpp:448-450)
   builds a `tcp_socket` from every accepted inbound socket, wraps it in a `tcp_server`, and
   calls `start()`. `start_impl` → `perform_handshake` → `receive_message` →
   `receive_message_impl` runs on the very FIRST inbound message, before any node-id
   handshake / signature / PoW. Fully unauthenticated. The older `message_deserializer`
   (which DID bound the size, message_deserializer.cpp:72-77) is now used only by the
   in-process transport (`inproc.cpp`); the coroutine rewrite dropped the check on the TCP
   path (git: "Coroutine server"/"Coroutine socket"). This is a regression.

5. **No payload bytes needed.** The `release_assert` sits at the TOP of `co_read_impl`
   (tcp_socket.cpp:311), before `async_read`. The node aborts while *requesting* the read,
   so only the 8-byte header must be sent.

No invalidation hypothesis survived: not dead code, not release-build-safe, not admin-gated,
not intended (the sibling path enforces the bound), no other guard present, size is
attacker-controlled, and the network/version/type checks are all trivially satisfiable and
do not bound size.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence |
|---|--------|--------|---------|----------|
| 1 | Coroutine path is dead code; message_deserializer still used | Adversarial | FAILS | tcp_listener.cpp:448-450 starts tcp_server for all inbound; message_deserializer only in inproc.cpp |
| 2 | release_assert compiled out in release builds | Adversarial | FAILS | assert.hpp:12-21 release_assert is outside NDEBUG guard; debug_assert (:23-35) is the gated one |
| 3 | A size bound exists elsewhere on this path | Generic (input-validation) | FAILS | grep of tcp_server.cpp: only lines 21/278/283 touch payload_size/buffer; no guard |
| 4 | payload_size not attacker-controlled | Adversarial | FAILS | message_header.cpp:61-63 reads extensions raw; asc_pull.cpp:109 uses it directly |
| 5 | Crash requires sending the full 65544-byte payload | Adversarial | FAILS | assert at tcp_socket.cpp:311 precedes async_read; 8-byte header suffices |
| 6 | network/version/type checks gate the attack | Generic (access-control) | FAILS | all satisfiable with public constants; none bound size |
| 7 | "Even honest peers crash the node" | Report sub-claim | PARTIAL/overstated | legit asc_pull_ack ≤128 blocks ≈ 28KB < 65536; honest peers don't trigger — immaterial to the malicious primitive |

## Severity
- **Per-node primitive**: unauthenticated remote DoS, single 8-byte packet, zero cost,
  re-triggerable on restart. CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` = **7.5 High**. Beyond dispute.
- **Composed (spray at reps holding quorum weight)**: crashing a quorum of online voting
  weight prevents blocks from reaching `delta = 67% × max(online, trended, online_weight_minimum)`,
  halting confirmation network-wide until operators restore the reps. This "network unable to
  confirm new transactions" outcome is the top availability tier for an L1 and is standardly
  scored **Critical**. The composition follows directly from documented quorum mechanics and
  is demonstrated by the report's PoCs; no step of it failed review. Recoverable (restart
  resumes) but sustainable by an attacker who keeps re-crashing.

## Suggested Fix
Bound the requested read on the realtime path before issuing it (mirroring
message_deserializer.cpp:72), and reconcile the buffer size so a protocol-legal maximum
payload fits:
```cpp
// tcp_server.cpp, after computing payload_size (:278):
if (payload_size > buffer->size ()) {
    co_return nano::deserialize_message_result{ nullptr, nano::deserialize_message_status::message_size_too_big };
}
```
and set `tcp_server::max_buffer_size >= message_deserializer::MAX_MESSAGE_SIZE` (66560).

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — code location, mechanism, impact all present; every referenced file/function/line verified to exist and match.
- **Step 2 (Privileged Roles)**: NO_ISSUE — attack is fully unauthenticated; no privileged role in the path. No severity cap.
- **Step 3 (Generic Check)**: input-validation and access-control invalidations checked → both FAIL (no guard present; gates don't bound size).
- **Step 4 (Adversarial Check)**: 6 issue-specific hypotheses generated and checked against source; none held. Verdict: VALID.
- **Final Severity**: High (floor) with demonstrated Critical composition (network confirmation halt).
