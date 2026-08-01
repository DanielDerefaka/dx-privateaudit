# High: Missing payload-size bound in the realtime TCP message reader -> unauthenticated single 8-byte packet node crash -> network confirmation halt

**Target:** nanocurrency/nano-node (Nano L1 node, C++, develop/v29)  
**Severity:** High  
**Slug:** `nano-node-asc-pull-unauth-crash-halt`

## Impact

Any peer crashes any nano-node with a single unauthenticated ~8-byte packet; sprayed at quorum-weight reps it halts network-wide transaction confirmation.

## Proof of Concept

systest/poc_asc_pull_chain_halt.sh drives REAL nano_node processes (baseline confirms -> 8-byte crash packet aborts the sole quorum rep -> post-attack send no longer confirms). Also 7 core_test gtests including a live dev-node ASSERT_DEATH abort ('read buffer size mismatch') and a Python multi-node network-halt harness on separate real daemons. asc_pull size 9 + uint16 extensions reaches 65544 > 65536 buffer, tripping release_assert before async_read.

## Submission notes / caveats

Merged from the nano-node folder ISSUE-1 and the top-level nano-node audit (same defect). Fully unauthenticated, pre-handshake, first-packet. Standalone crash is unambiguous High (CVSS 7.5); Critical is the documented composition (spray quorum-weight reps -> network-wide confirmation halt), recoverable on restart but re-triggerable. Availability/DoS only (clean assert, not RCE).

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `nano-node/validated_issues/ISSUE-1.md`
- [`nano-node-security-audit.md`](./nano-node-security-audit.md) — write-up, from `nano-node-security-audit.md`
- [`nano-node-asc_pull-dos-bugreport.md`](./nano-node-asc_pull-dos-bugreport.md) — write-up, from `nano-node-asc_pull-dos-bugreport.md`
- [`POC__poc_asc_pull_chain_halt.sh`](./POC__poc_asc_pull_chain_halt.sh) — PoC, from `nano-node/systest/poc_asc_pull_chain_halt.sh`
- [`POC__poc_asc_pull_dos_chain_halt.cpp`](./POC__poc_asc_pull_dos_chain_halt.cpp) — PoC, from `nano-node/nano/core_test/poc_asc_pull_dos_chain_halt.cpp`
