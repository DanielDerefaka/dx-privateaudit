# Critical: Unauthenticated remote DoS — malformed block-gossip timestamp (>=2^63) crashes the Mina daemon before any validation (network-wide chain halt)

**Target:** MinaProtocol/mina (L1 daemon, develop @ 213bb49bf6 / o1Labs-requested 439da4c)  
**Severity:** Critical  
**Slug:** `mina-gossip-timestamp-daemon-crash`

## Impact

Any peer crashes any Mina node (and, by flooding producers/seeds, halts the chain) with one crafted gossip message, before any proof or consensus check.

## Proof of Concept

rg1_crash drives the REAL Transition_handler.Block_sink.push with timestamp=2^63 -> process exit 1; rg1_net does a two-node real-libp2p round-trip crashing the victim. Re-confirmed on o1Labs commit 439da4c on a VPS build and against a live testnet-synced node; fix verified by re-execution.

## Submission notes / caveats

o1Labs actively requested validation against commit 439da4c (live engagement). Pre-auth/pre-validation, any gossip peer, negligible cost. Clean submit.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `mina/validated_issues/ISSUE-1.md`
- [`C-01_remote_daemon_crash_report.md`](./C-01_remote_daemon_crash_report.md) — write-up, from `mina/C-01_remote_daemon_crash_report.md`
- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `mina/AUDIT_REPORT.md`
- [`SRC__rg1_crash.ml`](./SRC__rg1_crash.ml) — source, from `mina/src/lib/transition_handler/rg1_crash/rg1_crash.ml`
