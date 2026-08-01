# Critical: Unbounded bridge-deposit amount/tip overflows int64 -> uncaught panic in oracle EndBlocker -> deterministic chain halt with no self-heal

**Target:** Tellor Layer L1 (x/bridge deposit-claim reached from x/oracle EndBlocker)  
**Severity:** Critical  
**Slug:** `tellor-layer-bridge-overflow-chain-halt`

## Impact

A reporter coalition can attest one fabricated deposit that panics every validator's EndBlocker at the same height, freezing the entire chain with no on-chain remediation.

## Proof of Concept

TestBridgeDepositOverflowHaltsEndBlocker: 5 reporters submit a malicious value that aggregates on-chain and the real oracle.EndBlocker panics 'negative coin amount: -8446744073709551616'. Reproduced 3 ways against pinned real deps; layerd built and ran a live single-validator devnet to height 23+.

## Submission notes / caveats

Gated by a ~33-50% reporter-power attestation quorum (an adversary modeled inside ADR1012's defended zone, so no trusted-role downgrade). SECURITY.md enumerates no explicit scope list and no public bounty was located — needs private scope confirmation (info@tellor.io) before submission.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `layer/validated_issues/ISSUE-1.md`
- [`report.md`](./report.md) — write-up, from `layer/report.md`
- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `layer/AUDIT_REPORT.md`
- [`POC__claim_deposit_overflow_test.go`](./POC__claim_deposit_overflow_test.go) — PoC, from `layer/tests/integration/claim_deposit_overflow_test.go`
