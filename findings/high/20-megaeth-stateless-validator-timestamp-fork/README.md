# High: Missing timestamp validation lets a malicious block source pick the EVM fork ruleset and get an invalid block accepted/committed

**Target:** MegaETH stateless-validator (Rust, reth-based)  
**Severity:** High  
**Slug:** `megaeth-stateless-validator-timestamp-fork`

## Impact

A malicious/compromised sequencer backdates one header field to select a permissive fork (MiniRex, unlimited state growth) and gets the validator to accept and persist a block that is invalid under the live fork.

## Proof of Concept

Unit PoC e2e_accept_invalid.rs (real mega-evm: same block+witness returns Ok under backdated MiniRex vs Err(ReceiptsRootMismatch) under honest Rex) and full-pipeline PoC e2e_pipeline_accept_invalid.rs (real RpcClient + run_pipeline + ValidatorDB commits the invalid-under-Rex block to CANONICAL_CHAIN). The real mainnet genesis (chainId 4326) has a genuinely staggered fork schedule.

## Submission notes / caveats

Block source is documented as UNTRUSTED (README 'maliciously injected data'), so no trusted-role cap. Auditor downgraded Critical->High honestly: in-repo impact is false-assurance / silent STF-rule violation (no in-repo value-loss consumer), and the recommended op-node deployment would keep such a block off-canonical. Escalates to Critical only if shown to gate a value-bearing downstream (not determinable from this repo).

## Files in this folder

- [`report.md`](./report.md) — write-up, from `stateless-validator/report.md`
- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `stateless-validator/validated_issues/ISSUE-1.md`
- [`SRC__e2e_accept_invalid.rs`](./SRC__e2e_accept_invalid.rs) — source, from `stateless-validator/crates/stateless-core/tests/e2e_accept_invalid.rs`
