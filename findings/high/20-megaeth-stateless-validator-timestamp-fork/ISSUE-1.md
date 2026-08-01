# ISSUE-1: Missing timestamp validation lets a malicious block source pick the EVM fork ruleset and get an invalid block accepted

## Pipeline Result
**Verdict**: VALID (severity-adjusted)
**Final Severity**: High
**Original Claimed Severity**: Critical (for the validator itself; author explicitly hedges downstream blast radius)
**Pipeline Exit Point**: Step 4 (issue-specific adversarial + scope adjudication)
**Confidence**: HIGH (mechanism), MEDIUM (severity — hinges on an undocumented scope boundary + deployment)

## Summary
The stateless validator selects the entire EVM ruleset — `MegaSpecId` (opcode/gas via `create_evm_env` → `spec_id`) and the per-fork `BlockLimits` (via `hardfork` → e.g. the state-growth cap) — purely from the unvalidated `header.timestamp`. Nothing on the standalone path binds that timestamp to the parent or enforces monotonicity, so a malicious/compromised block source can backdate it to select an older, more permissive fork (MiniRex: unlimited state growth) and get a block that is invalid under the live fork (Rex: cap 1000) accepted and committed to the persistent `CANONICAL_CHAIN`. The mechanism is fully confirmed by reading the code and by two PoCs that execute the real code paths. Severity is reduced from Critical to High because (a) the in-repo impact is false assurance / silent undetected STF-rule violation rather than a direct value-loss gate, and (b) the README's recommended `op-node` deployment derives L2 timestamps from L1+DA and would keep such a block off the canonical chain fed to the validator.

## Location
- `crates/stateless-core/src/executor.rs:205` — `create_evm_env`: `CfgEnv::new_with_spec(chain_spec.spec_id(header.timestamp))`
- `crates/stateless-core/src/executor.rs:336–347` — `replay_block`: `hardfork(header.timestamp)` → `BlockLimits::from_hardfork_and_block_gas_limit(...)`
- `crates/stateless-core/src/executor.rs:213,219–221` — `base_fee_per_gas` / `excess_blob_gas` consumed from header, not re-derived from parent (secondary vector, same class)
- `bin/stateless-validator/src/chain_sync.rs:114–130` — `verify_continuity` checks only pre-state-root and pre-withdrawals-root
- `crates/stateless-core/src/db.rs:25–30` — `BlockMeta` has no timestamp field (monotonicity check structurally impossible)
- `crates/stateless-core/src/pipeline/advancer.rs:132` — advancer checks only `parent_hash`
- `crates/stateless-common/src/rpc_client.rs:1098–1147` — `verify_block_integrity` checks hash / tx-root / signer only

## Justification
**Mechanism — CONFIRMED, independent of the report.**
- Direct code read confirms the ruleset (spec + limits) is a pure function of `header.timestamp`; `validate_block` never bounds or compares it.
- The **real mainnet genesis** (`test_data/mainnet/genesis.json`, chainId 4326 — matches the PoC) has a genuinely staggered schedule: `miniRexTime:0`, `rexTime:1764851940`, `rex4Time:1776659200`, `rex5Time:1780632000`. So a backdated `timestamp=1` selects MiniRex on the *production* schedule — the PoC's synthetic genesis is a faithful reproduction, not a fabricated artifact. This knocks out the single strongest potential invalidator.
- The **unit PoC executes against real mega-evm**: under Rex the growth tx *halts* (0 contract writes, gas 22188106), under MiniRex it runs fully (1010 writes, gas 2042348060); `validate_block` returns `Ok` under backdated MiniRex and `Err(ReceiptsRootMismatch)` under honest Rex — same `(block, witness)`, only the timestamp differs. This verifies the state-growth-limit enforcement claim by execution, not assumption.
- The **full-pipeline PoC executes** the real `RpcClient` (block verification ON by default) + `run_pipeline` + `ValidatorProcessor` + on-disk `ValidatorDB` and commits the invalid-under-Rex block to `CANONICAL_CHAIN[1000]`.
- Exhaustive search found **zero** timestamp validation on the standalone path and **no** reth/alloy consensus header validation invoked anywhere in the repo. Premise could not be refuted.

**Threat actor — within the documented threat surface (no trusted-role cap).** `README.md` §Scope-and-Trust-Model explicitly frames the block source as untrusted: it "will validate whatever sequence of blocks is supplied, including forks, stale heads, or **maliciously injected data**" (:152) and the recommended setup exists "to avoid **trusting a third-party RPC provider**" (:158). So the adversary (malicious/compromised sequencer or RPC serving injected data) is a documented untrusted party — this is not a "trusted admin rugs" scenario, and the Step-2 trusted-role severity cap does not apply.

**The severity hinge — an undocumented scope boundary.** The same README section delegates *canonicality* to `op-node`: the validator "does not verify that the blocks it receives form the canonical chain" (:151); "Determining canonicality requires a consensus client" (:153–154). The unresolved question is whether a backdated-timestamp fork-downgrade is an **in-scope STF defect** (the validator's job) or an **out-of-scope canonicality/derivation defect** (op-node's job). No project document decides it. Adjudication:
- The carve-out is worded around *ordering / forks / stale heads / reorgs* — selection **among** blocks — not around whether a single block's header fields are consistent enough to trust its fork selection.
- The fork ruleset is an **input to the STF** the validator claims to verify. "Verify the STF is correct under the block's own declared timestamp" is a near-tautology that would make the validator unable to catch a whole class of execution-rule violations — contradicting its advertised value of an "independently implemented state transition function to reduce single-client risk" (audit §2.1.2; `README.md:148,162`). Therefore treating fork-selection soundness as within the STF remit is the better reading, and the finding is **not foreclosed** by any documented scope statement.

**Why High, not Critical (Step-4 downgrade).**
- Impact within this repo is **false assurance / silent undetected STF violation**, not a direct value-loss gate: the verdict's only effects are a write to the local `CANONICAL_CHAIN` and an *optional* report to one upstream node via `mega_setValidatedBlocks` (`workers.rs:129–169`). No signing, bridge, fraud-proof, finality, or slashing consumer exists in-repo.
- The **recommended op-node deployment materially mitigates** exploitability: OP-Stack L2 timestamps are deterministically derived from L1+DA, so a backdated block would fail derivation and never reach the validator as canonical.

**Why not lower than High.** It is a genuine, cheap, deterministic soundness break (single backdated field) in a consensus-critical component whose sole purpose is independent STF verification; the block source is explicitly untrusted; a supported standalone-RPC mode (defaults enable it) has no op-node protection; and relying on op-node for fork-correctness makes it a single point of failure for the exact rule (state-growth limit) that keeps MegaETH state bounded — undermining the multi-client-diversity rationale. Severity would escalate to Critical if the verdict is shown to gate any value-bearing downstream (bridge / fraud-proof / finality) — not determinable from this repo.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | PoC uses a fabricated staggered genesis; real chain activates all forks at genesis so `spec_id(ts)` is constant | Adversarial (generator) | FAILS | Real `test_data/mainnet/genesis.json` staggers MiniRex(0)→Rex(1764851940)→Rex5(1780632000); backdating genuinely downgrades the fork |
| 2 | Some layer validates `header.timestamp` (monotonicity/bound/drift) | Generic (input-validation) | FAILS | Exhaustive search: zero VALIDATES hits; `BlockMeta` has no timestamp field; no reth consensus header validation invoked |
| 3 | mega-evm doesn't actually enforce different limits per fork / doesn't halt | Adversarial | FAILS | Unit PoC executes: Rex halts the tx (0 writes), MiniRex runs it (1010 writes) — verified, not assumed |
| 4 | Attack requires a trusted role (sequencer) to act maliciously → severity cap | Generic (trusted-role) | FAILS | README documents block source as untrusted ("maliciously injected data", "avoid trusting a third-party RPC") |
| 5 | PoC "calibrates" the state root / uses synthetic pre-state → cheats validation | Adversarial | FAILS | Calibrated root = what an honest MiniRex sequencer would publish; attacker *is* the sequencer; block passes all real checks incl. verify_block_integrity |
| 6 | Backdated fork-downgrade is a canonicality defect → out-of-scope (op-node's job) → INVALID/Low | Adversarial (design-intent) | PARTIAL (downgrade only) | Canonicality carve-out is about ordering/forks/reorgs, not within-block fork-selection; fork is an STF input; not foreclosed by docs — supports Critical→High, not invalidation |
| 7 | Impact is a direct value-loss (bridge/fraud-proof/finality) → Critical | (author's implied ceiling) | FAILS (caps severity) | No such consumer in-repo; verdict is local-persist + optional single-node report → false assurance |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — location, mechanism, impact all present and internally consistent; all cited files/functions/lines exist and match.
- **Step 2 (Privileged Roles)**: NO_CAP — attacker is the block source, documented as untrusted; trusted-role severity cap does not apply.
- **Step 1.5 (External Research)**: N/A — no external protocol dependency; the one external-fact claim (mega-evm per-fork limits) was verified by executing the PoC rather than by web research.
- **Step 3/4 (Generic + Adversarial Check)**: 7 invalidation reasons tested (table above); the only surviving reason (#6) is a severity limiter, not an invalidator. Two PoCs re-executed and passed; real mainnet genesis confirmed the staggered schedule; three parallel investigators confirmed premise (no timestamp check), threat model (source untrusted; scope hinge undocumented), and impact consumption (false assurance, no value-loss gate).
- **Final Severity**: High (adjusted from Critical) — soundness break confirmed; capped below Critical by false-assurance-only in-repo impact and op-node deployment mitigation.

## Notes / Recommendation
Root cause is a single missing check. Fix: carry `timestamp` in `BlockMeta` and enforce non-decreasing (ideally OP-derivation-consistent) timestamps in `verify_continuity`; and re-derive `base_fee_per_gas` / `excess_blob_gas` from the parent per EIP-1559/4844 instead of trusting the header. The secondary `base_fee`/`excess_blob_gas` observation is the same class of bug (unvalidated header consensus fields) and should be fixed together.
