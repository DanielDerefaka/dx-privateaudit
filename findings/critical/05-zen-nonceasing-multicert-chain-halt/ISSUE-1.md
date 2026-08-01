# ISSUE-1: Missing per-block certificate-uniqueness check for non-ceasing sidechains lets any miner reach `assert(isBlockTopQualityCert)` in `ConnectBlock`, halting the network

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full pipeline; no invalidation reason held)
**Confidence**: HIGH

## Summary
A block containing two certificates for the same non-ceasing sidechain at consecutive epochs (N, N+1) is valid at `CheckBlock`/`ContextualCheckBlock` (the relaxed `CheckCertificatesOrdering` permits increasing epochs, and no block-level uniqueness rule exists), but trips `assert(isBlockTopQualityCert)` in `ConnectBlock` while processing the earlier-epoch cert — aborting the process of every full node that connects the block. Because the block is persisted before connection, nodes re-crash on restart (poison-block crash loop). Confirmed by independent static control-flow analysis of the real source plus a passing gtest death test. The crash precedes SNARK verification, so no valid proof / proving key is required.

## Location
- `src/main.cpp:3761-3764` — reachable `assert(isBlockTopQualityCert)` in `ConnectBlock`
- `src/main.cpp:2880-2887` — symmetric reachable assert in `DisconnectBlock`
- `src/main.cpp:980-1009` — `HighQualityCertData` records only the highest-epoch cert per scId
- `src/main.cpp:1047-1079` — `CheckCertificatesOrdering` relaxed (rejects only decreasing epoch/quality)
- `src/main.cpp:5179` — `CheckCertificatesOrdering` is the only `vcert` ordering gate in `CheckBlock`
- `src/main.cpp:1322` — uniqueness guard (`pool.certificateExists`) exists ONLY at mempool admission
- `src/coins.cpp:1172-1245` — `IsCertApplicableToState` does state checks only (no SNARK)
- `src/main.cpp:3969` — `BatchVerify` runs after the cert loop (after the assert)
- `src/sc/sidechain.cpp:158-206` — `CheckCertTiming` (non-ceasing requires epoch == lastTop+1)

## Justification
Every load-bearing claim was verified against the actual zend 6.0.0 source:

1. **Two same-scId certs at increasing epochs pass block validation.** `CheckCertificatesOrdering` (1047-1079) rejects only `bestEpoch > cert.epoch` (decreasing) or equal-epoch decreasing quality. For `[epoch N, epoch N+1]` neither fires. The function comment explicitly states the old "no 2+ certs for different epochs" rule was dropped for v2/non-ceasing. It is the sole `vcert` ordering gate in `CheckBlock` (called at 5179); the only other per-cert checks are semantic (`CheckCertificate`). No block-level per-scId uniqueness rule exists anywhere in `CheckBlock`/`ContextualCheckBlock` (grep-confirmed).

2. **The earlier-epoch cert becomes non-top.** `HighQualityCertData` (980-1009) reverse-iterates `vcert` and records one cert per scId — the last in block order (highest epoch). cert-N is therefore absent from the map.

3. **cert-N reaches the assert.** `ConnectBlock` processes certs in forward order. cert-N (index 0): `IsCertApplicableToState` (3720) runs unconditionally (NOT gated by `fScRelatedChecks`) and passes for a legitimate next-epoch cert (timing requires epoch == lastTop+1; cum-tree root must match real on-chain history; quality/balance/proof-size only). Then at 3761-3764 `isBlockTopQualityCert == false` and `isNonCeasing() == true` → `assert(false)` → abort. cert-N+1 is never processed.

4. **No proof/proving key needed.** `IsCertApplicableToState` never verifies the SNARK; `BatchVerify` is at 3969, after the loop. The assert aborts first. A dummy proof of valid size suffices. (Even otherwise, the attacker creates/controls their own non-ceasing sidechain.)

5. **PoC faithfulness.** The committed gtest death test reaches the assert through the real `IsCertApplicableToState` path; `flagScRelatedChecks::OFF` hides no defense because that flag gates only the commitment-tree builder (3642, 3850, 3945), all of which are either in the tx loop or after the assert. The PoC's own comments correctly state IsCertApplicableToState runs unconditionally.

**Severity.** Impact = permanent total network halt requiring manual per-node remediation (poison block survives restarts) — the canonical CRITICAL impact "network not being able to confirm new transactions." Likelihood = any miner producing one valid-PoW block (permissionless capability; cheap for an existing pool, rentable for an outsider on a modest-cap PoW chain). No downgrade modifier applies: the impact is availability (crosses on/off-chain boundary — exchanges/bridges stall, operators intervene), so the on-chain-only −1 does not apply; a miner is not a FULLY_TRUSTED actor, so the trusted-actor −1 does not apply. The only mitigating factor is the PoW/mining requirement, which narrows the actor set to "any miner" but does not lower the impact. High Impact × Medium–High Likelihood = **Critical** (conservative floor: High).

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | Requires privileged/trusted role | Step 2 (roles) | FAILS | Attacker is "any miner" — permissionless PoW capability, not owner/admin/governance; no trusted-actor downgrade |
| 2 | Intended design / known invariant | Step 3 (generic) | FAILS | Comment shows devs *assumed* the invariant; mempool-only guard (1322) shows uniqueness was intended but the block path was missed — an oversight, not design |
| 3 | A block-validation check rejects it | Step 3/4 | FAILS | `CheckCertificatesOrdering` deliberately relaxed for v2; no uniqueness rule in `CheckBlock`/`ContextualCheckBlock` (grep + read confirmed) |
| 4 | cert-N fails `IsCertApplicableToState` on mainnet | Step 4 (adversarial) | FAILS | Only state checks; epoch==lastTop+1, real cum-tree root, valid quality/balance/proof-size all satisfiable; runs before assert |
| 5 | PoC artificially reaches assert via flags | Step 4 (adversarial) | FAILS | `fScRelatedChecks` gates only commitment builder (3642) and post-assert paths (3850, 3945); IsCertApplicableToState + assert run regardless |
| 6 | Needs valid SNARK / proving key | Step 4 (adversarial) | FAILS | Assert at 3764 precedes `BatchVerify` at 3969; dummy valid-size proof suffices; attacker also controls own sidechain |
| 7 | Commitment-tree / scTxsCommitment rejects block | Step 4 (adversarial) | FAILS | Miner computes the valid commitment; the check is post-assert anyway |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — every cited location verified in real source; description internally consistent.
- **Step 2 (Privileged Roles)**: NO_DOWNGRADE — "any miner" is not a trusted role; PoW requirement affects likelihood only, not to Low.
- **Step 1.5 (External Research)**: N/A — no external protocol dependency (self-contained node consensus code).
- **Step 3 (Generic Check)**: 0 invalidation reasons held.
- **Step 4 (Adversarial Check)**: 5 issue-specific invalidation hypotheses generated and checked against source; judge verdict = VALID (none held).
- **Final Severity**: Critical (unchanged from claimed).
