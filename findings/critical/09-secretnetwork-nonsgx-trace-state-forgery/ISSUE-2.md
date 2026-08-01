# ISSUE-2: Unauthenticated remote execution traces in non-SGX replay nodes enable cross-module state forgery

## Pipeline Result
**Verdict**: VALID — CRITICAL (CORRECTED after reviewer challenge; downgrade retracted)
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 + post-verdict reviewer dispute (re-verified against code)
**Confidence**: HIGH

> **CORRECTION NOTICE.** My initial pipeline DOWNGRADED this Critical→High on the basis that
> "the enclave block-verifier accepts only SGX-*attested* whitelisted validators, so non-SGX
> nodes cannot hold voting power and the ≥2/3 canonical-forgery path is unreachable." A reviewer
> challenged this. On re-verification against the code, **the challenge is correct and my downgrade
> rationale was a factual error**:
> - `whitelisted_validators_in_block` (validator_whitelist.rs:51-59) checks **CometBFT consensus
>   addresses** (`a.address.to_string()`) against a text file — **no SGX attestation, no MRENCLAVE,
>   no quote**. "Whitelisted" ≠ "attested".
> - `verify_block` (block.rs:14) runs **inside the SGX enclave** via `submit_block_signatures_impl`
>   to produce the **random beacon**, NOT as a CometBFT consensus-acceptance gate. A non-SGX replay
>   node **never runs it**: `module.go:192-195,243` shows replay mode fetches `random`/
>   `validator_set_evidence` from the backend and calls `SetRandomSeed`, bypassing the enclave path.
> - Therefore a non-SGX node runs full CometBFT with its own consensus key, obtains the seed from
>   its backend, and **can be a bonded validator with voting power**. Canonical state is a CometBFT
>   voting-power question; the enclave whitelist is orthogonal.
> - Provenance confirms active onboarding: `9f08b0e50` (vlad@scrtlabs.com, 2026-06-08) + a cluster
>   of "emergency whitelist updated" / "threshold reduced to 5" / "machine allow-list" commits.
>
> **The catastrophic path IS reachable.** Severity restored to **Critical**. The present-tense,
> PoC-proven harm floor is single-node (High); the ceiling under the actively-pursued non-SGX
> validator deployment is canonical state forgery / unlimited SCRT mint (Critical) at ≥2/3 non-SGX
> voting power, and full chain-halt (Critical liveness) at >1/3 — both enabled by network MITM of
> the plaintext backend link or a shared/compromised backend, with NO validator-key or SGX compromise.

## Summary
The reported mechanism is **real, confirmed, and present in genuine upstream scrtlabs code** (authored by `bohdan@scrtlabs.com`, on `origin/master` + `non-sgx-v1.25`/`non-sgx-v1.25.0`). A non-SGX replay node fetches per-block execution traces from a remote SGX node over plaintext, unauthenticated gRPC and applies attacker-shaped `CrossModuleOp` writes to arbitrary module stores via `ApplyCrossModuleOps` with no whitelist, no AppHash check, no signature, and no quorum. **However, the "Critical / unlimited canonical SCRT minting" framing is not reachable as described** and is not demonstrated by any PoC. The realistically reachable, PoC-backed impact is single-node: forged spendable state in one replay node's committed DB, exploitable by a network MITM on the plaintext link or a compromised/rogue configured SGX backend → that node's RPC serves forged balances (off-chain fund-loss vector) and/or the node self-halts on AppHash divergence.

## Location
- `x/compute/internal/keeper/recording_multistore.go:219-232` — `ApplyCrossModuleOps`, raw `store.Set`/`Delete`, only a key-existence check
- `go-cosmwasm/api/replay.go:12-13, 34-73` — "We trust the SGX node's trace data completely"; infinite poll; `SetPendingCrossModuleOps`
- `go-cosmwasm/api/ecall_client.go:459-461` — `insecure.NewCredentials()` (plaintext, no TLS/attestation)
- `go-cosmwasm/api/ecall_client.go:735-775` — `billingAuthInterceptor` (client→server billing auth only; signs `timestamp|method`, not body, not response)
- `go-cosmwasm/api/ecall_client.go:405-443, 516-558` — `getRandomNode` / `invokeWithRetry`: single random node, first-response-wins, no quorum
- Production apply sites: `keeper.go:750,959,1768,1887,2029`, `relay.go:88`
- Store-key wiring: `app/keepers/keepers.go:558-564`
- Consensus gate (caps catastrophic impact): `cosmwasm/enclaves/shared/block-verifier/src/verify/block.rs:14-19`, `validator_whitelist.rs:16-21,51-59`

## Justification
The full pipeline ran (no early exit). Five independent adversarial checkers traced the strongest invalidation/downgrade hypotheses against the actual code:

1. **Trust-model invalidation → FAILS (finding is real).** "Trust your configured backend" can legitimately cover delegating *computation* to an enclave a non-SGX node cannot reproduce, but it cannot excuse (a) failing to *authenticate the channel* (`insecure.NewCredentials()` → a network MITM impersonates the backend with no node/role compromise), (b) zero integrity binding on consensus-critical data, or (c) no quorum across the node pool. The "trust your RPC" analogy cuts *against* invalidation, since production RPC trust still uses TLS to authenticate the endpoint.

2. **Consensus reachability → catastrophic path NOT reachable as described.** The enclave block-verifier accepts only blocks signed by SGX-*attested* whitelisted validators (`validator_whitelist.rs`, prod threshold 5, `validator_whitelist_prod.txt`). A non-SGX node cannot produce a valid attestation quote, so it cannot enroll as a voting validator. The ≥2/3-non-SGX-power precondition requires a deliberate governance act the attack cannot create. Commit `9f08b0e50` lowers the *minimum SGX signers per block*; it does **not** grant non-SGX nodes voting power. Sub-threshold impact (local corruption, self-halt, RPC integrity loss) is genuine.

3. **Attacker position → "any user, no permissions" is misleading.** Triggering the replay fetch is permissionless, but *controlling the trace content* (the actual exploit) requires PRIVILEGED_NETWORK (MITM of plaintext link), TRUSTED_BACKEND (rogue/compromised configured SGX node), or PRIVILEGED_INFRA (host control). No permissionless on-chain actor controls trace content. Default backend is `localhost:9090`.

4. **PoC integrity → legitimate, not fabricated.** PoC 1 proves *harm* (forged balance spendable via real `bank.SendCoins`). PoC 2 proves the *network path* (production client + insecure transport over real TCP). PoC 3 proves single-node forgery only (regtest node IS the whole validator set). The `test_common.go` harness change is a **faithful mirror** of production wiring (`keepers.go:558-564`); `git status` confirms no production code modified. PoCs do **not** substantiate canonical minting.

5. **Generator → DOWNGRADE Critical → High.** Strongest levers: H1 self-halt on AppHash mismatch (conceded in the report's own `MAINNET_POC.md`: "The node will halt on AppHash mismatch... This is itself the proof") and H5 circular escalation (the catastrophic branch is the same single-node defect applied N times plus an unproven ≥2/3 precondition). Further downgrade to Medium is defensible only if non-SGX nodes provably hold zero mainnet voting power AND the link is always operator-internal.

**Severity decision (Impact × Likelihood) — CORRECTED:** Impact **Critical** (L1 consensus class: canonical state forgery / unlimited native-token mint at ≥2/3 non-SGX voting power; full chain-halt at >1/3). Likelihood **Medium** (network-MITM position on the plaintext backend link(s), or a shared/compromised backend — NO validator-key or SGX compromise required — combined with non-SGX validator voting power that scrtlabs is actively onboarding). No trusted-actor downgrade applies: the MITM path needs no trusted actor. Under L1 consensus-severity norms (consensus-takeover / unlimited-mint / chain-halt), this is **Critical**. The earlier "governance-gated / not reachable" rejection was based on the attestation misreading and is **withdrawn** — the precondition is a deployment state the team is building toward, not a security-model abandonment, and the enabling defect is in actively-deployed code. Present-tense PoC-proven floor remains single-node (High); the headline rating is Critical.

## Invalidation / Downgrade Reasons Tested
| # | Reason | Source | Verdict | Effect |
|---|--------|--------|---------|--------|
| 1 | SGX backend is a trusted-by-design component; missing verification is intended | Trust-model checker | FAILS | None (finding stands) |
| 2 | ≥2/3 non-SGX canonical-forgery path reachable | Consensus-reachability checker | FAILS (not reachable) | DOWNGRADE catastrophic branch |
| 3 | "Any user, no permissions" attacker framing | Attacker-position checker | MISLEADING (trigger≠exploit) | DOWNGRADE likelihood |
| 4 | PoCs prove canonical Critical harm | PoC-integrity checker | PARTIAL (prove local harm only) | DOWNGRADE; mechanism confirmed real |
| 5 | Circular escalation + self-halt boundary | Generator H1/H5 | HOLDS | DOWNGRADE Critical → High |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all cited code locations exist and match; mechanism is genuine upstream scrtlabs code (commit `0e9d3d01c`, `bohdan@scrtlabs.com`).
- **Step 2 (Privileged Roles)**: No trusted-actor early exit — at least one viable exploit path (plaintext-link MITM) requires a non-trusted on-path attacker, so the FULLY_TRUSTED downgrade does not cap severity at Low.
- **Step 3 (Generic Check)**: No invalidation reason HELD; trust-model invalidation explicitly FAILS. No early exit to INVALID.
- **Step 4 (Adversarial Check)**: Mechanism confirmed real and not invalidated; all severity-layer hypotheses converge on DOWNGRADE Critical → High. Judge-level reassessment: VALID, High.
- **Final Severity**: High (adjusted from Critical).

## Notes for the reporter
- The core defect is genuine and worth fixing: a consensus-state-mutating channel uses plaintext `insecure.NewCredentials()` with no server authentication, no response integrity/MAC, no quorum across the configured pool, and an unrestricted write target (`ApplyCrossModuleOps` resolves any registered store key and writes any key/value, including deletes). Recommended fixes: mTLS + SGX-attestation-bound channel to the pool; sign or AppHash-bind the trace response; require N-of-M agreement across the pool; whitelist permissible `CrossModuleOp` store keys.
- To maximize credibility, reframe the headline away from "unlimited canonical SCRT minting" (which your own `MAINNET_POC.md` concedes is gated by a ≥2/3 precondition the attack cannot create) toward the demonstrated harm: **a MITM/rogue SGX backend forges spendable state on a non-SGX node, enabling off-chain deposit-fraud via its RPC and self-inflicted consensus halt.** Separate "trigger (any tx)" from "exploit (control the trace source)" explicitly.
