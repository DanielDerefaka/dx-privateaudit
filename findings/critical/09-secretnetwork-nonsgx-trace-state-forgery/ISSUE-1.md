# ISSUE-1: Non-SGX Replay Nodes Apply Unauthenticated Remote Execution Traces — Arbitrary State Forgery / Native-Token Inflation

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full adversarial pass)
**Confidence**: HIGH (mechanism re-confirmed by direct code reading, not just PoC output)

## Summary
SecretNetwork's official non-SGX "replay" node line fetches per-block execution traces
from a remote SGX node over **plaintext, unauthenticated gRPC** and applies the embedded
`CrossModuleOp` mutations directly to the real consensus multistore — with no transport
authentication, no integrity/consensus binding, and no write-target restriction. The
vulnerability is real and confirmed against genuine production code paths. The verdict is
Critical, with a precise severity caveat about the canonical-network impact precondition.

## Location (independently verified by direct read)
- `go-cosmwasm/api/replay.go:12-13` — `// We trust the SGX node's trace data completely.`
- `go-cosmwasm/api/replay.go:34-50` — infinite poll loop, no timeout, no integrity check
- `go-cosmwasm/api/replay.go:70-73` — stashes attacker `CrossOps` for the keeper to apply
- `go-cosmwasm/api/ecall_client.go:459-461` — `grpc.WithTransportCredentials(insecure.NewCredentials())`
- `x/compute/internal/keeper/recording_multistore.go:219-232` — `ApplyCrossModuleOps` resolves an attacker-controlled `StoreKey` string and writes raw `{Key,Value}` / deletes, no whitelist
- `x/compute/internal/keeper/relay.go:85-89` + `keeper.go:750,959,1768,1887,2029` — production replay-mode apply sites in live WASM entrypoints
- `app/keepers/keepers.go:563` — `ak.ComputeKeeper.SetStoreKeys(sk)` populates `k.storeKeys` with ALL mounted module stores (bank/staking/gov/…) in production
- `go-cosmwasm/api/ecall_record.go:73-74` — `CrossModuleOp.StoreKey` is an attacker-controllable string

## Provenance (settles "is this planted code?")
- Replay subsystem introduced in `0e9d3d01c` by `bohdan@scrtlabs.com` (core dev), 2025-11-27.
- Billing/transport touched in `ca5f25fe8` by `bohdan@scrtlabs.com`, 2026-06-03.
- Commits present on `origin/master`, `origin/non-sgx-v1.25`, `origin/non-sgx-v1.25.0`.
- Conclusion: **genuine official SecretNetwork non-SGX code**, not an externally planted
  backdoor. The finding's subject is a legitimate (recent, experimental) feature line.

## Justification
- STEP 1 (sweep): PASS. All referenced files/functions/lines exist exactly as described and
  are internally consistent. Confirmed by reading source, not by trusting the report.
- STEP 2 (privileged roles): No trusted-actor downgrade. The attack does NOT reduce to "a
  trusted role rugs." A pure **network MITM on the plaintext link** (no privileged access,
  no pool compromise) suffices — `insecure.NewCredentials()` provides zero server
  authentication. The operator's intended "trust the configured SGX pool" is precisely what
  the implementation fails to cryptographically enforce.
- STEP 3 (generic invalidation): No generic reason holds. There is no input validation
  (only a store-name existence check that bank/staking/gov always pass); the path is fully
  reachable on normal chain operation (any compute tx triggers replay); not gated behind any
  privilege.
- STEP 4 (adversarial): Strongest invalidation considered = **AppHash divergence bounds
  canonical impact**. On a CometBFT network with an honest SGX-validator majority, a single
  corrupted non-SGX node that applies forged `CrossModuleOp`s computes a different AppHash
  than the 2/3+ majority → it does NOT mint canonical SCRT; it diverges and halts
  ("wrong AppHash") or serves wrong local data. The report's PoC 3 ran on a **single-validator
  regtest**, where the fed node IS the canonical chain — so it proves the mechanism + local
  forgery, but NOT network-wide canonical minting in a realistic multi-validator deployment.
  **This downgrades the report's headline framing but does NOT invalidate the finding**, because:
  (a) the transport + integrity flaws are real regardless of consensus topology;
  (b) the sub-threshold outcome is itself a consensus safety/liveness issue (≥1/3 non-SGX
      pointed at a poisoned/MITM'd source → chain halt; forks; slashing);
  (c) the active non-SGX validator rollout (dedicated `non-sgx-v1.25` branches +
      `9f08b0e50 emergency validator threshold reduced to 5`) makes ≥2/3 non-SGX
      voting power — and thus full canonical state forgery / token inflation — a plausible
      configuration for this fork;
  (d) a non-SGX RPC node serving forged balances has off-chain impact (exchange deposit
      crediting).

## Severity Decision: Critical (not downgraded)
- No privileged role required (untrusted network MITM is sufficient).
- Vulnerable code executes in the **live consensus state-machine path** (replay-mode keeper).
- Impact ceiling is catastrophic: arbitrary bank/staking/gov state forgery, native-token
  inflation, or chain halt.
- `insecure.NewCredentials()` for consensus-critical data is indefensible on its own.
- Honest caveat retained: network-wide *canonical* inflation is conditioned on non-SGX
  consensus voting-power thresholds; the sub-threshold outcome (AppHash divergence → local
  corruption + node halt) is still High-class on its own.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | "By design — non-SGX nodes must trust the SGX pool" | Step 4 | FAILS | Design intent is to trust *attested* SGX; plaintext `insecure` transport + no AppHash binding is exactly what the code fails to enforce. A MITM defeats it without any pool compromise. |
| 2 | Attack requires a trusted/privileged actor → downgrade | Step 2 | FAILS | Network MITM on the plaintext link is fully untrusted; no role betrayal needed. |
| 3 | Input validation guards the write target | Step 3 | FAILS | Only a store-name existence check (`storeKeys[op.StoreKey]`); bank/staking/gov resolve and write unrestricted Key/Value. |
| 4 | Not reachable / dead code | Step 3 | FAILS | Wired into Instantiate/Handle/Migrate/UpdateAdmin replay paths; any compute tx triggers it. Genuine official code on master + release branches. |
| 5 | Production would panic (storeKeys empty) → harness fakes it | Step 4 | FAILS | `app/keepers/keepers.go:563` populates `k.storeKeys` with all mounted stores in production; the test_common.go change faithfully mirrors this (+1 block), not a fabrication. |
| 6 | AppHash divergence prevents canonical impact | Step 4 | PARTIAL (severity caveat, not invalidation) | True for SGX-majority deployments at the single-node level; bounded by non-SGX voting-power thresholds; sub-threshold outcome is still halt/local-corruption. Calibrated into severity, does not negate. |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all locations verified by direct read; report internally consistent.
- **Step 2 (Privileged Roles)**: NO downgrade — untrusted network MITM is a sufficient actor.
- **Step 3 (Generic Check)**: 0 of the applicable generic invalidations hold.
- **Step 4 (Adversarial Check)**: strongest reason (AppHash divergence) is a severity caveat, not an invalidation. Judge verdict: VALID.
- **Final Severity**: Critical (caveated).

## Notes / caveats on the report itself
- The executive framing ("any network attacker can mint SCRT from nothing") slightly
  overstates the *unconditional* canonical-network outcome; it holds outright on the
  single-validator PoC and on ≥2/3-non-SGX deployments, while a lone corrupted non-SGX node
  on an SGX-majority network diverges/halts rather than minting canonical tokens. The
  underlying vulnerability is unaffected by this nuance.
- PoCs 1 & 2 (unit mechanism + real-gRPC e2e) carry the mechanism proof and are
  platform-independent; the verdict does not depend on independently re-running PoC 3.
  (Prior session memory noted arm64 cannot run the live node; the report claims a Docker
  arm64 PoC 3 — treat PoC 3 as supporting, not load-bearing.)
- The `billingAuthInterceptor` (ecall_client.go:462-464) authenticates the *client to the
  server* (billing), not the server to the client — it does nothing for trace integrity or
  server impersonation.
