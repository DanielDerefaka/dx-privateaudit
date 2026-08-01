# ISSUE-1: Missing cross-state validation on `x/mint` `MaxSupply` lets a parameter update drive ecosystem mint supply negative, halting `BeginBlocker` unrecoverably

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full pipeline; no early exit)
**Confidence**: HIGH

## Summary
A mint whitelist admin (or a genesis author) can commit params that make the remaining ecosystem
mint supply negative while `Params.Validate()` returns `nil`. The next `BeginBlocker` then panics or
returns an error, which CometBFT converts into `CONSENSUS FAILURE` on every validator
simultaneously. Because `BeginBlock` precedes all transaction delivery, no on-chain transaction can
correct it. Nine invalidation reasons were tested and all nine failed. The mechanism was reproduced
three independent ways, including a controlled real-binary regtest.

## Location
- `x/mint/keeper/emissions.go:265-278` — `GetEcosystemMintSupplyRemaining`, unclamped subtraction
- `x/mint/types/params.go:82-132` — `Params.Validate()`, stateless only; no cross-state check
- `x/mint/keeper/msg_server.go:33,41,77` — whitelist gate, validate, then unguarded `Params.Set`
- `x/mint/module/abci.go:109` — Sink A, `sdk.NewCoin` with an unchecked negative amount
- `x/mint/keeper/emissions.go:376-386` — Sink B, `ErrNegativeCirculatingSupply` (month boundary)
- `x/mint/keeper/emissions.go:237-245` via `x/mint/module/abci.go:144` — Sink C, every block
- `x/mint/module/module.go:183` — returns the error rather than swallowing it
- `x/mint/types/genesis.go:38-61` — `ValidateGenesis`, checks `IsNegative()` only

## Justification

**The mechanism is confirmed, three independent ways.**

1. *In-process, real keepers.* The submitted PoC was re-run from a clean build and passes:
   `ecosystemMintSupplyRemaining = -28100000000000000000000000`, and the real `mint.BeginBlocker`
   panics on both block 2 and block 3.
2. *Real message path.* A checker drove the actual `msgServiceServer.UpdateParams` handler with a
   real emissions keeper and a whitelisted admin, `RecalculateTargetEmission: false`. It returned a
   `nil` error, the regressed `MaxSupply` persisted, and `BeginBlocker` panicked. This closes the
   biggest gap in the submitted evidence, which had bypassed the msg server via `Params.Set`. The
   write at `msg_server.go:77` happens *before* the optional recalculation block at `:89-110`, so
   there is no atomic rollback when the flag is false.
3. *Real binary, with the control the submitted script lacked.* The regtest was re-run with a
   baseline arm and a committed-height verdict instead of a log grep. Baseline: node commits blocks
   1-4, zero panics. Patched (three `jq` edits): `validate-genesis` returns exit 0 and "is a valid
   genesis file", then **zero blocks commit** and `CONSENSUS FAILURE!!!` fires at height 1 at
   `x/mint/keeper/emissions.go:238`.

**Framework mechanics verified** against cosmos-sdk v0.50.14 / cometbft v0.38.21 source: `sdk.NewCoin`
panics on negative (`types/coin.go:19-30`); `NewCoins` strips only zero coins, not negatives;
baseapp's `recover()` is scoped to `runTx` alone (`baseapp.go:840`) and never wraps `beginBlock`; a
BeginBlock error propagates through `Manager.BeginBlock` -> `internalFinalizeBlock` -> `FinalizeBlock`
to CometBFT's `finalizeCommit`, which panics -> `CONSENSUS FAILURE` -> `onExit`. Allora adds no
recovery; `app/app.go`'s `FinalizeBlock` override is observability only.

**Unrecoverability survived its strongest challenge.** The best counterargument was `allorad rollback`.
It fails on the SDK's own docstring (`server/rollback.go:22-26`): *"No blocks are removed, so upon
restarting CometBFT the transactions in block n will be re-executed against the application."* Bad
params commit at height H; the halt is at H+1; rolling back to H-1 replays H and re-poisons state.
`EmissionEnabled=false` would avert the halt (`abci.go:48-50` sits before all sinks) but setting it
requires a transaction, which requires a block.

**Not intended design.** PR #838 / `0bfa7584` deliberately restored `return err` (fail-closed),
reversing `32c935d1` from Feb 2025 which had swallowed errors. But that record never mentions params,
and `CHANGELOG.md:28-29` defines `Fixed` as "bug fixes that did **not** threaten user funds or chain
continuity" — #838 is filed under `Fixed` while the same release has a populated `Security` stanza.
Decisively, design intent covers only the *error* path: a `panic` from `sdk.NewCoin` unwinds
regardless of whether `BeginBlock` returns `nil` or `err`, so Sink A halted the chain even under the
Feb-2025 swallow-errors regime. Conversely, `validateMaxSupply` rejecting `<= 0` exists *solely* to
prevent a sibling `BeginBlocker` halt (`ErrZeroDenominator`) — so `MaxSupply` already carries a
halt-safety validator that misses this case. That is a gap in an existing policy, not a policy choice.

**Severity: Critical, not High.** This was the only genuinely contested question and went to the
neutral judge. `SECURITY.md:54-61` publishes the asset owner's own rubric, and it is impact-only:
"**CRITICAL** | Immediate threat to critical systems (e.g., **chain halts**, funds at risk)". It has
no likelihood axis and no privileged-role carve-out; its sole exclusion is testing against
production. Where an asset owner names the exact impact class, that rubric governs over a generic
external trusted-role discount. The objection is also mis-fitted: privileged-action discounts exist
to suppress findings that grant an admin no capability the trust model already conceded, and apply
when the privileged action is *inherently* destructive. Here the defect is a safety failure, not an
authorization failure — the system's own validator affirmatively certifies the bricking value as
valid. Every other mint-admin power is reversible by a later `MsgUpdateParams`; this one is uniquely
one-way. And the genesis vector reaches a height-1 brick with no whitelist and no admin key at all,
which forecloses the purely-privileged framing.

## Invalidation Reasons Tested

| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | EG-1 Access control prevents unauthorized caller | Step 3 (Generic) | FAILS | Gate is real and exclusive, but the report never claims an unprivileged caller. Proposed DOWNGRADE_TO_HIGH; overruled at Step 4C on the project's own rubric. |
| 2 | US-1 State combination prevented by invariant | Step 3 (Generic) | FAILS | No guard in keeper, msg server, ante handler, invariant registry, migration, or genesis. Real `UpdateParams` driven end-to-end: commits cleanly with `nil` error. |
| 3 | AM-2 Timelock / governance delay | Step 3 (Generic) | FAILS | No timelock, no gov routing, no deferred application. `rollback` cannot recover (SDK docstring). |
| 4 | Equivalent pre-existing admin bricking powers | Step 4 (Adversarial) | FAILS | `RemoveWhitelistAdmin` freeze is governance-only, chain keeps producing. Hyperinflation is recoverable. The one true sibling halt is a *new* bug, not prior art. |
| 5 | Deliberate fail-closed design intent (PR #838) | Step 4 (Adversarial) | FAILS | Defends the halt mechanism, not the missing validation. CHANGELOG taxonomy classifies #838 as not-chain-continuity. Sink A untouched by it. |
| 6 | PoC evidence quality / genesis claim | Step 4 (Adversarial) | FAILS | Script hygiene critique is fair, but a controlled re-run confirms the halt. `validate-genesis` *does* invoke `ValidateGenesis` and passes the bricking genesis. |
| 7 | Simpler equivalent halt via `MaxSupply=1` | Step 4 (Adversarial) | FAILS | Real and easier, but same param, same message, same gap — collapses into this finding rather than duplicating it. Broadens the root cause. |
| 8 | Trigger realism / deliberate-act framing | Step 4 (Adversarial) | FAILS | Mandatory 12-field re-supply *increases* misconfiguration exposure. `EcosystemTokensMinted` has no query endpoint. Dry-run reads committed params only. |
| 9 | `blocksPerMonth = 0` simpler halt (orchestrator hypothesis) | Orchestrator | FAILS | Refuted: `ValidateBlocksPerMonth` rejects 0, enforced at `msg_server.go:80-83`. |

## Required Report Corrections

1. **Root cause is framed too narrowly.** The gap is not `MaxSupply` vs `EcosystemTokensMinted`; it is
   that `MaxSupply` is validated in isolation from *every* runtime quantity it is arithmetically
   compared against, including the ecosystem module account's live bank balance.
2. **Three sinks, not two.** The report omits the most reachable one: `GetEmissionInfo` at
   `abci.go:144` runs unconditionally at the end of every `BeginBlocker`. This is the sink the
   real-binary regtest actually hit. The report understates reachability by a factor of `blocksPerMonth`.
3. **Recommended fix #3 is an anti-fix — remove it.** Clamping instead of erroring reverses PR #838
   and converts a loud halt into silent, undetectably wrong emissions.
4. **Recommended fix #2 is insufficient.** Clamping remaining at zero does not close the `abci.go:144`
   sink, since `circulatingSupply` still goes negative through `ecosystemBalance` alone.
5. **Correct fix follows the team's own precedent** (`ValidateBlocksPerMonth`): validate the invariant
   at the msg boundary and in `ValidateGenesis` + the migration path, keeping consensus-path errors
   fail-closed. Retain an `IsNegative()` guard before `sdk.NewCoin` as defense-in-depth only.
6. **Drop the adversarial framing.** Lead with the honest-operator misconfiguration path, not
   "a malicious admin could" — the latter invites the trusted-role downgrade.
7. **Replace the self-deprecating severity caveat** with a direct citation to `SECURITY.md:58`.
8. **Tighten unrecoverability wording** and cite the SDK `rollback` docstring rather than asserting it.
9. **Fix the mutable-whitelist claim.** `AddToWhitelistAdmin` requires `CanUpdateAllGlobalWhitelists`,
   so the admin set is closed under existing privilege; it does not lower the trust bar.
10. **Rewrite `poc_regtest_mint_halt.sh`** with `set -e`, checked exit codes, a committed-height
    verdict, and a baseline arm before presenting it as proof.

## Spin-off Findings (out of scope for this issue; file separately)

- **`x/mint/keeper/emissions.go:181` — second unrecoverable halt.**
  `validateValidatorsVsAlloraPercentReward` accepts `0`; `f_stakers` then becomes `0` and
  `QuoTruncate` panics ("division by zero", confirmed empirically). Sits on the unconditional
  every-block path via `abci.go:144`. `reputersPercentOfTopicRewards` is genuinely `0` for any month
  with no topic rewards (`weights.go:185-186,202`), so this is latent on a mature chain and detonates
  at the next zero-reward month boundary. **Not covered by this issue's fix.**
- **`x/emissions/keeper/whitelist.go:69-74` — no minimum-admin guard.** One `RemoveFromWhitelistAdmin`
  can empty the admin set, permanently freezing all params. Chain keeps producing blocks, so this is
  a governance lockout rather than a halt. Low/Medium.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — every cited location verified accurate.
- **Step 2 (Privileged Roles)**: Whitelist admin identified as TRUSTED under the default heuristic.
  No early exit and no `MAX_SEVERITY` cap applied, per the rule that a trusted role making a
  validator-approved call that misbehaves is a code bug, not admin abuse.
- **Step 1.5 (Framework Research)**: Cosmos SDK / CometBFT halt semantics verified from module cache.
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, 0 held. No early exit (requires >=2 HOLDS).
- **Step 4 (Adversarial Check)**: 5 reasons generated (x2 generator runs), 5 checked, 0 held.
  Judge invoked on the contested severity question only.
- **Step 4C (Neutral Judge)**: VALID / Critical / HIGH confidence.
- **Final Severity**: Critical (unchanged from claimed).
