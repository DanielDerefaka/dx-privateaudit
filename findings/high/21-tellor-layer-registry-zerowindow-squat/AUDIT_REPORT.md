# Security Audit Report — Tellor Layer

**Date**: 2026-06-26
**Auditor**: Plamen Automated Security Analysis (whitehat)
**Scope**: Tellor Layer custom Cosmos SDK modules (`x/bridge`, `x/oracle`, `x/reporter`, `x/dispute`, `x/registry`, `x/mint`) + app ABCI++ (`app/extend_vote.go`, `app/proposal_handler.go`, `app/ante.go`)
**Language/Version**: Go 1.24.13 (pinned), Cosmos SDK v0.53.4, CometBFT v0.38.17
**Build Status**: Compiled successfully (`GOTOOLCHAIN=go1.24.13 go build ./cmd/layerd`)
**Confirmation**: Real-keeper Go tests + live single-validator `layerd` devnet (block production verified)

---

## Executive Summary

A **Critical, deterministic chain-halt** vulnerability that does not self-heal exists in the bridge deposit-claim path. The amount and tip carried in an attested bridge-deposit report are converted to native `loya` coins via `big.Int.Int64()` → `sdk.NewInt64Coin` **with no upper-bound guard**. A value whose `loya`-scaled magnitude exceeds `MaxInt64` wraps **negative**, and `sdk.NewCoin` **panics** (`negative coin amount`). This decode executes inside the oracle `EndBlocker` (`AutoClaimDeposits → ClaimDeposit → DecodeDepositReportValue`). Because it is a **panic, not a returned error**, it unwinds before the module's error handler can dequeue the entry — and the block never commits, so the queue entry persisted by an earlier block survives untouched. There is no `recover` on the `EndBlock`/`FinalizeBlock` path, so every node re-panics at the same height, restart replays the same block into the same panic, and the chain stays down until a coordinated patched-binary restart.

The vulnerability was **confirmed end-to-end on the real state machine**: 5 reporters submit a malicious deposit value, it aggregates on-chain, and the real `oracle.EndBlocker` panics with `negative coin amount: -8446744073709551616` (exactly `1e19 − 2⁶⁴`, the Int64 overflow wrap).

Secondary findings: a permissionless permanent registry query-type squat (High, confirmed), a stale reporter-power forgery after full undelegation (High, structurally confirmed), and a dispute-module accounting/slice-mutation pair (Medium, flagged for deeper tracing — potential second halt).

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 2 |
| Medium | 1 |
| Low | 0 |
| Informational | 0 |

### Components Audited

| Component | Path | LOC (non-test) | Description |
|-----------|------|------|-------------|
| Bridge | `x/bridge` | ~9,031 | EVM bridge: deposits/withdrawals, attestations, valset signatures |
| Oracle | `x/oracle` | ~9,419 | Reporting, weighted-median aggregation, tips, TBR, EndBlocker auto-claim |
| Reporter | `x/reporter` | ~8,997 | Staking/delegation/power, reward distribution |
| Dispute | `x/dispute` | ~6,445 | Dispute lifecycle, fees, voting, slashing |
| Registry | `x/registry` | ~2,772 | Data-spec registration |
| Mint | `x/mint` | ~1,193 | Time-based inflation |

---

## Critical Findings

### [C-01] Unbounded bridge-deposit amount/tip causes uncaught EndBlocker panic → chain halt with no self-heal [VERIFIED]

**Severity**: Critical (Impact: High — total network shutdown, liveness loss that does not self-heal; Likelihood: Medium — requires a reporter coalition large enough to win the weighted-mode aggregate)
**Location**: `x/bridge/keeper/claim_deposit.go:221-226` (decode); reached via `x/oracle/abci.go:21` → `x/oracle/keeper/keeper.go:367` (`AutoClaimDeposits` → `ClaimDeposit`). Submit-time validation gap: `x/oracle/keeper/token_bridge_deposit.go:79-110` (`validateBridgeDepositAmount`).
**Confidence**: HIGH (2 agents + manual confirmation; PoC: PASS at unit, keeper, and integration level)

**Description**:

`DecodeDepositReportValue` converts the attested deposit `amount` and `tip` (uint256 from the oracle aggregate) to native coins without any upper bound:

```go
// x/bridge/keeper/claim_deposit.go:221-226
amountDecimalConverted := amountBigInt.Div(amountBigInt, big.NewInt(1e12))
tipDecimalConverted := tipBigInt.Div(tipBigInt, big.NewInt(1e12))
amountCoin := sdk.NewInt64Coin(layer.BondDenom, amountDecimalConverted.Int64()) // panics if negative
amountCoins := sdk.NewCoins(amountCoin)
tipCoin := sdk.NewInt64Coin(layer.BondDenom, tipDecimalConverted.Int64())        // panics if negative
tipCoins := sdk.NewCoins(tipCoin)
```

`big.Int.Int64()` is undefined for values exceeding `int64` and in practice returns the low 64 bits as a signed integer — i.e. it **wraps negative** for any `amount/1e12 > MaxInt64` (`amount > ~9.2e30` wei). `sdk.NewInt64Coin → NewCoin → coin.Validate()` then **panics** with `negative coin amount`.

Submit-time validation does not prevent this: `validateBridgeDepositAmount` only checks `amount.Sign() <= 0` (no upper bound) and **never inspects the tip field at all**. So a malicious value passes `MsgSubmitValue`, aggregates normally, and is queued for auto-claim.

The decode runs inside the consensus `EndBlocker`:
- `oracle.EndBlocker` → `AutoClaimDeposits` → `bridgeKeeper.ClaimDeposit` → `DecodeDepositReportValue` (panic).
- `AutoClaimDeposits` dequeues on **both** the error and success paths (`keeper.go:371` and `:378`), so a *returned error* from `ClaimDeposit` is handled safely. A **panic** is different in kind: it unwinds before either `Remove` executes.
- There is no `recover` in the module `EndBlock` / `Manager.EndBlock` / `baseapp.FinalizeBlock` path (the `runTx` recovery middleware wraps per-tx execution only). The panic propagates to CometBFT → node crash.
- The block never commits, so neither `Remove` is persisted and the entry — written by an *earlier*, committed block (`x/oracle/keeper/aggregate.go:153`) and triggered by wall-clock time, not a tx — survives. Every node re-selects the same oldest entry and re-panics at the same height. Restart does not clear it: CometBFT stores the block before applying it and the handshake replays it into the identical panic (`consensus/replay.go:534`). **Deterministic halt that does not self-heal**, until a coordinated patched restart + state surgery.

The `if !amount.IsAllPositive()` guard at `claim_deposit.go:65` is **dead code** for this path — the panic at line 223 precedes it (line 60).

**Impact**:
- Total network shutdown (maximal L1 liveness impact); does not self-heal across restart, recoverable only by a coordinated out-of-band patched binary. Trust-model note: ADR2001 grants a trust exemption only at *">2/3 malicious"* (`adr/adr2001:68`), while ADR1012 states *"Nothing today stops a single reporter from accumulating 30%, 50%, or more of total reporting power"* with *"No retroactive remediation"* (`adr/adr1012:20,81`) — this attacker is inside the defended zone.
- Gating actor is the bridge attestation quorum (`claim_deposit.go:52`, `AggregatePower < powerThreshold`) — a **semi-trusted ≥2/3 reporter-power set**, not a fully-trusted governance key, so no trust-assumption downgrade applies. A 2/3 reporter coalition (or a single entity controlling ≥2/3 reporter power) can attest a deposit with an absurd amount/tip that no legitimate deposit could reach (would require ~9.2e12 TRB, above total supply), making it purely attack-induced.

**PoC Result** (`GOTOOLCHAIN=go1.24.13 go test`):

- **Tier 1** — `x/bridge/keeper/claim_deposit_overflow_test.go`
  - `TestClaimDepositOverflowPanics_Amount`: decode of `amount=1e31` panics `negative coin amount` — PASS
  - `TestClaimDepositOverflowPanics_Tip`: decode of `tip=1e31` (amount valid) panics identically — PASS (proves the tip field is entirely unvalidated)
- **Tier 2** — `TestClaimDepositOverflow_PanicsNotErrors`: real `ClaimDeposit` (power gate cleared, 12h age cleared) **panics rather than returning an error** — PASS (proves `AutoClaimDeposits` cannot catch it)
- **Tier 3** — `tests/integration/claim_deposit_overflow_test.go` `TestBridgeDepositOverflowHaltsEndBlocker`: 5 reporters submit the malicious value → it aggregates on-chain (`res.Aggregate.AggregateValue == overflowValue`) → real `oracle.EndBlocker` panics:
  ```
  CONFIRMED CHAIN HALT — oracle.EndBlocker panicked: "negative coin amount: -8446744073709551616"
  ```
  PASS. (`-8446744073709551616 == 1e19 − 2⁶⁴`, the Int64 wrap.)
- **Full build + live regtest**: `layerd` built and ran a single-validator chain to height 23+ with vote extensions, 0 crashes — the live node executes this exact code path.

**Recommendation**:

Guard the conversion (defense in depth at both the decode and submit-validation layers):

```go
// x/bridge/keeper/claim_deposit.go — before the NewInt64Coin calls
if !amountDecimalConverted.IsInt64() || !tipDecimalConverted.IsInt64() {
    return nil, sdk.Coins{}, sdk.Coins{}, types.ErrInvalidDepositReportValue.Wrap("amount/tip exceeds int64")
}
```

Preferably avoid `int64` truncation entirely and use `sdk.NewCoin(layer.BondDenom, math.NewIntFromBigInt(amountDecimalConverted))`, which returns an error (does not panic) on invalid input. Mirror an explicit upper bound in `validateBridgeDepositAmount` **and add a symmetric check for the tip field** so a malformed value is rejected at `MsgSubmitValue` and never reaches the aggregate. As a broader hardening measure, wrap the bridge auto-claim invoked from the oracle EndBlocker so a single malformed deposit cannot panic the block (treat it like the existing returned-error path: log + dequeue rather than propagate).

---

## High Findings

### [H-01] Permissionless permanent registry query-type squat via zero `ReportBlockWindow` [VERIFIED]

**Severity**: High (permissionless permanent griefing/DoS of a query type; conditional third-party fund loss via stranded tips)
**Location**: `x/registry/keeper/msg_server_register_spec.go:18-57` (no `ReportBlockWindow` check) vs `x/registry/types/genesis.go:34` (genesis rejects `== 0`)
**Confidence**: HIGH (PoC: PASS)

**Description**: `RegisterSpec` is permissionless and `validateRegisterSpec` validates the registrar, query type, ABI components, aggregation method, and response type — but **never `ReportBlockWindow`**. Genesis `Validate()` rejects `ReportBlockWindow == 0` ("report block window is 0"); the runtime path does not. Registering a spec with `ReportBlockWindow = 0` collapses the submission window (`Expiration = tipHeight + 0`), so from the next block every `SubmitValue` is rejected (`ErrSubmissionWindowExpired`) and the EndBlocker aggregate loop skips the never-reported query. Because re-registration is blocked (`AlreadyExists`), the query type is **permanently squatted** — recoverable only by governance. Any tip later placed on the bricked type is stranded (no refund path exists in `x/oracle/keeper`).

**PoC Result**: `x/registry/keeper/zerowindow_dos_test.go` `TestZeroWindowSpecAcceptedAndSquats` — runtime accepts the zero-window spec, genesis rejects the identical spec, and re-registration with a valid window is permanently blocked. PASS.

**Recommendation**: Add the genesis invariant to the runtime path: reject `Spec.ReportBlockWindow == 0` (and enforce the existing `MaxReportBufferWindow` upper bound) in `validateRegisterSpec`. Consider gating `RegisterSpec` or charging a meaningful fee to deter squatting, and add a tip-refund/expiry path for never-aggregated queries.

### [H-02] Stale-inflated reporter power after full undelegation (missing recalc hook) [VERIFIED — structural]

**Severity**: High (stake forgery: oracle aggregate weight, dispute voting power, and reward share with zero bonded backing)
**Location**: `x/reporter/keeper/hooks.go:65-103` — `FlagStakeRecalc` is called only from `AfterDelegationModified`; full undelegation takes the SDK `RemoveDelegation` branch (`x/staking/keeper/delegation.go:1029`), which fires `BeforeDelegationRemoved` (only decrements `DelegationsCount`) and **skips** `AfterDelegationModified`.
**Confidence**: HIGH (structural confirmation against cosmos-sdk v0.53.4 source)

**Description**: When a delegator fully undelegates (`delegation.Shares.IsZero()`), the recalc flag that would refresh a reporter's cached stake is never set. `ReporterStake` keeps returning the cached pre-undelegation total, so a reporter can wield power not backed by any bonded stake — forging weighted-median aggregate weight, dispute vote weight, and tip/TBR/dispute reward share. The per-reporter ante cap bounds single-actor feed control, so full feed corruption needs sybil coordination — hence High rather than Critical, but it is a clean, permissionless, capital-efficient forgery and is **not** the design-accepted passive drift documented in `adr/adr1012` (that is a different vector).

**Recommendation**: Call `FlagStakeRecalc` from `BeforeDelegationRemoved` (or hook the full-undelegation path) so cached reporter stake is invalidated on full undelegation as it is on partial modification.

---

## Medium Findings

### [M-01] Dispute slashed-amount accounting + slice-mutation-during-range (potential second halt) [CONTESTED — needs tracing]

**Severity**: Medium (potential escalation to Critical chain-halt pending a single-dispute reachability trace)
**Location**: `x/dispute/keeper/withdraw.go:279-292` (`RemoveEntry` = in-place `slices.Delete` while ranging — panics with ≥2 unbonding entries in the removal branch); `DisputedDelegationAmounts.Total` set to the full slash amount even when less was escrowed.
**Confidence**: MEDIUM

**Description**: Two adjacent issues in the dispute slash/return path. (a) A slice is mutated in place during iteration in the multi-entry-unbonding removal branch, which panics. (b) `DisputedDelegationAmounts.Total` can exceed what was actually escrowed, leaking value on token return. The open question — flagged for a focused integration trace — is whether either can be driven from a `BeginBlocker` path (`dispute/abci.go → CheckClosedDisputesForExecution → ExecuteVote → ReturnSlashedTokens`) such that a `SendCoinsFromModuleToModule` errors or a panic propagates → consensus halt. If a single large multi-entry-unbonding dispute can trigger the slice-mutation panic in BeginBlocker, this is a **second Critical**.

**Recommendation**: Build the removal list first and delete after the range completes (or iterate by index descending); reconcile `DisputedDelegationAmounts.Total` against actually-escrowed amounts. Trace the BeginBlocker reachability before triage.

---

## Priority Remediation Order

1. **C-01** — Unbounded deposit amount/tip → chain halt with no self-heal. **Immediate** (one-block, permissionless-by-quorum, unrecoverable without coordinated restart).
2. **H-01** — Zero-window registry squat. Add the runtime `ReportBlockWindow` guard. Before launch.
3. **H-02** — Stale reporter-power forgery. Add the recalc hook on full undelegation. Before launch.
4. **M-01** — Dispute slice-mutation/accounting. Fix and trace the BeginBlocker reachability (possible second Critical).

---

## Appendix A: PoC Artifacts (regression tests)

| File | Tests | Result |
|------|-------|--------|
| `x/bridge/keeper/claim_deposit_overflow_test.go` | overflow panics (amount, tip), ClaimDeposit-panics-not-errors | PASS |
| `tests/integration/claim_deposit_overflow_test.go` | real `oracle.EndBlocker` halt on aggregated malicious deposit | PASS |
| `x/registry/keeper/zerowindow_dos_test.go` | zero-window accepted + permanent squat | PASS |

Run: `GOTOOLCHAIN=go1.24.13 go test ./x/bridge/keeper/ ./x/registry/keeper/ ./tests/integration/ -run 'Overflow|ZeroWindow|HaltsEndBlocker' -v`
