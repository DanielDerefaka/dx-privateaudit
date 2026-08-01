# ISSUE-1: Unbounded bridge-deposit amount/tip causes an uncaught arithmetic-overflow panic in the oracle `EndBlocker`, halting the Tellor Layer chain

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (neutral judge)
**Confidence**: HIGH

## Summary
An attested bridge-deposit report value carrying a `uint256` amount or tip whose `loya`-scaled
magnitude exceeds `MaxInt64` wraps negative through `big.Int.Int64()` and panics inside
`sdk.NewInt64Coin`. The decode executes in the oracle `EndBlocker`, a consensus path with no
panic recovery, so every validator crashes at the same height and does not recover on restart.
The mechanism was confirmed three independent ways. Both proposed downgrades were rejected by
the neutral judge. Severity stands at Critical, but the report's stated precondition is roughly
twice the true one and several factual claims need correction (see below).

## Location
- `x/bridge/keeper/claim_deposit.go:221-226` — unbounded `Int64()` → `sdk.NewInt64Coin` (panic site)
- `x/bridge/keeper/claim_deposit.go:52` — power gate before the decode
- `x/bridge/keeper/claim_deposit.go:60,65` — `IsAllPositive` guard is dead code (after the decode)
- `x/oracle/abci.go:21` — `AutoClaimDeposits` in the oracle `EndBlocker`
- `x/oracle/keeper/keeper.go:333-385` — `AutoClaimDeposits`
- `x/oracle/keeper/token_bridge_deposit.go:79-112` — `validateBridgeDepositAmount` (sign-only; tip unread)
- `x/oracle/keeper/aggregate.go:153` — unconditional `BridgeDepositQueue` enqueue

## Justification

### Mechanism — CONFIRMED (three independent ways)
1. **Pinned dependency source.** cosmos-sdk v0.53.4 + cometbft v0.38.17, no `replace` directives.
   `NewInt64Coin → NewCoin → Validate → panic(err)` (`types/coin.go:19-36`). `grep -rn "recover("
   baseapp/` hits only `Query`, `PrepareProposal`, `ProcessProposal`, `ExtendVote`,
   `VerifyVoteExtension`, `grpcserver.go`, and `runTx` (`baseapp.go:857-864`, logged "panic
   recovered in runTx"). ZERO recovery in `FinalizeBlock → internalFinalizeBlock → endBlock →
   Manager.EndBlock → App.EndBlocker`. `big.Int.Int64()` on 1e19 yields `-8446744073709551616`
   (`math/big/int.go:427-435`).
2. **Unit PoCs re-run independently — all PASS** (`x/bridge/keeper/`, exit 0): amount overflow, tip
   overflow, and `ClaimDeposit` panicking rather than returning an error.
3. **Integration PoC re-run independently — PASS** (`tests/integration/`, exit 0):
   `CONFIRMED CHAIN HALT — oracle.EndBlocker panicked: "negative coin amount: -8446744073709551616"`.
   The PoC drives the real app/msg servers and is a one-variable delta from the project's own
   passing `TestClaimingBridgeDeposit` (`tests/integration/oracle_keeper_test.go:1075`). No
   production code was modified — the PoCs are new untracked test files only.

### No self-heal
CometBFT converts a `FinalizeBlock` error into `panic("failed to apply block")`
(`consensus/state.go:1781`); the block is saved to the blockStore *before* `ApplyVerifiedBlock`, so
on restart the handshake replays it into the identical panic (`replay.go:534`). The poisoned queue
entry lives in state committed by an *earlier* block and fires on wall-clock time, so rollback,
restart, and waiting all change nothing. Cosmovisor cannot act — it consumes `upgrade-info.json`,
written only by `x/upgrade`'s `PreBlocker`, which requires a passed governance proposal and a
produced block, both impossible on a halted chain.

### Precondition — materially EASIER than the report claims
`AggregatePower` is `ValuesWeightSum` (`x/oracle/keeper/aggregate.go:184-195`), the summed power of
**every** reporter on the query across **all** values (`submit_value.go:299-309`), while the winning
value is chosen separately by strict-`>` weighted-mode plurality (`submit_value.go:327`). The
attacker therefore piggybacks on honest reporters' power to clear `powerThreshold`. Solving
`A > H` and `A + H >= 2T/3` minimizes at `H = T/3`:

| Participation | Minimum attacker share |
|---|---|
| 2/3 (bare quorum) | **~33.4%** |
| 80% | ~40% |
| 100% | ~50% |

No sybil resistance exists: `MaxReporterPowerShare` (30%) is per-reporter-address and ante-only
(`x/reporter/ante/ante.go:808-824`), registering another reporter costs 1 TRB (`MinLoya`), and
`AddReportWeightedMode` sums identical values across reporters (`submit_value.go:293`). The 5%/12h
tracker (`ante.go:710-737`) bounds total-bonded movement and never fires on reporting-power
concentration, since `SelectReporter`/`SwitchReporter` don't touch `totalBondedDelta`. It does
rate-limit a market-purchase path to ~5 days of visible accumulation.

### Trust model — inside the defended zone
ADR2001:28,68 grants a trust exemption only at `>2/3` ("a completely compromised layer chain
(>2/3 malicious)… a social fork will be necessary"). ADR1012:20,22,81 is directly on point and
written precisely because reporters at "30%, 50%, or more of total reporting power… can dominate
medians on low-participation queries", with the cap "prevent[ing] crossings rather than remediating
existing concentration" and "**No retroactive remediation**". A ~33-50% coalition is an explicitly
modeled adversary, not an assumed-honest party.

### Both downgrade arguments rejected
- **"Non-incremental harm"** (same quorum can mint ~9.22e12 TRB vs ~2.8M supply without
  overflowing): rejected. Severity is a property of the issue, not a ranking against the worst
  capability reachable at the same precondition — that reasoning would zero out every bug in any
  protocol with a documented quorum assumption. The comparison is also not like-for-like: minting
  on quorum is *designed* behavior with ADR2001 mitigations (5%/12h withdraw limit, 12h optimistic
  delay, social fork) and is bounded by the bridge contract's actual TRB balance, whereas the halt
  is unintended, unmitigated, cannot be disputed once it lands (a halted chain accepts no
  transactions), and defeats restart. The two also select for different adversaries — a halt needs
  no exit or laundering path and suits a short-seller, competitor, or key-compromise actor.
- **"Likelihood Low"**: rejected on its premise. It reasons from "≥2/3 of bridge-valset power",
  which two independent checkers refuted (~33-50%). Its factual contribution stands — there is no
  accidental trigger: the reporter daemon packs `deposit.Amount` verbatim with no scaling
  (`daemons/token_bridge_feed/client/client.go:456,550`), the sole `/1e12` is chain-side, and a
  spurious ×1e12 would break the first deposit ≥9.22 TRB loudly rather than lying dormant. That is
  why likelihood is Medium and not High.

### Mitigations assessed and found insufficient
The 12h maturation window plus dispute-driven `Flagged` check (`claim_deposit.go:33`) genuinely
precedes the decode and would defuse the attack. But flagging is discretionary and human-initiated,
costs at-risk capital (1% of the reporter's stake for Warning, 100% for Major), requires targeting
the exact aggregate reporter — a mistargeted dispute silently no-ops (`x/oracle/types/indexes.go:33-40`,
`keeper.go:302-314`) — and there is no automatic or heuristic detection anywhere. The attacker can
queue many poisoned deposits (one processed per block; a deposit re-enters the queue when re-tipped),
so defenders must detect and individually bond against every one. It is a chance of rescue that
fails open, not a mitigation.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | AM-2 — 12h delay + dispute flagging acts as a timelock defense | Step 3 (Generic) | FAILS | Flag gate does precede the decode, but flagging is paid, discretionary, human-initiated, silently no-ops if mistargeted, has no auto-detection, and is out-spammable |
| 2 | EG-5 — a missed input-validation bound blocks the attack | Step 3 (Generic) | FAILS | Exhaustive gate audit: only sign check + ABI-decodability. `grep IsInt64\|MaxInt64\|BitLen` in `x/` hits nothing on this path; zero `Cmp(` in `x/bridge`/`x/oracle` |
| 3 | UP-2 — requires majority-of-supply / majority stake | Step 3 (Generic) | FAILS | Real bar ~33-50%, not >50% or 2/3; recommended downgrade on other grounds, rejected by judge |
| 4 | "Permanent/unrecoverable" overstated; error-halt already accepted | Step 4 (Adversarial) | FAILS | CometBFT panics on FinalizeBlock error too; replay re-panics; Cosmovisor inapplicable. Other halt paths = fragility argument, not acceptance |
| 5 | EVM caps ⇒ no honest trigger ⇒ likelihood Low | Step 4 (Adversarial) | **HOLDS** (conclusion only) | No accidental path confirmed; but EVM caps are irrelevant (Layer does zero L1 verification) and its ≥2/3 premise is refuted. Judge: Likelihood Medium |
| 6 | Power-domain mismatch + concentration caps raise the bar | Step 4 (Adversarial) | FAILS | Same `PowerReduction` units (~1.1-1.2× correction only); caps are per-address with no sybil resistance; net precondition is *easier*, not harder |

## Corrections the report author MUST make
1. **Delete the "≥2/3 reporter-power quorum" claim.** Replace with the verified derivation
   (~33.4% minimum, ~40% at 2/3 participation, >50% at full).
2. **Fix the dequeue description.** "`AutoClaimDeposits` only dequeues on a returned error" is
   wrong — `keeper.go:371` *and* `:378` both remove the entry. The entry survives because the panic
   unwinds before either removal and the block's writes are discarded.
3. **State the units precisely.** `powerThreshold` is `totalPower * 2 / 3` over the **bridge
   validator set** (`x/bridge/keeper/keeper.go:280`); the numerator is **reporter** power. The
   report conflates them.
4. **Drop "permanent."** Use: "does not self-heal; survives restart via deterministic replay;
   recoverable only by a coordinated out-of-band patched binary on ≥2/3 of validator power."
5. **Keep the `tip` vector explicit.** `decoded[3]` panics identically even though `ClaimDeposit`
   discards it with `_`, and Layer never enforces the EVM's `tip <= amount`. Any patch must bound
   **both** fields.
6. **Cite ADR1012, not ADR2011,** as the on-point trust-model evidence. ADR2011 governs validators
   signing attestations on the Layer→Ethereum path, not reporters submitting deposit reports.
7. **Preempt the "they could already mint infinite TRB" objection** in the report itself
   (`ClaimDeposit:69` mints uncapped) and explain the class boundary.
8. **Fix the severity arithmetic.** "High × Medium ⇒ Critical" does not follow from the generic
   matrix; rate it Critical on the DLT total-network-shutdown convention, with Likelihood Medium
   stated openly.

## Suggested Fix
Bound both `amountBigInt` and `tipBigInt` against `MaxInt64` and **return an error** rather than
panic (prefer `sdkmath.NewIntFromBigInt` + `sdk.NewCoin`). Add a symmetric upper bound for both
fields in `validateBridgeDepositAmount` so malformed values are rejected at `MsgSubmitValue`.
Independently, harden `AutoClaimDeposits` (dequeue-before-claim, or a scoped `recover()`) so no
future decode bug in this path can halt block production.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all seven referenced code locations verified to exist and
  match the report verbatim.
- **Step 2 (Privileged Roles)**: NO_ISSUE — the attack actor is a reporter coalition, not
  `owner`/`admin`/`governance`. No trusted-role severity cap applied.
- **Step 1.5 (External Research)**: 4/4 claims verified TRUE against pinned source.
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, 0 held → no early exit (requires ≥2).
- **Step 4 (Adversarial Check)**: 5 reasons generated, 2 dropped as duplicates of Step 3, 3 checked,
  1 held (likelihood only) → judge invoked. Judge verdict: VALID, Critical upheld, confidence HIGH.
- **Orchestrator direct verification**: both PoC suites re-executed (exit 0); PoC legitimacy
  confirmed (real symbols, no production-code modification, benign sibling test present);
  absence-of-bound greps confirmed.
- **Final Severity**: Critical (unchanged from claimed; Impact High × Likelihood Medium, resolved to
  Critical by the DLT total-network-shutdown convention — the single narrowest judgment in the ruling).
