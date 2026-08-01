# Unbounded bridge-deposit amount/tip causes an uncaught arithmetic-overflow panic in the oracle `EndBlocker`, halting the Tellor Layer chain with no self-heal

A missing upper-bound check in the bridge deposit-claim decoder (`DecodeDepositReportValue`) lets an attested `uint256` amount or tip overflow `int64` and wrap negative, which makes `sdk.NewInt64Coin` panic. Because this decode is executed inside the oracle `EndBlocker` (`AutoClaimDeposits → ClaimDeposit`) — a consensus path where panics are **not** recovered and **not** treated as the handler's returned error — the panic propagates out of `FinalizeBlock` and crashes every validator at the same height, producing a deterministic, network-wide chain halt that does not self-heal — it survives node restart via deterministic block replay and is recoverable only by a coordinated out-of-band patched binary.

---

## Brief/Intro

`x/bridge/keeper/claim_deposit.go` converts the deposit `amount` and `tip` carried in an oracle-attested bridge-deposit report into native `loya` coins using `big.Int.Int64()` followed by `sdk.NewInt64Coin`, with **no upper-bound validation** anywhere on the path (the submit-time validator only checks the sign of `amount` and never inspects `tip`). If a bridge-deposit report whose `loya`-scaled amount or tip exceeds `MaxInt64` is aggregated by the required reporter-power quorum, the value is queued for auto-claim and, on the next post-12h block, the oracle `EndBlocker` calls into the decoder, `Int64()` wraps negative, and `sdk.NewInt64Coin` panics with `negative coin amount`. The panic is uncaught in the `EndBlock`/`FinalizeBlock` path; on a live network every node re-executes the same queued claim and re-panics at the same height, so the chain stops producing blocks and does not resume until operators ship and coordinate a patched binary plus manual state surgery. On mainnet this is a total network shutdown that freezes all funds and all activity across every module.

---

## Vulnerability Details

### The unbounded conversion

When a bridge deposit is claimed, the attested report value is decoded by `DecodeDepositReportValue`. The attested value is `abi.encode(address ethSender, string layerRecipient, uint256 amount, uint256 tip)`. The decoder scales the `uint256` amount/tip from 18 decimals (EVM) to 6 decimals (`loya`) and builds coins:

```go
// x/bridge/keeper/claim_deposit.go:221-226
amountDecimalConverted := amountBigInt.Div(amountBigInt, big.NewInt(1e12))
tipDecimalConverted := tipBigInt.Div(tipBigInt, big.NewInt(1e12))
amountCoin := sdk.NewInt64Coin(layer.BondDenom, amountDecimalConverted.Int64()) // <-- panics on overflow
amountCoins := sdk.NewCoins(amountCoin)
tipCoin := sdk.NewInt64Coin(layer.BondDenom, tipDecimalConverted.Int64())        // <-- panics on overflow (tip never validated)
tipCoins := sdk.NewCoins(tipCoin)
```

`big.Int.Int64()` is documented as undefined when the value does not fit in an `int64`; in the Go runtime it returns the low 64 bits interpreted as signed, i.e. it **wraps negative** for any value `> MaxInt64` (`9223372036854775807`). Concretely, an amount of `1e31` wei scales to `1e31 / 1e12 = 1e19`, and `big.NewInt(1e19).Int64()` returns `1e19 − 2⁶⁴ = -8446744073709551616`.

`sdk.NewInt64Coin` then constructs the coin via `NewCoin`, which calls `coin.Validate()`; a negative amount fails validation and `NewCoin` **panics**:

```go
// cosmos-sdk/types/coin.go (NewCoin -> Validate -> IsNegative -> panic)
func NewCoin(denom string, amount Int) Coin {
    coin := Coin{Denom: denom, Amount: amount}
    if err := coin.Validate(); err != nil { panic(err) } // "negative coin amount: <wrapped value>"
    return coin
}
```

The `if !amount.IsAllPositive()` guard at `claim_deposit.go:65` is **dead code** for this path — the panic at line 223 happens during the decode at line 60, before that check at line 65 and before the mint at line 69.

### Why submit-time validation does not stop it

A reporter submits a bridge-deposit value through `MsgSubmitValue`, which routes bridge deposits to `HandleBridgeDepositDirectReveal` and validates the value with `validateBridgeDepositAmount`:

```go
// x/oracle/keeper/token_bridge_deposit.go:79-110 (validateBridgeDepositAmount)
args := abi.Arguments{ {Type: addressType}, {Type: stringType}, {Type: uint256Type}, {Type: uint256Type} }
decoded, err := args.Unpack(valueBytes)
...
amount := decoded[2].(*big.Int)
if amount.Sign() <= 0 {
    return types.ErrInvalidValue.Wrap("bridge deposit amount cannot be zero")
}
// no upper bound; decoded[3] (tip) is never read
```

The only check is `amount.Sign() <= 0`. There is **no upper bound**, and the **tip field (`decoded[3]`) is never validated at all**. So a malicious value with `amount = 1e31` (or a valid amount and `tip = 1e31`) passes `MsgSubmitValue`, aggregates normally (weighted-mode), and is queued for auto-claim.

### Why it is a chain halt, not a failed transaction

The decode is reached from the oracle `EndBlocker`, not from a user transaction:

```go
// x/oracle/abci.go:13-23
func EndBlocker(ctx context.Context, k keeper.Keeper) error {
    if err := k.SetAggregatedReport(ctx); err != nil { return err }
    if err := k.AutoClaimDeposits(ctx); err != nil { return err } // <-- entry point
    if err := k.RotateQueries(ctx); err != nil { return err }
    return k.RemoveOldReports(ctx)
}
```

`AutoClaimDeposits` pulls the oldest deposit older than 12h from `BridgeDepositQueue` and calls `bridgeKeeper.ClaimDeposit`, handling only a **returned error** (it dequeues on error):

```go
// x/oracle/keeper/keeper.go:367-384
err = k.bridgeKeeper.ClaimDeposit(ctx, depositId, aggregateTimestamp)
if err != nil {
    k.Logger(ctx).Error("autoClaimDeposits", "error calling claim deposit", err)
    // dequeue on failed claim
    err = k.BridgeDepositQueue.Remove(ctx, collections.Join(aggregateTimestamp, metaId))
    if err != nil { /* log */ return err }
}
// dequeue on successful claim — also reached when the error branch above falls through
err = k.BridgeDepositQueue.Remove(ctx, collections.Join(aggregateTimestamp, metaId))
if err != nil { /* log */ return err }
return nil
```

Note that **both** paths dequeue: a *returned error* from `ClaimDeposit` is handled safely and the poisoned entry would be dropped. A **panic is different in kind** — it unwinds the call stack before either `Remove` executes, and, decisively, the block never commits, so every state write made during that block is discarded anyway. The queue entry itself was persisted by an *earlier*, successfully committed block (`x/oracle/keeper/aggregate.go:153`), and the claim is triggered by wall-clock time (`keeper.go:336`) rather than by a transaction, so there is no transaction to omit and no way to avoid re-entering the same code path. The panic propagates up through `oracle.EndBlocker` → module manager `EndBlock` → `baseapp.FinalizeBlock`, none of which `recover()` (the SDK's panic-recovery middleware wraps per-transaction `runTx` execution only, not `EndBlock`). The panic reaches CometBFT and the node crashes.

`ClaimDeposit` reaches the decode only after the deposit aggregate clears the bridge power threshold:

```go
// x/bridge/keeper/claim_deposit.go:52
if aggregate.AggregatePower < powerThreshold {
    return types.ErrInsufficientReporterPower
}
```

So the attacker must get the malicious value aggregated with `AggregatePower ≥ powerThreshold` — i.e. attested by a ≥2/3 reporter-power quorum (the same trust assumption that secures the bridge). This is a semi-trusted reporter set, not a fully-trusted governance key.

### Persistence — the halt does not self-heal

Because the panic prevents the block from committing, neither `BridgeDepositQueue.Remove` call is ever persisted, and the entry survives in state committed by an earlier block. On restart every node re-selects the same oldest queue entry (`AutoClaimDeposits` walks oldest-first, stopping at the first match) and re-panics at the same height.

Restarting is not a remedy, because the failing block is already durable before it is applied: CometBFT saves the block to the blockStore *before* `ApplyVerifiedBlock` (`consensus/state.go:1727-1735`, then `:1772`), so the handshake replays it on startup (`consensus/replay.go:534`) straight into the identical panic. CometBFT also converts a `FinalizeBlock` *error* into `panic("failed to apply block")` (`consensus/state.go:1781`), so there is no degraded or skip-ahead mode to fall back on.

Cosmovisor does not help either: it acts on `upgrade-info.json`, which is written only by `x/upgrade`'s `PreBlocker` when a governance-approved plan reaches its height — both a passed proposal and a produced block are impossible on a halted chain.

The halt is therefore **deterministic and does not self-heal**: it survives node restart via deterministic block replay, and is recoverable only by every validator obtaining and running a coordinated out-of-band patched binary (or a state-surgery/export hard fork) representing ≥2/3 of validator power.

---

## Impact Details

**Primary impact: total network shutdown (chain halt that does not self-heal) — the highest-severity blockchain/DLT impact.**

- **Liveness:** the chain stops finalizing blocks at the height where `AutoClaimDeposits` first reaches the poisoned deposit. No transactions of any kind can be confirmed: no transfers, no staking/unstaking, no governance, no oracle reporting, no bridge withdrawals, no dispute resolution. The entire network is frozen.
- **Funds at risk:** indirectly, **all funds on the chain are frozen** for the duration of the halt — every `loya` balance, all bonded/unbonding stake, all module escrows (tips, dispute bonds, bridge module account), and all in-flight bridge transfers are inaccessible because no block can be produced. Bridge deposits/withdrawals in flight cannot settle. This is the standard "Network not being able to confirm new transactions (total network shutdown)" Critical impact for blockchain/DLT targets.
- **No self-healing:** unlike a transient consensus stall, this is deterministic and re-fires every block, so the network does not resume on its own. Recovery requires every validator to upgrade to a patched binary and coordinate around the poisoned queue entry — an emergency, multi-party, out-of-band operation (downtime measured in hours to days, as observed in comparable L1 halt incidents).
- **Trigger cost:** the malicious value is trivially constructed; the gating cost is producing a bridge-deposit aggregate that clears the ≥2/3 reporter-power threshold. A reporter coalition controlling ≥2/3 of reporter power (or a single large reporter past that bound) can brick the chain at will. No legitimate deposit can ever reach the overflow boundary (it would require on the order of 9.2e12 TRB, far above total supply), so any occurrence is unambiguously attack-induced. This is materially worse than ordinary 2/3 misbehavior: a colluding quorum normally risks slashing/forking, but here a single poisoned attestation stops the chain outright, with no on-chain remediation path — no dispute, governance vote, or upgrade can execute once blocks stop.

**Severity:** Impact = High (total network shutdown; liveness loss that does not self-heal), Likelihood = Medium (requires the ≥2/3 reporter-power attestation quorum) ⇒ **Critical**. The actor is a semi-trusted reporter quorum rather than a fully-trusted governance key, so no trust-assumption downgrade applies.

**Note on related amplification:** finding H-02 in this audit (stale reporter-power after full undelegation, `FlagStakeRecalc` never set on `RemoveDelegation`) lets a reporter retain power not backed by bonded stake, which lowers the real economic cost of reaching the attestation threshold for this halt.

---

## References

- Vulnerable decode (no upper bound on amount/tip):
  `x/bridge/keeper/claim_deposit.go:221-226` — https://github.com/tellor-io/layer/blob/main/x/bridge/keeper/claim_deposit.go#L221-L226
- Dead `IsAllPositive` guard (after the panic): `x/bridge/keeper/claim_deposit.go:60`, `:65`
- Power gate before decode: `x/bridge/keeper/claim_deposit.go:52`
- Submit-time validation gap (sign-only, tip unchecked): `x/oracle/keeper/token_bridge_deposit.go:79-110` — https://github.com/tellor-io/layer/blob/main/x/oracle/keeper/token_bridge_deposit.go#L79-L110
- Oracle `EndBlocker` entry point: `x/oracle/abci.go:13-23` — https://github.com/tellor-io/layer/blob/main/x/oracle/abci.go
- `AutoClaimDeposits` (error-only handling, panic bypasses dequeue): `x/oracle/keeper/keeper.go:333-380` — https://github.com/tellor-io/layer/blob/main/x/oracle/keeper/keeper.go#L367-L376
- Cosmos SDK `NewCoin` panics on negative amount: `github.com/cosmos/cosmos-sdk@v0.53.4/types/coin.go` (`NewCoin` → `Validate` → `IsNegative`)
- Go `math/big` `Int.Int64()` is undefined when the value does not fit in `int64`: https://pkg.go.dev/math/big#Int.Int64
- Audited commit: `943a2709` (HEAD of `main` at audit time)

---

## Proof of Concept

All PoCs run against the unmodified codebase with the repo's pinned toolchain.

> **Build/run note:** the host Go toolchain is newer than `go.mod`'s pin, and `GOTOOLCHAIN=auto` will not downgrade (it breaks on the `bytedance/sonic` dependency). All commands below pin `GOTOOLCHAIN=go1.24.13`.

### PoC 1 — End-to-end chain halt on the real consensus `EndBlocker` (decisive)

This integration PoC clones the project's own passing `TestClaimingBridgeDeposit` flow verbatim (real validators, reporters, bridge checkpoint, tip, aggregation, real keepers) and changes exactly one thing — the attested deposit value carries an unbounded amount — then asserts the real `oracle.EndBlocker` panics.

File: `tests/integration/claim_deposit_overflow_test.go`

```go
func (s *IntegrationTestSuite) TestBridgeDepositOverflowHaltsEndBlocker() {
    // ... identical setup to TestClaimingBridgeDeposit:
    //     5 bonded validators -> reporters, bridge ValidatorCheckpointParams{PowerThreshold: 3000e6},
    //     tip a TRBBridgeV2 deposit (depositId=1) ...

    // THE ATTACK: amount = 1e31 wei -> /1e12 = 1e19 > MaxInt64. Recipient is a valid layer addr.
    overflowAmount, _ := new(big.Int).SetString("10000000000000000000000000000000", 10)
    overflowValue, _ := packBridgeDepositValue(valAccAddrs[0].String(), overflowAmount, big.NewInt(0))

    for _, rep := range valAccAddrs {
        _, err = oracleMsgServer.SubmitValue(ctx, &types.MsgSubmitValue{
            Creator: rep.String(), QueryData: bridgeQueryData, Value: overflowValue,
        })
        require.NoError(err, "malicious value passes submit (only sign-checked)")
    }
    // ... fast-forward so the deposit aggregates and verify it on-chain:
    require.Equal(overflowValue, res.Aggregate.AggregateValue) // the unbounded value IS the on-chain aggregate

    // fast forward 12h so the deposit is auto-claimable in the EndBlocker
    ctx = ctx.WithBlockTime(time.Now().Add(13 * time.Hour))

    // HARM: the real consensus EndBlocker PANICS (does not return an error) -> chain halt.
    pv := recoverPanic(func() { _ = oracle.EndBlocker(ctx, s.Setup.Oraclekeeper) })
    require.NotNil(pv, "oracle EndBlocker must PANIC on the overflow deposit (uncaught -> halt)")
    require.Contains(panicMsg(pv), "negative coin amount")
    s.T().Logf("CONFIRMED CHAIN HALT — oracle.EndBlocker panicked: %q", panicMsg(pv))

    // deposit still unclaimed AND still queued -> on a real node every block re-panics.
    _, err = s.Setup.Bridgekeeper.DepositIdClaimedMap.Get(ctx, uint64(1))
    require.ErrorContains(err, "collections: not found")
}
```

Run:

```bash
GOTOOLCHAIN=go1.24.13 go test ./tests/integration/ \
  -run 'TestKeeperTestSuite/TestBridgeDepositOverflowHaltsEndBlocker' -v
```

Output (confirmed):

```
=== RUN   TestKeeperTestSuite/TestBridgeDepositOverflowHaltsEndBlocker
    claim_deposit_overflow_test.go:207: CONFIRMED CHAIN HALT — oracle.EndBlocker panicked: "negative coin amount: -8446744073709551616"
--- PASS: TestKeeperTestSuite/TestBridgeDepositOverflowHaltsEndBlocker (0.03s)
PASS
```

`-8446744073709551616` is exactly `1e19 − 2⁶⁴`, the Int64 overflow wrap. The malicious value aggregated on-chain and the real `oracle.EndBlocker` halted.

### PoC 2 — Unit-level harm (amount and the unvalidated tip), and panic-not-error

File: `x/bridge/keeper/claim_deposit_overflow_test.go`

- `TestClaimDepositOverflowPanics_Amount` — decoding a deposit value with `amount = 1e31` panics with `negative coin amount`.
- `TestClaimDepositOverflowPanics_Tip` — decoding a value with a valid amount but `tip = 1e31` panics identically (proves the tip field is entirely unvalidated).
- `TestClaimDepositOverflow_PanicsNotErrors` — the real `ClaimDeposit`, with the value cleared past the 2/3 power gate and 12h age gate, **panics rather than returning an error**, which is why `AutoClaimDeposits`' error handler cannot catch it.

Run:

```bash
GOTOOLCHAIN=go1.24.13 go test ./x/bridge/keeper/ -run 'TestClaimDepositOverflow' -v
```

Output (confirmed):

```
--- PASS: TestClaimDepositOverflowPanics_Amount (0.00s)
--- PASS: TestClaimDepositOverflow_PanicsNotErrors (0.00s)
--- PASS: TestClaimDepositOverflowPanics_Tip (0.00s)
PASS
```

### Environment confirmation

The full node binary builds and runs a live single-validator chain executing this exact code path:

```bash
GOTOOLCHAIN=go1.24.13 go build ./cmd/layerd      # builds layerd
# init + (genesis: stake->loya, vote_extensions_enable_height=1) + gentx, then:
./layerd start --home <home> --key-name <val>    # produces blocks (verified to height 23+, vote extensions active)
```

### Suggested fix

```go
// x/bridge/keeper/claim_deposit.go — before the NewInt64Coin calls
if !amountDecimalConverted.IsInt64() || !tipDecimalConverted.IsInt64() {
    return nil, sdk.Coins{}, sdk.Coins{}, types.ErrInvalidDepositReportValue.Wrap("amount/tip exceeds int64")
}
```

Prefer `sdk.NewCoin(layer.BondDenom, math.NewIntFromBigInt(amountDecimalConverted))` (returns an error instead of panicking). Add a symmetric upper-bound check for both `amount` and the currently-unvalidated `tip` in `validateBridgeDepositAmount` so the malformed value is rejected at `MsgSubmitValue` and never aggregates. Additionally, treat the bridge auto-claim invoked from the oracle `EndBlocker` defensively (log + dequeue on failure, like the existing returned-error path) so no single deposit can panic block production.

---

## Caveats, Scope & Disclosure

This finding was run through an adversarial disqualifier gate (admin/permission gating, scope, already-known, by-design, reachability, preconditions, trust-model). It survives all of them; the relevant rulings, with citations:

- **Permission gating — none (permissionless given the precondition).** No admin/authority/whitelist guard on the path; the only precondition is clearing the bridge power gate (`x/bridge/keeper/claim_deposit.go:51-52`, `if aggregate.AggregatePower < powerThreshold`). The actor is a **semi-trusted ≥2/3 reporter-power quorum**, not a fully-trusted governance key, so no trusted-actor downgrade applies (per the matrix this is already captured as Medium likelihood → Critical).
- **Trust model — this attacker sits inside the defended zone, not outside it.** The project grants a trust exemption only at **strictly greater than 2/3**: ADR2001 addresses *"a completely compromised layer chain (>2/3 malicious)"*, for which *"a social fork will be necessary to save layer"*, and notes the 5% withdraw limit *"mitigates the worst case scenario where a supermajority of the reporter set is compromised, allowing time to react and coordinate a social fork"* (`adr/adr2001 - trb bridge structure.md:68,28`). Nothing exempts sub-supermajority coalitions.

  The directly on-point document is **ADR1012 (reporter power cap)**, which is explicit that reporter concentration below that line is both reachable and unremediated: *"Nothing today stops a single reporter from accumulating 30%, 50%, or more of total reporting power. A reporter that large can dominate medians on low-participation queries"* (`adr/adr1012 - reporter power cap.md:20`). The 30% cap *"prevents crossings rather than remediating existing concentration"* (`:22`), and the ADR states plainly: *"**No retroactive remediation.** If a reporter is at/over the cap when the upgrade activates … nothing forces divestment"* (`:81`). The cap is also enforced per **reporter address** in the ante handler (`x/reporter/ante/ante.go:808-824`) with no sybil resistance — a second reporter identity costs `MinLoya` (1 TRB, `x/reporter/keeper/msg_server.go:56-58`), and `AddReportWeightedMode` sums identical values across distinct reporters (`x/oracle/keeper/submit_value.go:293`), so the cap forces two addresses rather than bounding a coalition.

  A reporter coalition attesting a fabricated deposit is therefore an adversary the protocol explicitly models and builds controls against — it is not an assumed-honest party, and it is below the only threshold at which the design concedes the chain.
- **Aggravating — the protocol's own mitigations cannot stop it.** The post-hoc defenses (per-period bridge withdrawal caps, social fork) operate *after* a malicious attestation; this panic fires during `EndBlock` decode, *before* any cap or fork response, and re-fires every block. The team's own comment (`x/oracle/keeper/keeper.go:329-332`, *"claim deposit should only fail if aggregate power is not reached"*) shows the uncaught-panic path was not anticipated.
- **No EVM-side mitigation.** The Layer chain does **not** independently verify the deposit against an Ethereum event/proof (no L1 cross-check exists in `x/bridge`/`x/oracle`). The Ethereum bridge contract's amount caps (`amount % 1e12 == 0`, `> 0.1 ether`) constrain *real* deposits but **do not bound a fabricated attestation**, which is what a malicious quorum submits.
- **Not already known.** The unbounded conversion has existed since the feature's introduction; the only added validation (`#996`) checks the amount's sign only and never the tip; `#1031` (`DecodeValue`) does not touch this path; no audit report, advisory, CHANGELOG, ADR, or `TODO`/`known` comment references it.
- **Reachable in production.** The deposit is queued unconditionally on aggregation (`x/oracle/keeper/aggregate.go:151-153`) and `AutoClaimDeposits` runs every block in the oracle `EndBlocker` (`x/oracle/abci.go:21`, ordered in `app/app.go` `SetOrderEndBlockers`).

**Scope — confirm before submission.** `SECURITY.md` references *"the scope set out below"* but enumerates no scope list, and no public bug-bounty program (Immunefi/HackenProof) for the **Tellor Layer cosmos chain** could be located. Disclose privately via the channel in `SECURITY.md` (**info@tellor.io**, initial confirmation within 72h) and confirm that the Layer chain and a *chain-halt / total-network-shutdown* impact are an in-scope, rewarded Critical. Do not assume a public-bounty payout.
