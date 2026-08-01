# Missing cross-state validation on `x/mint` `MaxSupply` lets a parameter update drive ecosystem mint supply negative, panicking `BeginBlocker` and causing an unrecoverable total chain halt

**Severity:** Critical (total, unrecoverable network shutdown)
**Component:** `x/mint` (emission/inflation module)
**Asset:** allora-chain L1 (`github.com/allora-network/allora-chain`, branch `dev`, commit `9fd4a374`)
**Status:** Confirmed on-chain — in-process real-keeper test **and** a literal single-node `allorad` + CometBFT regtest (`CONSENSUS FAILURE`, block 1 never finalizes)

---

## Brief / Intro

The `x/mint` module computes how many tokens the "ecosystem" bucket may still mint as `EcosystemTreasuryPercentOfTotalSupply × MaxSupply − EcosystemTokensMinted`, with **no lower clamp**, and `Params.Validate()` never relates that param-derived cap to the already-accumulated `EcosystemTokensMinted` runtime state. A whitelist admin (or a genesis author) can therefore set a `MaxSupply` (a routine monetary-policy change) that makes the remaining ecosystem mint supply **negative** while passing every validation gate. On the next block, `BeginBlocker` constructs a coin from that negative amount (and/or recomputes a negative target emission), which **panics inside `BeginBlocker`**. Because `BeginBlocker` runs before any transaction in the block, the bad parameter can never be corrected by a follow-up transaction — every validator panics on every block and the **entire network is permanently, unrecoverably halted** until a coordinated binary patch / state surgery / hard fork. Exploited on mainnet, this is a complete network shutdown: no transfers, no staking, no governance, no withdrawals — all funds frozen indefinitely.

---

## Vulnerability Details

### Root cause — an unclamped, un-cross-validated cap

`GetEcosystemMintSupplyRemaining` subtracts the *runtime* minted total from a *parameter-derived* cap and returns the raw difference, which can be negative:

```go
// x/mint/keeper/emissions.go:264-278
func (k Keeper) GetEcosystemMintSupplyRemaining(ctx context.Context, params types.Params) (math.Int, error) {
	ecosystemTokensAlreadyMinted, err := k.EcosystemTokensMinted.Get(ctx)
	if err != nil {
		return math.Int{}, err
	}
	ecosystemMaxSupply := math.LegacyNewDecFromInt(params.MaxSupply).
		MulTruncate(params.EcosystemTreasuryPercentOfTotalSupply).TruncateInt()
	return ecosystemMaxSupply.Sub(ecosystemTokensAlreadyMinted), nil  // <-- NO clamp: can be negative
}
```

The only gate on `MaxSupply` is a stateless positivity/format check; nothing relates `MaxSupply × EcosystemTreasuryPercent` to `EcosystemTokensMinted`:

```go
// x/mint/types/params.go:82  (Params.Validate)  — validateMaxSupply only checks MaxSupply > 0;
// validateTokenSupplyAddsTo100Percent only checks the six fraction params sum to 1.
// There is NO check that EcosystemTreasuryPercent*MaxSupply >= EcosystemTokensMinted.
```

This is a classic *missing constraint*: the cap is **used** in consensus arithmetic but is never **pinned** to the runtime state it must dominate. Under normal operation `EcosystemTokensMinted` can never exceed the cap (minting in `BeginBlocker` is clamped to `remaining`), so the only way to invert the relationship is to *lower the cap below already-minted supply* via a parameter change — which validation does not catch.

### The panic sinks in `BeginBlocker`

Once `remaining` is negative, the next `BeginBlocker` halts via one of two sinks that share the same root cause:

**Sink A — negative-coin panic (steady-state mint branch):**

```go
// x/mint/module/abci.go:96-109
if blockEmission.GT(ecosystemBalance) {                 // steady state: emission > ecosystem balance
	tokensToMint := blockEmission.Sub(ecosystemBalance)
	if tokensToMint.GT(ecosystemMintSupplyRemaining) {  // positive > negative  => true
		blockEmission = blockEmission.Sub(tokensToMint).Add(ecosystemMintSupplyRemaining)
		tokensToMint = ecosystemMintSupplyRemaining     // tokensToMint is now NEGATIVE
	}
	coins := sdk.NewCoins(sdk.NewCoin(moduleParams.MintDenom, tokensToMint)) // sdk.NewCoin panics: "negative coin amount"
	...
}
```

`sdk.NewCoin(denom, negative)` calls `Coin.Validate()`, which panics on a negative amount. There is no `recover` in the module's `BeginBlock`, so the panic propagates and aborts block processing.

**Sink B — negative target emission (month-boundary recalc; the path hit by the regtest at block 1):**

```go
// x/mint/keeper/emissions.go:238  (inside RecalculateTargetEmission, called from BeginBlocker on a month boundary)
// returns: "target emission per token is negative: ... : negative target emission per token"
// -> this error propagates out of BeginBlocker -> FinalizeBlock fails -> CometBFT CONSENSUS FAILURE
```

### Why it is unrecoverable

The panic/abort is inside `BeginBlocker`, which executes at the **start of every block, before any transaction is delivered**. Therefore:
- The bad parameter is committed state; it persists across restarts.
- No `MsgUpdateParams` (or any tx) can ever be included to fix it, because the block never finalizes.
- Every honest validator hits the identical deterministic failure → the chain produces no further blocks.
- Recovery requires an out-of-band, coordinated emergency binary patch + state migration / rollback (hard fork).

### Reachability / trigger

- **Runtime trigger:** a mint-params whitelist admin sends `MsgUpdateParams` lowering `MaxSupply` (or `EcosystemTreasuryPercentOfTotalSupply`) so that `EcosystemTreasuryPercent × MaxSupply < EcosystemTokensMinted`. The mint whitelist is a **mutable, on-chain whitelist where any existing admin can add new admins** — it is *not* `x/gov` and *not* a timelock. The triggering action is a legitimate-looking monetary-policy change, and `Params.Validate()` *accepts it*, giving false assurance of safety.
- **Genesis trigger:** the identical halt state can be encoded in a genesis file that passes `allorad genesis validate-genesis` (the same missing validation), bricking the chain at block 1.

---

## Impact Details

- **Total network shutdown (Critical).** The real `allorad` binary under CometBFT throws `CONSENSUS FAILURE` and cannot finalize a block. All chain activity stops: token transfers, staking/unstaking, reward emission, topic/worker/reputer operations, governance, and IBC. **100% of on-chain funds are frozen** for the duration of the halt.
- **Unrecoverable without a hard fork.** Because the failure is in `BeginBlocker` (pre-transaction), there is no on-chain remediation path. Restoring liveness requires every validator to deploy a patched binary and/or perform coordinated state surgery — i.e., an emergency hard fork. Downtime is measured in hours-to-days of full network outage plus the reputational and economic damage of a public chain halt.
- **Latent false assurance.** `Params.Validate()` and `validate-genesis` both *pass* the chain-bricking value, so neither operators nor tooling get any warning before the change activates.
- **Trigger realism.** The runtime trigger does not require a malicious, fully-trusted governance actor — it fires on a routine `MaxSupply` reduction by a mutable/low-bar whitelist admin. (Honest caveat: a severity rubric that treats the mint whitelist as a fully-trusted role would rate this High; we assess Critical on the confirmed total-shutdown impact, the unrecoverability, and the validation gap that actively blesses the dangerous value.)

In-scope impact mapping: **"Network not being able to confirm new transactions / total network shutdown"** and **"Unintended permanent chain split / halt requiring hard fork"** — the canonical Critical class for an L1.

---

## References

- `x/mint/keeper/emissions.go:264-278` — `GetEcosystemMintSupplyRemaining` (unclamped negative remaining)
- `x/mint/keeper/emissions.go:238` — negative target emission error (regtest sink)
- `x/mint/module/abci.go:96-109` — `BeginBlocker` mint branch (`sdk.NewCoin(negative)` panic sink)
- `x/mint/types/params.go:82` — `Params.Validate()` (missing cross-state check)
- `x/mint/keeper/msg_server.go` — `UpdateParams` (whitelist-admin gate, then `Params.Validate()`)
- `x/emissions/keeper/whitelist.go` — mutable whitelist-admin model (`IsWhitelistAdmin`, add-admin)
- Cosmos SDK `types/coin.go` — `NewCoin` panics on negative amount

---

## Proof of Concept

Two complementary, runnable PoCs are included. Both are additive (`_test.go` / shell script); no production code is modified.

### PoC 1 — In-process, real-keeper consensus test (proves the runtime admin-regression flow)

`x/mint/module/poc_halt_test.go` uses the module test suite with **real** `auth`/`bank`/`staking`/`emissions`/`mint` keepers (the in-process consensus state machine) and calls the real `mint.BeginBlocker`.

```
go test ./x/mint/module/ -run 'TestMintModuleTestSuite/TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression' -v
```

Steps the test performs:
1. Seed realistic mid-life state: `AddEcosystemTokensMinted = 1e26` (well within the default cap of `1e27 × 0.3595 = 3.595e26`).
2. Build regressed params: lower `MaxSupply` to `2e26` → new cap `7.19e25 < 1e26`.
3. **Assert `params.Validate()` returns `nil`** — the chain-bricking value is accepted (the missing constraint).
4. Apply the params; set `PreviousBlockEmission = 1e12` (> ecosystem balance); block height 2.
5. Assert `GetEcosystemMintSupplyRemaining` is **negative**.
6. **Assert `mint.BeginBlocker` panics** on block 2 **and** block 3 (unrecoverable).

Observed result (PASS):
```
poc_halt_test.go: ecosystemMintSupplyRemaining (negative) = -28100000000000000000000000
--- PASS: TestMintModuleTestSuite/TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression
```

### PoC 2 — Literal single-node regtest on the built binary (proves the halt under real CometBFT)

`poc_regtest_mint_halt.sh` builds `allorad`, inits a throwaway single-node chain, injects the regressed state into genesis (which **passes `validate-genesis`**), starts the node, and observes the consensus failure.

```
make build && bash poc_regtest_mint_halt.sh
```

Observed result:
```
### genesis validate: ... is a valid genesis file
### starting node (15s window)...
ERR Mint BeginBlocker error!  module=server
ERR error in proxyAppConn.FinalizeBlock  err="could not recalculate target emission:
      target emission per token is negative: 0.605 | -28100 | -425.0125 : negative target emission per token"  module=state
ERR CONSENSUS FAILURE!!!  err="failed to apply block; ... [x/mint/keeper/emissions.go:238]"  module=consensus
   panic -> github.com/cometbft/cometbft/consensus.(*State).finalizeCommit ...
### ===== RESULT =====
CHAIN_HALT_CONFIRMED=YES
```

The real `allorad` binary under CometBFT **could not finalize block 1** — a total, on-chain consensus failure.

(PoC 1 proves the *runtime trigger* — a validated `MsgUpdateParams`; PoC 2 proves the resulting committed state *halts the binary under real consensus*. Together they confirm the full end-to-end Critical.)

---

## Recommended Fix

1. Enforce the cross-state invariant at the keeper `UpdateParams` boundary (where runtime state is available), rejecting any params where `MaxSupply × EcosystemTreasuryPercentOfTotalSupply < EcosystemTokensMinted`; mirror the check in genesis validation.
2. Defensively clamp `GetEcosystemMintSupplyRemaining` at zero so a stale/regressed cap degrades to "mint nothing" instead of producing a negative value:

```diff
- return ecosystemMaxSupply.Sub(ecosystemTokensAlreadyMinted), nil
+ remaining := ecosystemMaxSupply.Sub(ecosystemTokensAlreadyMinted)
+ if remaining.IsNegative() {
+     remaining = math.ZeroInt()
+ }
+ return remaining, nil
```

3. Convert the `BeginBlocker` mint path to never construct a coin from an unchecked amount (guard `tokensToMint.IsNegative()` before `sdk.NewCoin`), and have `RecalculateTargetEmission` return a clamped (non-negative) emission rather than a propagating error during consensus.
