package mint_test

// PoC: Unrecoverable chain halt via a MaxSupply parameter regression that the
// mint module's Params.Validate() fails to reject.
//
// Root cause: x/mint/keeper/emissions.go GetEcosystemMintSupplyRemaining returns
//   ecosystemMaxSupply.Sub(ecosystemTokensAlreadyMinted)
// with NO clamp. ecosystemMaxSupply = MaxSupply * EcosystemTreasuryPercentOfTotalSupply
// is a function of *params*, while ecosystemTokensAlreadyMinted is accumulated
// *runtime state*. x/mint/types/params.go Params.Validate() never relates the two.
//
// A whitelist admin (a MUTABLE on-chain whitelist where any admin can add admins;
// NOT x/gov, NOT a timelock) can therefore set, via a single MsgUpdateParams that
// passes every validation gate, a MaxSupply lower than the value already minted.
// On the very next block, x/mint/module/abci.go BeginBlocker computes a NEGATIVE
// remaining supply, sets tokensToMint to that negative value, and constructs
// sdk.NewCoin(denom, negativeAmount), which PANICS ("negative coin amount").
//
// Because the panic is in BeginBlocker (which runs at the start of every block,
// before any transaction is processed), the bad parameter can never be corrected
// by a subsequent tx: every node panics on every block => the chain is PERMANENTLY,
// UNRECOVERABLY halted (recovery requires a coordinated binary patch / state surgery
// / hard fork). Params.Validate() passing gives false assurance that the change is safe.

import (
	cosmosMath "cosmossdk.io/math"

	"github.com/allora-network/allora-chain/app/params"
	mint "github.com/allora-network/allora-chain/x/mint/module"

	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (s *MintModuleTestSuite) TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression() {
	// ---- 1. Seed realistic mid-life minting state -------------------------------
	// Pretend the chain has been running and the ecosystem bucket has already minted
	// 1e26 uallo. Default cap = MaxSupply(1e27) * EcosystemPct(0.3595) = 3.595e26, so
	// 1e26 is well within the legitimate cap at this point.
	alreadyMinted, ok := cosmosMath.NewIntFromString("100000000000000000000000000") // 1e26
	s.Require().True(ok)
	s.Require().NoError(s.mintKeeper.AddEcosystemTokensMinted(s.ctx, alreadyMinted))

	// ---- 2. Build the regressed parameters --------------------------------------
	// A whitelist admin lowers MaxSupply (a plausible monetary-policy change) to 2e26.
	// New cap = 2e26 * 0.3595 = 7.19e25, which is now BELOW the 1e26 already minted.
	mintParams, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	regressedMaxSupply, ok := cosmosMath.NewIntFromString("200000000000000000000000000") // 2e26
	s.Require().True(ok)
	mintParams.MaxSupply = regressedMaxSupply

	// ---- 3. THE MISSING CONSTRAINT: Validate() accepts the chain-bricking value --
	// validateMaxSupply only checks > 0; nothing relates MaxSupply*EcosystemPct to
	// the already-minted runtime state. This is the under-constrained "missing check".
	s.Require().NoError(
		mintParams.Validate(),
		"VULN: Params.Validate() ACCEPTS a MaxSupply regression below already-minted supply",
	)

	// ---- 4. Apply the regressed params (effect of a successful MsgUpdateParams) --
	s.Require().NoError(s.mintKeeper.Params.Set(s.ctx, mintParams))

	// ---- 5. Establish the steady-state precondition: emission > ecosystem balance-
	// The ecosystem account is being continuously drained by payouts, so per-block
	// emission exceeding its balance is the NORMAL operating condition (that is why
	// the module mints). Ecosystem balance is 0 here; any positive emission triggers
	// the mint branch.
	s.Require().NoError(s.mintKeeper.PreviousBlockEmission.Set(s.ctx, cosmosMath.NewInt(1_000_000_000_000))) // 1e12
	s.ctx = s.ctx.WithBlockHeight(2)                                                                         // not a month boundary -> no recalc path

	// Confirm the root-cause precondition: remaining ecosystem mint supply is NEGATIVE.
	p, err := s.mintKeeper.Params.Get(s.ctx)
	s.Require().NoError(err)
	remaining, err := s.mintKeeper.GetEcosystemMintSupplyRemaining(s.ctx, p)
	s.Require().NoError(err)
	s.Require().True(
		remaining.IsNegative(),
		"precondition: GetEcosystemMintSupplyRemaining must be negative, got %s", remaining.String(),
	)
	s.T().Logf("ecosystemMintSupplyRemaining (negative) = %s", remaining.String())

	// ---- 6. HARM: the next block's BeginBlocker PANICS -> unrecoverable halt ------
	s.Require().Panics(
		func() {
			_ = mint.BeginBlocker(s.ctx, s.mintKeeper)
		},
		"HARM: BeginBlocker must panic (negative coin amount) -> chain halt",
	)

	// ---- 7. Demonstrate it is UNRECOVERABLE: every subsequent block also panics ---
	// (No corrective tx can ever run, because BeginBlocker fails before tx processing.)
	s.ctx = s.ctx.WithBlockHeight(3)
	s.Require().Panics(
		func() {
			_ = mint.BeginBlocker(s.ctx, s.mintKeeper)
		},
		"HARM: every subsequent BeginBlocker also panics -> permanent halt",
	)

	// Sanity: prove the panic really is the negative-coin construction.
	s.Require().Panics(func() {
		_ = sdk.NewCoin(params.DefaultBondDenom, remaining) // remaining is negative
	}, "the negative remaining supply is what NewCoin rejects with a panic")
}
