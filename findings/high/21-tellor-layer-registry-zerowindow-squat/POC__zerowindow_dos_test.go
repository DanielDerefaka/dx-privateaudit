package keeper_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tellor-io/layer/testutil/sample"
	"github.com/tellor-io/layer/x/registry/types"
)

// REG-01: runtime RegisterSpec lacks the ReportBlockWindow==0 guard that genesis
// Validate() enforces. A permissionless tx can register a spec with a zero report
// block window, and because re-registration is blocked (AlreadyExists), the query
// type is permanently squatted (governance-only recovery).
func TestZeroWindowSpecAcceptedAndSquats(t *testing.T) {
	ms, ctx, k := setupMsgServer(t)
	registrar := sample.AccAddress()
	qType := "spotprice2" // a not-yet-registered query type

	mal := types.DataSpec{
		DocumentHash:      "h",
		ResponseValueType: "uint256",
		AggregationMethod: "weighted-median",
		QueryType:         qType,
		Registrar:         registrar,
		ReportBlockWindow: 0, // <-- the bug: rejected at genesis, accepted at runtime
		AbiComponents: []*types.ABIComponent{
			{Name: "field", FieldType: "uint256"},
		},
	}

	// HARM 1: runtime accepts the zero-window spec (no ReportBlockWindow guard).
	_, err := ms.RegisterSpec(ctx, &types.MsgRegisterSpec{Registrar: registrar, QueryType: qType, Spec: mal})
	require.NoError(t, err)

	// Contrast proof: the genesis validator WOULD reject the identical spec.
	// This demonstrates the missing-runtime-invariant root cause, not a coincidence.
	gs := types.GenesisState{Params: types.DefaultParams(), Dataspec: []types.DataSpec{mal}}
	require.Error(t, gs.Validate(), "genesis must reject window==0")
	require.ErrorContains(t, gs.Validate(), "report block window is 0")

	has, err := k.HasSpec(ctx, qType)
	require.NoError(t, err)
	require.True(t, has, "malformed spec is now stored on-chain")

	// HARM 2: a legitimate later registration of the same query type is permanently blocked.
	good := mal
	good.ReportBlockWindow = 10
	_, err = ms.RegisterSpec(ctx, &types.MsgRegisterSpec{Registrar: registrar, QueryType: qType, Spec: good})
	require.ErrorContains(t, err, "data spec previously registered")
}
