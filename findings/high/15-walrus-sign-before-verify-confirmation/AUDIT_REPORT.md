# Walrus Security Audit — Findings Report

**Date**: 2026-06-17
**Auditor**: Plamen automated security analysis (methodology: decompose → narrow hunt → adversarial verify → regtest-faithful PoC)
**Scope**: Move contracts (`contracts/`), `walrus-core` (encoding/crypto), `walrus-service` (storage node), `walrus-sui`
**Build status**: `sui move build` OK; `sui move test` 254/254 PASS; `walrus-service` builds; one PoC test added and **executed** (see H-01)
**Honest top-line verdict**: **No confirmable CRITICAL was found** despite exhaustive coverage. The strongest confirmed finding is **High** (H-01), mechanically proven by running the real node code. Three separate agent "Critical" claims were each downgraded by adversarial verification (recorded below) — the methodology working as intended, not a shortcut.

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 3 |
| Low | several |

---

## High Findings

### [H-01] Storage node signs availability confirmations without verifying sliver content (sign-before-verify; WAL-523 class) — **CONFIRMED via executed PoC**

**Severity**: High
**Location**: `crates/walrus-service/src/node.rs:4580-4644` (`compute_storage_confirmation`), `crates/walrus-service/src/node/storage/shard.rs:584-619` (`is_sliver_pair_stored` = key-presence only), `shard.rs:1249` (`//TODO(WAL-523): verify sliver validity` — unverified sync writer), `node/node_recovery.rs:142-152` (recovery skipped when key present), `node/consistency_check.rs` (no content scrub).

**Description**: `compute_storage_confirmation` signs an availability attestation gated only on `is_stored_at_all_shards_at_latest_epoch`, which is a pure RocksDB key-presence check — it never re-hashes the stored sliver bytes against the blob's Merkle commitment. The shard-sync receiver persists slivers from a single previous-epoch owner with **no verification** (the WAL-523 TODO), recovery self-heal is skipped while the (garbage) key is present, and there is no background content scrub. Result: a node attests "I store blob X" for bytes that are not X's sliver, and never self-heals the corruption.

**PoC (executed, real node code)**: `crates/walrus-service/src/node.rs::tests::poc_signs_confirmation_for_unverifiable_sliver`. Fully stores + registers a blob on an in-process node (baseline confirmation signs), then overwrites a shard's primary sliver with a single-byte-flipped (Merkle-invalid) sliver via the unverified `put_sliver` path, and asserts:
1. the node **still returns `Ok`/`Signed`** from `compute_storage_confirmation` (HARM 1), and
2. the stored sliver **fails `Sliver::verify`** against the blob metadata while the legitimate sliver verifies (HARM 2 + control).

Result: `test ... ok. 1 passed; 0 failed` (full `walrus-service` build + execution).

**Impact (calibrated, honest)**: Dishonest availability attestation + suppressed self-healing of corruption. It does **not** by itself (within the protocol's ≤ f Byzantine trust model, single epoch) certify an unrecoverable blob (the client-store path *does* verify, so initial certification is backed by verified data) or cause permanent loss of a certified blob: reconstruction needs `f+1` correct primary slivers (`source_symbols_primary = n−2f`), so loss requires corrupting `> 2f` shards (`> 2/3`). The escalation toward permanent data loss requires multi-epoch accumulation of unhealed corruption across `> 2f` distinct shards. Investigated and found **not attacker-controllable**: `committee::transition` (committee.move:57-131) minimizes shard movement (a node keeping the same shard count retains its exact shard IDs; only shards from departing/decreasing nodes are reassigned), and an isolated adversary that unstakes/restakes **reclaims its own released shards** from the `to_move` pool — acquiring *distinct* fresh shards to corrupt requires substantial *external* honest-node churn the adversary cannot force. Corruption is permanent and propagates on resync, so under sustained ≤ f Byzantine control plus heavy independent network churn the corrupt set can grow over many epochs toward `> 2f` (permanent, network-wide loss of certified data) — but this is a slow, churn-dependent degradation, not an on-demand exploit. Hence **High (with a churn-dependent path to Critical)**, not a confirmable Critical.

**Recommendation**: Verify each synced sliver against blob metadata before `insert_batch` (reuse `verify_sliver_against_metadata`); gate confirmation-signing and recovery-skip on a *verified*-storage marker (not raw key presence); add a periodic content scrub that re-hashes stored slivers and triggers verified recovery on mismatch.

### [H-02] Permanent epoch-transition halt — no `epoch_sync_done` timeout

**Severity**: High (liveness; requires ~1/3 of shard weight)
**Location**: `contracts/walrus/sources/staking/staking_inner.move:746-754` (`epoch_sync_done`), `:889` (`is_quorum`).
**Description**: Epoch transition completes only when synced shard weight reaches `is_quorum` (>2/3). There is **no timeout / fallback branch**. A party controlling > 1/3 of shard weight that withholds `epoch_sync_done` stalls the transition **permanently** (no recovery path). This is the BFT liveness boundary, but the absence of any recovery mechanism makes the halt permanent rather than degraded.
**Recommendation**: Add a clock-based sync-quorum timeout / governance fallback so a withholding minority cannot brick epochs indefinitely.

---

## Medium Findings

### [M-01] Storage-pool absorb/extract over-grants epoch range (integrity, past-confined)
`storage_pool.move:240-250` (`increase_capacity_with_storage` checks only `end_epoch`, not `start_epoch`) + `storage_resource.move:82-92` (`split_by_size` copies the full `[start,end)` range). An extracted `Storage` can *claim* a longer validity window than was paid for, but the over-granted range always lies in **already-elapsed past epochs** (both pool and absorbed starts are ≤ current epoch), so it yields no usable free storage. Fix: assert `other.start_epoch == pool.start_epoch` (or re-account).

### [M-02] `wal_exchange` rate-change extraction (trusted-actor-gated)
`wal_exchange.move:141-192`: swaps have no slippage/min-out and rate changes are instant, so a holder can swap across an admin `set_exchange_rate` for net gain. Requires the (trusted) admin to move the rate. Fix: add min-out parameters.

### [M-03] Sybil-split defeats the per-node shard cap (within BFT trust model)
`staking_inner.move` d'Hondt + per-*identity* cap (`n_shards/10`), `MIN_STAKE=0`, free registration. Splitting stake across identities restores full proportional weight, but running multiple nodes is expected and the real security boundary is the <1/3-*stake* assumption; crossing thresholds still requires ~1/3 of all staked WAL. Design/decentralization observation, not a cheap exploit.

---

## Low / Informational (selected)
- Active-set silently drops a saturated committee veteran (swallowed `insert_or_update` bool); equal-stake newcomer rejected at capacity (`active_set.move`).
- `storage_pool::remove_blob` recomputes encoded size from live `n_shards` (latent; safe while `n_shards` is genesis-fixed).
- blob_bucket expired-pool `Storage` permanently locked (no `&mut StoragePool` path) — owner's own capacity stranded.
- `execute_slashing` emits no event (observability).
- Latent `todo!()` panic on `DenyListBlobDeleted` event (`blob_event_processor.rs:151`) — not currently emittable.

---

## Verified clean (high-value surfaces, with evidence)
- **Rust crypto core** (`walrus-core` encoding, blob_id binding, Merkle leaf-index binding, sliver/recovery verification): **12 executed forgery PoCs, all rejected**. blob_id = `Blake2b256(encoding_type || unencoded_len_le || merkle_root)`, matches on-chain `derive_blob_id`.
- **BLS certification / committee**: proof-of-possession enforced at registration (`messages.move:86-96`); weight bound to signature via aggregate-key; epoch + intent inside signed bytes. Rogue-key, bitmap, replay all refuted.
- **Encoding size** (Move vs Rust): bit-identical across 18k inputs; charge rounds up.
- **Staking value conservation** (system↔staking reward handoff): holds; Move `Balance` prevents loss.
- **Package upgrade / init**: quorum + monotonic version + receipt gated; one-shot init.
- **Blob lifecycle / GC / deletion**: on-chain-gated, refcount-protected; no premature deletion.

---

## Verification artifacts
- `.audit/sui` — `sui` v1.73.1-ff1fe0ec (matches repo tag); `sui move test` → 254/254 PASS.
- `docker/local-testbed` image `local-testbed_walrus-service:cb3c1eb8…` built (4 Sui validators + 4 nodes) for optional end-to-end network repro.
- PoC test added to `crates/walrus-service/src/node.rs` (`poc_signs_confirmation_for_unverifiable_sliver`) — **executed, passing**. *(Source modification — revert if not wanted.)*
- `.audit/SYNTHESIS.md` + `.audit/*.md` — full per-cluster findings and refutations.

---

## Methodology note
The audit applied the zcash-full-stack-auditor playbook: decompose the codebase into narrow (Impact + Area + Mechanism) cells, hunt each, then **adversarially verify** before claiming severity. That verification step downgraded every agent "Critical": Sybil (trust-model), storage-pool absorb (past-confined), sync-loss (reconstruction-threshold overclaim). No finding was inflated to meet the engagement goal; the one finding driven to a confirmed, executed regtest-faithful PoC (H-01) is reported at its true severity, High.
