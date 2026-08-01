# Security Audit Report — Hathor Core (nano contracts)

**Date**: 2026-06-20
**Auditor**: Plamen Automated Security Analysis (whitehat)
**Scope**: `hathor-core` full node — focus on value integrity, token authority, consensus determinism, nano-contract execution, the on-chain-blueprint sandbox, and serialization. Vendored `hathorlib/` in scope.
**Commit**: `c22e97b5` (branch `master`)
**Language/Version**: Python `>=3.11,<3.14` (built & tested on CPython 3.12.13)
**Build Status**: Compiled successfully (uv venv + editable install incl. native `rocksdb`); harness validated (41/41 nano action tests pass).
**Verification ground-truth**: The project's in-process `HathorManager` + `DAGBuilder` pipeline, which executes the **identical verification + nano-execution + consensus code path** a live node uses. This is the regtest-equivalent proving ground used for all PoCs below; the consensus-split PoC was additionally isolated at the Patricia-trie commitment level.

---

## Executive Summary

Hathor Core is an exceptionally well-hardened codebase. The classic value-loss surfaces — value conservation, token mint/melt authority, deposit-collateral math, cross-contract reentrancy, the nano↔UTXO action bridge, signature/sighash binding, and the on-chain-blueprint Python sandbox — were each examined in depth (often empirically) and found to be **robust**, with consistent defense-in-depth (dataclass validation + asserts + a `MeteredExecutor` `BaseException→NCFail` catch + multi-layer verification).

One **Critical** issue was found and **mechanically confirmed**: nano-contract state that contains a `set`/`frozenset`/`dict` of hash-randomized elements (e.g. `str`/`bytes`) is serialized in **Python hash-iteration order**, which is randomized per process by `PYTHONHASHSEED`. Because that serialization feeds the Patricia trie whose root **is** the authoritative nano-contract state commitment `nc_block_root_id`, two honest nodes that differ only by their (default-random) hash seed compute **different consensus state for the same block** — a permanent chain/state split. No attacker privilege is required: any deployed blueprint using these ordinary type shapes triggers it. The team already guards the *sorter* against this exact hazard (shipping `test_sorter_determinism.py`, which varies `PYTHONHASHSEED`), but the **state-serialization encoders were missed**.

The most critical risk is therefore a network-wide consensus split (loss of liveness and state agreement) once any blueprint stores set/frozenset/dict-of-`str`/`bytes` state. Nano contracts are a mainnet feature (`ENABLE_NANO_CONTRACTS=FEATURE_ACTIVATION`).

**Reachability caveat (see C-01 → Caveats & Reachability):** on-chain-blueprint *deployment* is currently allowlist-gated to ~2 Hathor-Labs addresses on all public networks (open only on `localnet/privatenet`), so an arbitrary external attacker cannot deploy a triggering blueprint on a public chain *today*. This gate is a temporary launch measure and does **not** mitigate the underlying defect: `set`/`frozenset`/`dict` are first-class supported field types, so an *honest* blueprint by an allowlisted author (or any blueprint once deployment opens up) splits the network with no malice required. The finding is Critical as a latent consensus defect and on open/future-permissionless networks, and High for the immediate arbitrary-attacker lens on current public chains.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 0 |
| Medium | 0 |
| Low | 2 |
| Informational | 1 |

### Components Audited

| Component | Path | Focus |
|----------|------|-------|
| Value conservation | `hathor/verification/transaction_verifier.py`, `hathor/transaction/transaction.py` | sum(in)==sum(out), HTR collateral — robust |
| Token authority | `hathorlib/.../balance_rules.py`, `hathor/transaction/base_transaction.py` | mint/melt forgery — robust |
| Nano execution | `hathorlib/.../runner/runner.py`, `hathor/nanocontracts/execution/*` | conservation asserts, reentrancy, settlement — robust |
| **NC state serialization** | `hathorlib/.../serialization/compound_encoding/*`, `.../nc_types/*` | **Critical (C-01)** |
| NC consensus/determinism | `hathor/nanocontracts/sorter/*`, `.../execution/consensus_block_executor.py` | sorter robust; state root **C-01** |
| OCB sandbox | `hathor/verification/on_chain_blueprint_verifier.py`, `hathorlib/.../custom_builtins.py` | 3-layer sandbox — robust |
| Signature/sighash | `hathor/transaction/vertex_parser/_transaction.py`, `.../scripts/opcode.py` | SIGHASH_ALL binding — robust |

---

## Critical Findings

### [C-01] Non-deterministic serialization of `set`/`frozenset`/`dict` NC state diverges the consensus state root across honest nodes (permanent chain split) [VERIFIED]

**Severity**: Critical as a latent consensus-correctness defect / on open or future-permissionless networks; **High** for the immediate arbitrary-external-attacker lens against the *current* public networks (blueprint deployment is allowlist-gated there today — see **Caveats & Reachability**).
- Impact: High — permanent loss of consensus/state agreement (chain split) and divergent balances across the honest network.
- Likelihood: High that it triggers *accidentally* on honest use of a supported field type; gated for *arbitrary-attacker* deployment on public chains today (temporary launch allowlist).
**Location**:
- Root cause: `hathorlib/hathorlib/serialization/compound_encoding/collection.py:56-59` (`encode_collection`) and `hathorlib/hathorlib/serialization/compound_encoding/mapping.py` (`encode_mapping`)
- Backed types: `hathorlib/.../nc_types/collection_nc_type.py` (`FrozenSetNCType`/`SetNCType`), `.../nc_types/map_nc_type.py` (`DictNCType`); registered as NC field/arg blobs in `hathorlib/.../nc_types/__init__.py`
- Commitment path: `hathorlib/.../storage/patricia_trie.py:57-79` → `hathor/nanocontracts/execution/consensus_block_executor.py:96-98` (`nc_block_root_id`)
- Amplifier: `hathor/nanocontracts/execution/block_executor.py:236-244` (state root mixed into each NC tx's RNG seed)

**Description**:

`encode_collection` serializes a collection by iterating it directly, with **no canonical ordering**:

```python
# hathorlib/.../serialization/compound_encoding/collection.py
def encode_collection(serializer, values, encoder):
    encode_leb128(serializer, len(values), signed=False)
    for value in values:            # <-- Python iteration order; NOT sorted
        encoder(serializer, value)
```

`encode_mapping` is analogous (`for key, value in values_mapping.items()`). These functions back the nano-contract field/argument types `FrozenSetNCType`, `SetNCType`, and `DictNCType`. For a `set`/`frozenset` (and any `dict` built from one) whose elements are `str`/`bytes`, Python's iteration order is **SipHash-randomized per process** by `PYTHONHASHSEED`. Python randomizes this seed by default, and the node **never pins it** (no `PYTHONHASHSEED` in any `*.py`, `Makefile`, `Dockerfile`, or config; the Dockerfile entrypoint is `python -m hathor` with no seed). `sys.flags.hash_randomization` is `1` by default.

The serialized field bytes become the **content** of a Patricia-trie node, whose id is `sha256(key ‖ content ‖ sorted(child_ids))`. The trie root is stored as `nc_block_root_id` — the authoritative commitment to all nano-contract state after a block. This value is consensus-critical: `consensus_block_executor.py:96` asserts `meta.nc_block_root_id == block_storage.get_root_id()` on (re)execution, peers exchange it (`p2p/states/ready.py:333-364`, `peer_nc_block_root_id`), and verification of subsequent transactions loads contract state by it (`verification_service.py:384-386`).

It also self-amplifies: `block_executor.py:236-244` folds the evolving state root into each subsequent NC transaction's RNG seed:

```python
seed_hasher = hashlib.sha256(block.hash)
for tx in nc_sorted_calls:
    seed_hasher.update(tx.hash)
    seed_hasher.update(block_storage.get_root_id())   # divergent root -> divergent RNG seed
    rng_seed = seed_hasher.digest()
```

So once the root diverges, the per-transaction `NanoRNG` diverges, and nodes disagree on subsequent contract randomness, tx success/failure, and resulting **balances** — i.e. the split propagates into spendability, not merely an opaque hash.

The team is aware of this hazard class for the *sorter* — `hathor_tests/nanocontracts/test_sorter_determinism.py` deliberately varies `PYTHONHASHSEED` across many values to assert the sorter is deterministic — but the equivalent guard was **not** applied to the state-serialization encoders.

**Impact**:

- Two honest full nodes that differ only by their per-process hash seed compute **different `nc_block_root_id` for the identical block** whenever any executed contract stores a `set`/`frozenset`/`dict` of `str`/`bytes` (a very common shape: whitelists, member sets, address→amount maps, tag sets).
- This is the nano-contract state commitment nodes must agree on → **permanent consensus/state split** across the honest network, with downstream divergence of balances via the RNG-seed amplifier.
- A node that adopts a peer's root (state sync) and later re-executes under its own seed hits the `assert nc_block_root_id == get_root_id()` mismatch → **uncaught `AssertionError` → node crash**.
- No attacker privilege or special permission is required — an ordinary (even well-intentioned) blueprint deployment triggers it. An attacker can trivially deploy such a blueprint to force the split deliberately.

**PoC Result** (all run on the built node / regtest-equivalent pipeline):

1. **Airtight isolation** (`audit_poc/poc_trie_isolation.py`) — FIXED trie key + FIXED `frozenset[str]` value, varying **only** `PYTHONHASHSEED`, run twice each:
   ```
   run1 seed=0  trie_root=9a22854b1396e4632fbdc168e9c488e483660780ba5e90f2f0aa10467f44843c
   run1 seed=1  trie_root=168b9f4fe764b6b530e03052b548295773523c14a9f943b8f3e9287bccc0424a
   run1 seed=2  trie_root=fe148c1a38aea2344782005c209d109e61e678711ebfcd9b57137bf7c6902626
   run2 seed=0  trie_root=9a22854b…  (identical to run1 — deterministic per seed)
   run2 seed=1  trie_root=168b9f4f…  (identical)
   run2 seed=2  trie_root=fe148c1a…  (identical)
   ```
   Same seed → same root; different seed → different root. The only variable is the hash seed.

2. **Fix proven** (`audit_poc/poc_sorted_control.py`) — same value encoded via a **sorted** list:
   ```
   sorted-control seed=0  trie_root=657860f75cccc4b28ad2fdd0dfc4a30ddba367670e869c477e1d2db154d41165
   sorted-control seed=1  trie_root=657860f7…  (identical across all seeds)
   sorted-control seed=2  trie_root=657860f7…  (identical)
   ```
   A canonical ordering eliminates the divergence.

3. **End-to-end** (`hathor_tests/nanocontracts/test_zz_consensus_split_poc.py`, also `audit_poc/poc_consensus_split_e2e.py`) — a `WhitelistBlueprint` storing `frozenset[str]` driven through the full real pipeline in three honest-node subprocesses (`PYTHONHASHSEED=0/1/2`) yields three distinct `nc_block_root_id` for the identical block, with the nano tx not voided:
   ```
   PYTHONHASHSEED=0 -> nc_block_root_id=7653e56f…
   PYTHONHASHSEED=1 -> nc_block_root_id=57547a9e…
   PYTHONHASHSEED=2 -> nc_block_root_id=d6b7bbca…
   >>> 3 distinct consensus roots across honest nodes
   1 passed
   ```
   Run: `.venv/bin/python -m pytest hathor_tests/nanocontracts/test_zz_consensus_split_poc.py::ConsensusSplitPoC::test_split -p no:warnings -n0 -q -s`

**Caveats & Reachability** (disqualifier analysis — verified):

- **Permission gating (partial).** Deploying *new* blueprint code (OCB) is allowlist-gated on every public network: `NC_ON_CHAIN_BLUEPRINT_RESTRICTED` defaults to `True`, and `mainnet.yml` / `testnet.yml` / `nano_testnet.yml` each pin `NC_ON_CHAIN_BLUEPRINT_ALLOWED_ADDRESSES` to **two Hathor-Labs addresses** (mainnet: `HDkKGHwD…`, `HUbxYhtq…`). `localnet/privatenet` sets `NC_ON_CHAIN_BLUEPRINT_RESTRICTED: false` (**open to anyone**). So an *arbitrary external attacker* cannot deploy a triggering blueprint on a public chain **today**.
- **But the gate does not actually mitigate this bug.** The allowlist exists for code-execution *sandbox* safety, not to constrain field types. `set`/`frozenset`/`dict` are **first-class, supported state types** (dedicated `fields/set_container.py`, `fields/dict_container.py`; registered in `FIELD_TYPE_TO_NC_TYPE_MAP`/`ARG_TYPE_TO_NC_TYPE_MAP`). An allowlisted author writing an entirely *honest* blueprint with a `frozenset[str]` whitelist (a natural, idiomatic pattern, with no warning) **splits the network**. No malice is required, so the "fully-trusted actor acting maliciously → −1 tier" downgrade does **not** apply.
- **Triggerable by any user where a suitable blueprint exists.** If any deployed (allowlisted) blueprint stores a `set`/`dict` method argument, any caller controls the contents → split. And the gate is a **temporary launch measure** — the roadmap is permissionless blueprints (a public "Blueprint Marketplace" already exists), at which point any user can deploy a triggering blueprint and the finding is unambiguously Critical.
- **Not admin-required to *exploit*, only to *introduce* code on public chains today; fully open on localnet.**
- **In scope.** The defect is in core, consensus-critical serialization (`hathorlib` encoders) feeding the nano state commitment — not test/example code.
- **Not already known by the team (high confidence).** No comment acknowledges it anywhere near the encoders (all nearby `XXX` notes are mypy quirks); there is a determinism test for the *sorter* (`test_sorter_determinism.py`, which varies `PYTHONHASHSEED`) but **none for state serialization**; the encoder was only *moved* in refactor #1612 (no determinism fix); the Halborn Nano Contracts audit (2025-06-30 → 2025-08-01), whose scope explicitly included *serialization, consensus, and DoS vectors*, reported a different critical (mutable context sharing) and **did not** flag this — and the unsorted encoder is still present. No Hathor documentation states a serialization-determinism guarantee or warns against `set`/`frozenset` fields.

**Recommendation**:

Make NC-state serialization of unordered collections **canonical and deterministic**. Minimal fix in `encode_collection` / `encode_mapping`: serialize elements/keys in a fixed total order independent of process hash seed.

```diff
  def encode_collection(serializer, values, encoder):
      encode_leb128(serializer, len(values), signed=False)
-     for value in values:
+     # Canonicalize unordered collections (set/frozenset) so serialization is
+     # independent of PYTHONHASHSEED. Sort by the element's serialized bytes to
+     # get a stable, type-agnostic total order.
+     for value in _canonical_order(values, encoder):
          encoder(serializer, value)
```

Implement `_canonical_order` by encoding each element to bytes and sorting by those bytes (works for any element type, including nested/heterogeneous), or sort by element directly when elements are orderable. Apply the same to `encode_mapping` (sort by encoded key). Restrict this to the unordered NC types (`FrozenSetNCType`/`SetNCType`/`DictNCType`); ordered containers (`list`/`tuple`/`OrderedDict`) already serialize deterministically and must be left unchanged.

**Defense-in-depth** (recommended in addition, not instead): the node should pin determinism at startup (`PYTHONHASHSEED=0` in the entrypoint, or refuse to start under a randomized seed), and extend the existing `test_sorter_determinism.py` approach to assert serialization/state-root determinism across seeds for all NC field/arg types.

**Verified**: YES — isolation, fix-control, and end-to-end PoCs all reproduce on the built node; sorted control demonstrates the fix removes divergence.

---

## Low Findings

### [L-01] `syscall_melt_tokens` trips `assert fee_amount > 0` when melting a sub-threshold deposit-token amount

**Severity**: Low
**Location**: `hathorlib/hathorlib/nanocontracts/runner/runner.py:~1106`

**Description**: For a DEPOSIT token, `calculate_melt_fee` returns `floor(amount × TOKEN_DEPOSIT_PERCENTAGE)`; for amounts below `DENOM/NUM` (e.g. melting `<100` tokens at the 1% rate) this rounds to `0`, tripping `assert fee_amount > 0`. The assertion is reached inside the blueprint method body, so `MeteredExecutor.call`'s `except BaseException: raise NCFail` converts it to `NCFail` and the transaction is cleanly voided — **not** a consensus halt. The effect is that melting a small amount fails with an opaque internal error instead of a clear, intended `NCFail` (or being allowed). Confirmed empirically: `melt(100)` succeeds, `melt(50)` raises (caught → `NCFail`).

**Recommendation**: Replace the `assert` with an explicit `NCFail`/`NCInvalidSyscall` (e.g. "melt amount too small to redeem deposit") or define the intended behavior for sub-threshold melts. Audit all `assert` statements on attacker-influenced values in the execution path; prefer typed exceptions to asserts for input validation.

### [L-02] Non-canonical LEB128 accepted in nano header fields (wire malleability)

**Severity**: Low
**Location**: `hathorlib/hathorlib/serialization/encoding/leb128.py` (`decode_leb128`), used by `hathor/transaction/vertex_parser/_nano_header.py`

**Description**: `decode_leb128` does not enforce minimal-length encoding, so e.g. `nc_seqnum=5` accepts both `0x05` and the non-canonical `0x85 0x00`. This is wire-format malleability only — the txid is recomputed over the re-serialized (canonical) form, so it is **not** txid-malleable and does not affect consensus identity. (Identified by the breadth pass; not independently weaponized.)

**Recommendation**: Enforce minimal LEB128 length on decode (reject overlong encodings) for defense-in-depth against relay-layer malleability and parser ambiguity.

---

## Informational Findings

### [I-01] OCB sandbox relies on a deny-list of builtins replaced by raising stubs — verified safe, but worth a periodic audit

The on-chain-blueprint sandbox exposes a full `__builtins__` namespace but replaces all dangerous names (`eval`, `exec`, `open`, `getattr`, `type`, `compile`, `globals`, `setattr`, …) with **raising stubs** (`_generate_disabled_builtin_func`), in addition to a text-level `'__' in code` ban and an AST `_RestrictionsVisitor` blacklist. This three-layer design was verified robust (the disabled entries are stubs, not the real functions). Because deny-list sandboxes are inherently fragile to new Python features/bypasses, recommend a recurring review on each supported-Python upgrade, and consider an allow-list construction of the exec builtins dict to make additions fail-closed.

---

## Priority Remediation Order

1. **C-01** — Canonicalize `set`/`frozenset`/`dict` NC-state serialization (consensus split). **Immediate** — blocks safe nano-contract operation on any network where such state is used. Add the startup `PYTHONHASHSEED` pin and a cross-seed state-root determinism test as a backstop.
2. **L-01** — Replace the sub-threshold melt `assert` with a typed error; sweep execution-path asserts on attacker-influenced values.
3. **L-02** — Enforce minimal LEB128 on decode.

---

## Appendix A: Coverage Ledger (surfaces audited and found robust)

| Surface | Result | Key guard |
|---------|--------|-----------|
| HTR/token value conservation (`verify_transparent_balance`) | Robust | strict `==` check; deferred nano-token check re-run post-execution (`block_executor.py:381`) |
| Deposit/withdraw collateral rounding | Robust | mint `ceil`, melt `floor` — strictly protocol-favorable |
| Nano vs UTXO mint/melt symmetry | Robust | both use the same `get_deposit_token_*_amount` |
| Token mint/melt authority forgery | Robust | output authority requires matching input; ACQUIRE re-anchored by callee rule (`runner.py:674-678`) |
| HTR authority actions | Robust | `NCGrantAuthorityAction.__post_init__` rejects HTR (`types.py:484`) |
| Withdrawal underflow | Robust | `validate_balances_are_positive` + storage `assert >= 0` |
| Cross-contract reentrancy / nested settlement | Robust (empirically) | `_validate_reentrancy`, per-tracker validation, conservation asserts |
| Consensus reward-lock / transitive confirmation | Robust (empirically) | `min_height` inheritance through verification parents |
| Runner conservation → halt | Robust | `MeteredExecutor` `BaseException→NCFail`; conservation asserts are internal-consistency, not attacker-violable |
| Nano-arg deserialization → halt | Robust | `_deserialize_map_exception` catch-all → `NCFail` |
| Nano sorter determinism | Robust | `SortedSet` candidates + seeded `NanoRNG` + `test_sorter_determinism.py` |
| Signature/sighash binding | Robust | SIGHASH_ALL over all inputs/outputs/headers |
| OCB Python sandbox | Robust | text `'__'` ban + AST blacklist + raising-stub builtins (see I-01) |

## Appendix B: Reproduction

```bash
# build (one-time): uv venv --python 3.12 .venv ; install hathor (editable) + rocksdb + pytest
# C-01 — airtight isolation (no reactor needed):
for s in 0 1 2; do PYTHONHASHSEED=$s .venv/bin/python audit_poc/poc_trie_isolation.py; done   # 3 different roots
for s in 0 1 2; do PYTHONHASHSEED=$s .venv/bin/python audit_poc/poc_sorted_control.py; done    # identical (fix)
# C-01 — end-to-end through the full consensus pipeline:
.venv/bin/python -m pytest hathor_tests/nanocontracts/test_zz_consensus_split_poc.py::ConsensusSplitPoC::test_split -p no:warnings -n0 -q -s
```
