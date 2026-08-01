# ISSUE-1: Non-deterministic serialization of `frozenset`/`set`/`dict` nano-contract state causes honest nodes to compute different consensus state roots → permanent chain split

## Pipeline Result
**Verdict**: VALID (with mandatory scope correction)
**Final Severity**: High — rises to **Critical** on localnet/open networks and once permissionless blueprint deployment ships
**Original Claimed Severity**: Critical (primary), High (current-public-network fallback)
**Pipeline Exit Point**: Step 4 (full generic + adversarial + judge synthesis)
**Confidence**: HIGH (every load-bearing code claim independently verified + 3 mechanical reproductions)

## Summary
A nano-contract state field of type `frozenset[str]` / `frozenset[bytes]` (or any `str`/`bytes`-keyed unordered collection that lands in a single trie leaf) is serialized in Python hash-iteration order, which CPython randomizes per process via `PYTHONHASHSEED`. Those bytes become the raw `content` of a Patricia-trie leaf whose root is the consensus commitment `nc_block_root_id`. Two honest nodes with different hash seeds therefore compute different consensus state for the identical block → divergent state roots, divergent per-tx RNG, divergent balances, and `AssertionError` crashes on re-execution. The mechanism is real, reachable, unmitigated, not known to the team, and not by-design. **It was reproduced three independent ways in this environment.** The report's central claim and PoC are correct; however the report's *breadth* is overstated and must be scope-corrected (see below).

## Location
- `hathorlib/hathorlib/serialization/compound_encoding/collection.py:56-59` — `encode_collection` iterates `for value in values` with no sort
- `hathorlib/hathorlib/serialization/compound_encoding/mapping.py:64-73` — `encode_mapping` iterates `.items()` with no key sort
- `hathorlib/hathorlib/nanocontracts/nc_types/collection_nc_type.py:78-80` — `SetNCType`/`FrozenSetNCType._serialize` pass the raw collection to `encode_collection`
- `hathorlib/hathorlib/nanocontracts/nc_types/map_nc_type.py:77-79` — `DictNCType._serialize`
- `hathorlib/hathorlib/nanocontracts/nc_types/__init__.py:109,132-141` — `frozenset` registered as FIELD type; `dict`/`set`/`frozenset` as ARG types
- `hathorlib/hathorlib/nanocontracts/storage/patricia_trie.py:72-79` — node id = `sha256(key + content + sorted(child_ids))`; `content` hashed raw
- `hathor/nanocontracts/execution/consensus_block_executor.py:96` — `assert meta.nc_block_root_id == block_storage.get_root_id()`
- `hathor/nanocontracts/execution/block_executor.py:236-242` — block state root folded into every subsequent tx's RNG seed

## Justification

### Mechanism — fully verified in code
1. The two encoders iterate Python order with **no canonical sort** (confirmed by reading; grep for `sorted`/`.sort`/`canonical` in both encoder files and both NC types returned nothing).
2. `frozenset` is a first-class registered **field** type; `set`/`dict`/`frozenset` are registered **argument** types. The project's own canonical test blueprint declares a `frozenset` field (`hathorlib/.../blueprint_files/all_fields.py:48`).
3. The trie node id hashes `content` raw (`h.update(self.content)`); only *child ids* are sorted (`sorted_child_ids`). So per-element container storage is order-independent, but a single-blob serialized unordered collection is **not** canonicalized.
4. The root is the consensus commitment `nc_block_root_id`, enforced by a bare `assert` (no try/except, voiding, or retry) and folded into the per-transaction `NanoRNG` seed — so divergence reaches randomness, control flow, and spendable balances, not just an opaque hash.
5. No `PYTHONHASHSEED` pinning exists anywhere in production code (`Dockerfile` ENTRYPOINT has none; repo-wide grep finds it only in auditor PoC files and in `test_sorter_determinism.py`, which *varies* it to test the unrelated call-sorter).

### Mechanical reproductions (this environment, `.venv` Python 3.12)
- **PoC 1 (airtight isolation)** — fixed trie key, fixed `frozenset({...10 strings...})` value, vary ONLY `PYTHONHASHSEED`: seeds 0/1/2/3 → **4 distinct roots**, each bit-identical across two reruns of the same seed. `[POC-PASS]`
- **PoC 2 (sorted control = the fix)** — same value encoded via `sorted(...)`: **identical root across all seeds**. Confirms both root cause and remediation. `[POC-PASS]`
- **PoC 3 (full pipeline)** — `members: frozenset[str]` blueprint driven through real verification + nano execution + consensus in three honest-node subprocesses (`PYTHONHASHSEED=0/1/2`): **3 distinct `nc_block_root_id` for the identical block**, 1 passed in 19.4s. `[POC-PASS]` (absolute values differ from the report's because the DAG build adds PoW/timestamp noise to the trie *key* — disclosed by the reporter; the divergence result holds.)
- PoC 3 also empirically proves there is **no** effective load-time guard and **no** hidden canonicalization on the `frozenset` field path — had either existed, the three roots would have matched.

### Disqualifier gate — all cleared
- **Admin/permission gating**: The deployment gate (`hathor/verification/on_chain_blueprint_verifier.py:146-149`) checks only the *deployer's address* against an allowlist (`NC_ON_CHAIN_BLUEPRINT_RESTRICTED=True` default; `localnet.yml` sets it `false`). It does **not** restrict field types. An honest, allowlisted blueprint using a `frozenset[str]` whitelist splits the network — no malice. Therefore the trusted-actor downgrade does NOT apply (this is "code behaves unexpectedly on a legitimate call," explicitly not an admin-abuse downgrade).
- **Already-known / by-design**: NO. No comment/docstring/doc/changelog acknowledges the non-determinism. The set→frozenset alias "warning" is a `logger.debug` about mutability tracking, unrelated to ordering. The one determinism guard (`test_sorter_determinism.py`) covers only the call-execution sorter, leaving the state encoders untested. Tellingly, the team *did* canonicalize ordering at the trie-structure layer (sorted child-ids; docstring "the tree structure must be the same regardless of the order the items are added") but left the leaf-content encoder unsorted — a cross-layer inconsistency indicating an oversight, not a design choice.
- **Reachability / mitigation**: NO invalidator. Metaclass, syntax validation, and OCB restriction visitor all permit `frozenset` fields; storage commit path applies no canonicalization; root mismatch is enforced by bare asserts with no tolerance.

### Mandatory scope correction (report breadth is overstated)
The report claims plain `set`/`dict` *fields* are vulnerable and that "`set` field aliases to `frozenset`." This is **inaccurate for the field path**:
- Top-level `set`/`dict`/`list`/`deque`/`OrderedDict` **fields** route to per-element containers (`SetContainer`/`DictContainer`/…) via `TYPE_TO_CONTAINER_MAP` (`fields/__init__.py:37-43`), checked on the raw origin **before** any aliasing. Per-element entries get separate trie keys, and child-ids are sorted → **order-independent / SAFE**. The metaclass field path uses `ESSENTIAL_TYPE_ALIAS_MAP` (no set→frozenset alias).
- `frozenset` is **absent** from `TYPE_TO_CONTAINER_MAP`, so a `frozenset` field falls through to single-blob `ContainerLeaf` serialization → **VULNERABLE**.

**True vulnerable surface** (all confirmed `str`/`bytes` element/key types only — `int`/`bool` are seed-stable and confirmed NOT vulnerable):
1. Top-level `frozenset[str|bytes|<bytes-backed hathor type>]` **fields** (the PoC's path — squarely in scope).
2. `str`/`bytes` unordered collections nested inside leaf-serialized compound types (`tuple`, `NamedTuple`, `frozenset`).
3. `set`/`dict`/`frozenset` of `str`/`bytes` as **method arguments** (`ARG_TYPE_TO_NC_TYPE_MAP` uses whole-blob `SetNCType`/`DictNCType`/`FrozenSetNCType` with no container interception) — under-emphasized in the report but a real additional surface whose serialized bytes feed the call record / nano-header.

The report's element-type scoping ("of `str`/`bytes` elements") is correct and precise — `frozenset[int]` is NOT vulnerable (confirmed: identical iteration order across seeds).

### Severity calibration
- **Impact**: High (permanent consensus/state split, network halt — top in-scope category). Unambiguous, mechanically proven.
- **Likelihood, current public networks**: Medium — deployment is allowlist-gated to a small set of honest Hathor-Labs addresses, and a triggering blueprint must use a `str`/`bytes` `frozenset` field / nested collection / arg. No attacker privilege or malice required, but it is "specific conditions." → **High** (Impact High × Likelihood Medium).
- **Likelihood, localnet / open networks / future permissionless deployment (stated roadmap)**: High — any user can deploy a triggering blueprint. → **Critical** (Impact High × Likelihood High).

Final severity recorded as **High** (conservative, current-public-network state), explicitly noting the **Critical** ceiling on open/permissionless networks. This matches the reporter's own dual framing.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | Encoders sort / canonicalize collections | Step 3 (Generic: input/serialization correctness) | FAILS | No `sorted`/`.sort`/`canonical` in `collection.py`/`mapping.py`/`*_nc_type.py`; PoC 1 shows divergent bytes |
| 2 | Blueprint load-time guard rejects frozenset/set/dict fields | Step 4 (Adversarial reachability) | FAILS | Metaclass + syntax validation + OCB restriction visitor permit `frozenset`; `all_fields.py:48` declares one; PoC 3 ran one through full pipeline |
| 3 | Hidden canonicalization in storage commit path | Step 4 (Adversarial reachability) | FAILS | `patricia_trie.py:74-75` hashes `content` raw; only child-ids sorted; PoC 3 produced divergent roots |
| 4 | Root mismatch tolerated / handled gracefully | Step 4 (Adversarial reachability) | FAILS | Bare `assert` at consensus_block_executor.py:96 (and :322), no try/except/void/retry |
| 5 | Per-element container makes collection fields order-independent | Step 4 (Adversarial reachability) | HOLDS (PARTIAL — scope only) | TRUE for `set`/`dict`/`list`/`deque`/`OrderedDict` fields, but `frozenset` bypasses the container map → still vulnerable. Narrows breadth, does not invalidate. |
| 6 | Already known by team / intended by design | Step 4 (Adversarial known/by-design) | FAILS | No comment/doc/test acknowledges it; sorter determinism test scoped to call-sorter only; trie-structure layer canonicalized but leaf encoder not — cross-layer inconsistency = oversight |
| 7 | Attack requires trusted/privileged actor to act maliciously | Step 2 (Privileged roles) | FAILS | Deployment allowlist gates *who deploys code*, not field types; honest benign blueprint splits the network. No malice → no trusted-actor cap. |
| 8 | `PYTHONHASHSEED` pinned in node entrypoint | Step 3 (Generic) | FAILS | No pinning in Dockerfile/Makefile/configs/code; default randomization (`sys.flags.hash_randomization==1`) |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all referenced files/functions exist and match; mechanism internally consistent.
- **Step 2 (Privileged Roles)**: NO DOWNGRADE — deployment allowlist gates code authorship, not field types; trigger is benign honest code, so the trusted-actor-malice cap does not apply.
- **Step 3 (Generic Check)**: serialization-correctness / determinism / config-pinning reasons checked → all FAIL (no sort, no pinning).
- **Step 4 (Adversarial Check)**: 2 independent opus skeptics (reachability/mitigation; already-known/by-design) → no invalidator; one PARTIAL scope correction (set/dict fields safe, frozenset fields vulnerable). Judge synthesis: VALID.
- **Final Severity**: High (current public networks) / Critical (localnet, open, and future permissionless networks). Recorded as High with explicit Critical ceiling.

## Recommended Fix (as reported, confirmed correct by PoC 2)
Serialize unordered collections in a canonical, seed-independent order (sort elements / mapping keys by their encoded bytes) inside `encode_collection`/`encode_mapping`, restricted to the unordered NC types (`FrozenSetNCType`/`SetNCType`/`DictNCType`); leave ordered containers (`list`/`tuple`/`deque`/`OrderedDict`) unchanged. Defense-in-depth: pin `PYTHONHASHSEED` (or refuse to start under randomized hashing) in the entrypoint, and extend the cross-seed determinism test to every NC field/arg type. PoC 2 mechanically confirms the sorted encoding yields a seed-invariant root.
