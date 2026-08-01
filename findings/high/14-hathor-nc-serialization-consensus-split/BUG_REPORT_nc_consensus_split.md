# Non-deterministic serialization of `set`/`frozenset`/`dict` nano-contract state makes honest nodes disagree on the state root, permanently splitting the chain

When a nano contract keeps a `set`, `frozenset`, or non-deterministically-built `dict` of strings or bytes in its state, that value gets serialized in whatever order Python happens to iterate it. Python randomizes that order per process (`PYTHONHASHSEED`), and the node never pins it. Since those serialized bytes are exactly what gets committed into the nano-contract state root (`nc_block_root_id`), two honest nodes that differ only by their hash seed end up with two different state roots for the same block. From there the network can't agree on anything: the roots diverge, the per-transaction RNG that's seeded from the root diverges, contract balances diverge, and nodes that re-execute after syncing a peer's root crash on an assert. No special access and no malicious intent is needed — an ordinary blueprint with a `frozenset` field does it.

---

## Brief/Intro

A nano contract that stores a `set`, `frozenset`, or `dict` of strings/bytes serializes it in Python's hash-random iteration order, and the node never pins `PYTHONHASHSEED`. Since those bytes form the state root `nc_block_root_id`, two honest nodes with different seeds — the default — commit different state for the same block. The first time any deployed blueprint uses such a field (a whitelist, a tag set, an address map), the network permanently splits, with divergent balances and crashing nodes, recoverable only by a hard fork. No special access or malicious intent is required.

---

## Vulnerability Details

### The bug: collections are serialized in iteration order

Nano-contract state is turned into bytes by per-type `NCType` adapters. The ones for unordered collections hand off to `encode_collection` / `encode_mapping`, and those just walk the Python object as-is:

```python
# hathorlib/hathorlib/serialization/compound_encoding/collection.py
def encode_collection(serializer, values, encoder):
    encode_leb128(serializer, len(values), signed=False)
    for value in values:          # iteration order, never sorted
        encoder(serializer, value)
```

`encode_mapping` does the same with `for key, value in values_mapping.items()`. These back `FrozenSetNCType` / `SetNCType` and `DictNCType`, which aren't obscure — they're registered, first-class field and argument types:

```python
# hathorlib/hathorlib/nanocontracts/nc_types/__init__.py
FIELD_TYPE_TO_NC_TYPE_MAP = {           # blueprint state (field) types
    ...
    frozenset: FrozenSetNCType,
    ...
}
ARG_TYPE_TO_NC_TYPE_MAP = {             # method argument types
    **FIELD_TYPE_TO_NC_TYPE_MAP,
    dict: DictNCType,
    set: SetNCType,
    ...
}
# (a `set` field is aliased to frozenset — still hash-ordered)
```

For a set or frozenset of strings/bytes, Python's iteration order depends on the per-process hash seed. That randomization is on by default (`sys.flags.hash_randomization == 1`), and the node ships without pinning it:

```dockerfile
# Dockerfile — no PYTHONHASHSEED anywhere
ENTRYPOINT ["python", "-m", "hathor"]
```

Grepping the whole tree for any `PYTHONHASHSEED` or hash-randomization control across `*.py`, `Makefile`, `Dockerfile*`, and the configs comes back empty.

### Why iteration order ends up in consensus

The serialized field bytes are stored as the content of a Patricia-trie node, and the node's id is a hash of that content:

```python
# hathorlib/hathorlib/nanocontracts/storage/patricia_trie.py
h = hashlib.sha256()
# h.update(key); h.update(content); h.update(sorted child ids)
```

Different content means a different node id, which means a different trie root. That root is `nc_block_root_id`, the commitment to all nano-contract state after a block:

```python
# hathor/nanocontracts/execution/consensus_block_executor.py
if meta.nc_block_root_id is not None:
    assert meta.nc_block_root_id == block_storage.get_root_id()
else:
    meta.nc_block_root_id = block_storage.get_root_id()
```

That root matters to consensus in three separate places, which is what turns "different bytes" into "split network":

1. The assert above. If a node already has a root for a block — say it pulled it from a peer during state sync, or it's re-executing after a reorg — and then computes a different one under its own hash seed, the assert fails and the node goes down with an uncaught `AssertionError`.
2. Peers exchange roots. Nodes advertise their per-block root and remember the peer's (`hathor/p2p/states/ready.py`, `peer_nc_block_root_id`, plus the `BEST_BLOCK` / `GET_NC_DB_NODE` sync messages). When the roots don't match, nano state sync between honest peers breaks.
3. The root seeds contract randomness. The running root is mixed into every later nano transaction's RNG seed in the same block:

```python
# hathor/nanocontracts/execution/block_executor.py
seed_hasher = hashlib.sha256(block.hash)
for tx in nc_sorted_calls:
    seed_hasher.update(tx.hash)
    seed_hasher.update(block_storage.get_root_id())   # divergent root -> divergent RNG seed
    rng_seed = seed_hasher.digest()
```

So once the root diverges, the `NanoRNG` handed to the rest of the block's transactions diverges with it. Nodes then disagree on contract randomness, on which transactions go through, and on the balances they leave behind. This isn't a cosmetic hash mismatch — it lands in spendable state.

### Why it's easy to hit, and why it slipped through

A few things make this a real footgun rather than a theoretical one:

- `set`, `frozenset`, and `dict` are normal, supported state types. They even have dedicated mutable wrappers (`fields/set_container.py`, `fields/dict_container.py`). A developer who writes `members: frozenset[str]` for a whitelist gets no warning that it'll split the network.
- The team clearly knows this hazard exists — they wrote `hathor_tests/nanocontracts/test_sorter_determinism.py`, which sweeps `PYTHONHASHSEED` to make sure the *execution sorter* is deterministic. They guarded the sorter and missed the state serializer right next to it.
- The official docs don't mention any determinism requirement for state, give no guidance on these types, and say nothing about hash randomization.

### Reachability and caveats (I checked the usual disqualifiers)

- **Deploying new blueprint code is gated on public networks.** `NC_ON_CHAIN_BLUEPRINT_RESTRICTED` defaults to `True`, and `mainnet.yml` / `testnet.yml` / `nano_testnet.yml` each pin `NC_ON_CHAIN_BLUEPRINT_ALLOWED_ADDRESSES` to two Hathor-Labs addresses. Only `localnet/privatenet` sets it to `false` (open to anyone). So an outside attacker can't currently deploy a triggering blueprint on a public chain.
- **That gate doesn't actually protect against this bug.** It's there for sandbox safety, not to restrict field types. An honest blueprint from an allowlisted author that uses a `frozenset` field splits the network — nobody has to do anything malicious. The allowlist is also a temporary launch measure (a public Blueprint Marketplace already exists, and the direction is permissionless deployment), and if any already-deployed blueprint takes a `set`/`dict` argument and stores it, any caller can trigger it.
- **It doesn't look already-known.** No comment near the encoders mentions the issue, there's a determinism test for the sorter but none for serialization, the encoder was only *moved* in refactor #1612 (not fixed), and Halborn's Nano Contracts audit (June 30 – Aug 1, 2025) — which explicitly covered serialization, consensus, and DoS — reported a different critical (mutable context sharing) while this encoder is still unsorted.

---

## Impact Details

Two honest full nodes that differ only by their per-process hash seed — which is the default — compute different `nc_block_root_id` for the same block as soon as any executed contract stores a set/frozenset/dict of strings or bytes. Because that value is *the* nano-contract state commitment, the honest network can no longer agree on canonical state. Concretely:

- The roots diverge, and because the root is folded into each later transaction's RNG seed, contract randomness, transaction success/failure, and balances diverge too. The split reaches spendable funds, not just an internal hash.
- Nodes crash. A node that adopts a peer's root via sync and then re-executes under its own seed trips `assert meta.nc_block_root_id == block_storage.get_root_id()` and dies. Nano state sync between differently-seeded peers is broken.
- There's no privilege or attack required. An honest blueprint with a `frozenset[str]` whitelist is enough. On `localnet/privatenet` anyone can do it today; on public chains it happens the moment any allowlisted/honest blueprint uses such a field, and becomes openly exploitable once deployment opens up.

The partition doesn't heal on its own. Each node deterministically computes a different root from its fixed seed, and the only paths to recovery — changing the serialization to be canonical, or getting the whole network to pin the same seed and reconcile the state already committed under mixed seeds — are coordinated, consensus-level changes. In other words, a hard fork.

**Selected in-scope impact (Critical): "Unintended permanent chain split requiring hard fork (network partition requiring hard fork)."** It's permanent (no reconvergence; sync between divergent nodes just crashes them) and the fix is a consensus-rule change that needs a coordinated hard fork. It also touches the Critical categories *"creation of tokens … without following consensus rules"* and *"direct loss of funds"* through the downstream balance divergence, and the re-execution crash would satisfy the Low *"shutdown of ≥30% of nodes"* category — but those undersell it. The headline is the permanent, hard-fork-requiring split.

---

## References

- The bug — collection/mapping encoders with no canonical sort:
  - `hathorlib/hathorlib/serialization/compound_encoding/collection.py` (`encode_collection`)
  - `hathorlib/hathorlib/serialization/compound_encoding/mapping.py` (`encode_mapping`)
- The types they back, and where they're registered:
  - `hathorlib/hathorlib/nanocontracts/nc_types/collection_nc_type.py` (`FrozenSetNCType`, `SetNCType`)
  - `hathorlib/hathorlib/nanocontracts/nc_types/map_nc_type.py` (`DictNCType`)
  - `hathorlib/hathorlib/nanocontracts/nc_types/__init__.py` (`FIELD_TYPE_TO_NC_TYPE_MAP`, `ARG_TYPE_TO_NC_TYPE_MAP`)
  - `hathorlib/hathorlib/nanocontracts/fields/set_container.py`, `fields/dict_container.py`
- How it reaches consensus, and the amplifier:
  - `hathorlib/hathorlib/nanocontracts/storage/patricia_trie.py` (node id = `sha256(content …)`)
  - `hathor/nanocontracts/execution/consensus_block_executor.py` (the `nc_block_root_id` assert)
  - `hathor/nanocontracts/execution/block_executor.py` (root mixed into each per-tx RNG seed)
  - `hathor/p2p/states/ready.py` (`peer_nc_block_root_id`, root exchange / state sync)
- The determinism guard they *did* write (the sibling they protected): `hathor_tests/nanocontracts/test_sorter_determinism.py`
- Deployment gating + the missing seed pin: `hathorlib/hathorlib/conf/{mainnet,testnet,nano_testnet,localnet}.yml`; `Dockerfile` (`ENTRYPOINT ["python","-m","hathor"]`)
- Docs / prior audit: [Hathor docs — Nano contracts: how it works](https://docs.hathor.network/explanations/features/nano-contracts/how-it-works/) · [Halborn — Hathor Nano Contracts audit](https://www.halborn.com/audits/hathor-labs-hathor-network/nano-contracts-c4e9b1) · [Blueprint Marketplace](https://blueprints.hathor.network/)

---

## Proof of Concept

Everything below runs locally against a full build of `hathor-core` (Python 3.12, in-memory storage). Nothing is broadcast to testnet or mainnet. The end-to-end test uses the node's real consensus, nano-execution, and verification code; the trie test strips away every other variable so you can see the hash seed is the only thing changing.

### Setup

```bash
# from the hathor-core repo root
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e .            # hathor + native rocksdb
uv pip install --python .venv/bin/python 'pytest>=8.3.2,<8.4.0' pytest-xdist flaky
```

### PoC 1 — same key, same value, only the hash seed changes → different state root

`audit_poc/poc_trie_isolation.py`:

```python
from hathorlib.nanocontracts.storage.memory_backends import InMemoryNodeTrieStore
from hathorlib.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathorlib.nanocontracts.nc_types.collection_nc_type import FrozenSetNCType
from hathorlib.nanocontracts.nc_types import StrNCType

value = frozenset({'alice', 'bob', 'carol', 'dave', 'erin',
                   'frank', 'grace', 'heidi', 'ivan', 'judy'})
content = FrozenSetNCType(StrNCType()).to_bytes(value)
trie = PatriciaTrie(InMemoryNodeTrieStore())
trie.update(b'fixed-contract-balance-key', content)   # fixed key, fixed value
print('ROOT=' + trie.root.id.hex())
```

Run each seed twice so you can see it's stable within a seed and different across seeds:

```bash
for run in 1 2; do for s in 0 1 2; do
  printf "run%s seed=%s " $run $s
  PYTHONHASHSEED=$s .venv/bin/python audit_poc/poc_trie_isolation.py
done; done
```

Output:

```
run1 seed=0 ROOT=9a22854b1396e4632fbdc168e9c488e483660780ba5e90f2f0aa10467f44843c
run1 seed=1 ROOT=168b9f4fe764b6b530e03052b548295773523c14a9f943b8f3e9287bccc0424a
run1 seed=2 ROOT=fe148c1a38aea2344782005c209d109e61e678711ebfcd9b57137bf7c6902626
run2 seed=0 ROOT=9a22854b…   (same as run1 — deterministic per seed)
run2 seed=1 ROOT=168b9f4f…   (same)
run2 seed=2 ROOT=fe148c1a…   (same)
```

Same key, same value, three different roots. The seed is the only thing that moved.

### PoC 2 — the fix, shown as a control: a sorted encoding is seed-invariant

`audit_poc/poc_sorted_control.py`:

```python
from hathorlib.nanocontracts.storage.memory_backends import InMemoryNodeTrieStore
from hathorlib.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathorlib.nanocontracts.nc_types import StrNCType, ListNCType

value = {'alice', 'bob', 'carol', 'dave', 'erin',
         'frank', 'grace', 'heidi', 'ivan', 'judy'}
content = ListNCType(StrNCType()).to_bytes(sorted(value))   # sorted = canonical
trie = PatriciaTrie(InMemoryNodeTrieStore())
trie.update(b'fixed-contract-balance-key', content)
print('ROOT=' + trie.root.id.hex())
```

```bash
for s in 0 1 2; do printf "seed=%s " $s; PYTHONHASHSEED=$s .venv/bin/python audit_poc/poc_sorted_control.py; done
```

Output — identical across all seeds, which confirms both the cause and the fix:

```
seed=0 ROOT=657860f75cccc4b28ad2fdd0dfc4a30ddba367670e869c477e1d2db154d41165
seed=1 ROOT=657860f7…   (same)
seed=2 ROOT=657860f7…   (same)
```

### PoC 3 — the full thing, end to end through real consensus

An ordinary blueprint with a `frozenset[str]` field, run through the actual pipeline (verification, nano execution, consensus) in three subprocesses at `PYTHONHASHSEED=0/1/2`. Each prints the `nc_block_root_id` it commits for the same block.

`hathor_tests/nanocontracts/test_zz_consensus_split_poc.py`:

```python
import os, subprocess, sys
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import BlueprintId, VertexId, public
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class WhitelistBlueprint(Blueprint):
    """An ordinary blueprint that keeps a set of member names."""
    members: frozenset[str]

    @public
    def initialize(self, ctx: Context) -> None:
        self.members = frozenset({
            'alice', 'bob', 'carol', 'dave', 'erin',
            'frank', 'grace', 'heidi', 'ivan', 'judy',
        })


class ConsensusSplitPoC(unittest.TestCase):
    def _compute_root(self) -> str:
        manager = self.create_peer('unittests')
        blueprint_id = BlueprintId(VertexId(b'\x01' * 32))
        manager.blueprint_service.register_blueprint(blueprint_id, WhitelistBlueprint)
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy
            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1 <-- b11
        ''')
        artifacts.propagate_with(manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        assert nc1.get_metadata().voided_by is None, 'nc1 was voided!'
        root = b11.get_metadata().nc_block_root_id
        assert root is not None
        return root.hex()

    def test_emit_root(self) -> None:
        print('ROOT=' + self._compute_root())

    def test_split(self) -> None:
        roots = {}
        for seed in ('0', '1', '2'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = subprocess.run(
                [sys.executable, '-m', 'pytest', os.path.abspath(__file__),
                 '-p', 'no:warnings', '-n0', '-q', '-s', '-k', 'test_emit_root'],
                env=env, capture_output=True, text=True, timeout=240,
            )
            line = next((ln for ln in out.stdout.splitlines() if ln.startswith('ROOT=')), None)
            assert line, f'no root for seed={seed}\n{out.stdout[-1500:]}\n{out.stderr[-1500:]}'
            roots[seed] = line[len('ROOT='):]
            print(f'PYTHONHASHSEED={seed} -> nc_block_root_id={roots[seed]}')
        distinct = set(roots.values())
        print(f'>>> {len(distinct)} distinct consensus roots across honest nodes: {roots}')
        assert len(distinct) > 1, 'roots agreed across seeds — not reproduced here'
```

Run it:

```bash
.venv/bin/python -m pytest \
  hathor_tests/nanocontracts/test_zz_consensus_split_poc.py::ConsensusSplitPoC::test_split \
  -p no:warnings -n0 -q -s
```

Output:

```
PYTHONHASHSEED=0 -> nc_block_root_id=7653e56fede988ed340d22bcda120a223a5bd31cca1f3054fca9c12be8c152d3
PYTHONHASHSEED=1 -> nc_block_root_id=57547a9e3d2f268da879b5b67616aca3b79e3ba4384b31b343346ca5eaf3bd9b
PYTHONHASHSEED=2 -> nc_block_root_id=d6b7bbca8fd4a9631fd422e1279dead70f9d508d74c70df72b50087f02a20e95
>>> 3 distinct consensus roots across honest nodes
1 passed
```

Three honest nodes, same block, three different consensus roots. One note: the absolute values shift run-to-run because the DAG build has its own timestamp/PoW noise that affects the trie key — that's why PoC 1 fixes the key and value, so you can see the hash seed is the sole cause without that noise in the way.

### Suggested fix

Serialize unordered collections in a canonical, seed-independent order — sort elements (and mapping keys) by their encoded bytes — inside `encode_collection` / `encode_mapping`, only for the unordered types (`FrozenSetNCType` / `SetNCType` / `DictNCType`). Leave the ordered containers (`list` / `tuple` / `OrderedDict`) alone. As a belt-and-suspenders measure, pin `PYTHONHASHSEED` in the entrypoint (or refuse to start under a random seed), and extend the existing `test_sorter_determinism.py` seed sweep to cover state-root determinism for every field and argument type.

```diff
  def encode_collection(serializer, values, encoder):
      encode_leb128(serializer, len(values), signed=False)
-     for value in values:
+     # Canonical order so serialization doesn't depend on PYTHONHASHSEED.
+     # Sort by each element's encoded bytes for a stable, type-agnostic order.
+     for value in _canonical_order(values, encoder):
          encoder(serializer, value)
```
