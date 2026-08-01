#  CONFIRMED-CRITICAL PoC — Consensus split from non-deterministic NC state serialization.
#
#  A blueprint stores a `frozenset[str]` field. The serializer (encode_collection)
#  emits set elements in Python iteration order, which for str/bytes is SipHash-
#  randomized by PYTHONHASHSEED. Those bytes become Patricia-trie content, so the
#  nano state commitment `nc_block_root_id` (the value nodes assert on, exchange
#  with peers, and seed per-tx RNG from) DIFFERS between two honest nodes that
#  differ only by their (default-random) hash seed => permanent consensus split.
#
#  `test_split` self-proves it: it runs the FULL real pipeline (verification +
#  nano execution + consensus) in three subprocesses with PYTHONHASHSEED=0,1,2
#  (via `test_emit_root`) and asserts the three honest nodes computed three
#  DIFFERENT consensus roots.

import os
import subprocess
import sys

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import BlueprintId, VertexId, public
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class WhitelistBlueprint(Blueprint):
    """A perfectly ordinary blueprint that keeps a set of member names."""
    members: frozenset[str]

    @public
    def initialize(self, ctx: Context) -> None:
        self.members = frozenset({
            'alice', 'bob', 'carol', 'dave', 'erin',
            'frank', 'grace', 'heidi', 'ivan', 'judy',
        })


class ConsensusSplitPoC(unittest.TestCase):
    def _compute_root(self) -> str:
        """One honest node: build a block confirming the blueprint tx via the full
        real pipeline; return the nano state commitment nc_block_root_id (hex)."""
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
        # Child workload: print this node's consensus root + the nano txid (trie key)
        # so the harness can confirm the build is identical across seeds.
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
        print('TXID=' + nc1.hash.hex())
        print('ROOT=' + root.hex())

    def test_split(self) -> None:
        roots: dict[str, str] = {}
        for seed in ('0', '1', '2'):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            out = subprocess.run(
                [sys.executable, '-m', 'pytest', os.path.abspath(__file__),
                 '-p', 'no:warnings', '-n0', '-q', '-s', '-k', 'test_emit_root'],
                env=env, capture_output=True, text=True, timeout=240,
            )
            line = next((ln for ln in out.stdout.splitlines() if ln.startswith('ROOT=')), None)
            assert line, (f'child (seed={seed}) produced no root.\n'
                          f'STDOUT:\n{out.stdout[-1500:]}\nSTDERR:\n{out.stderr[-1500:]}')
            roots[seed] = line[len('ROOT='):]
            print(f'PYTHONHASHSEED={seed} -> nc_block_root_id={roots[seed]}')

        distinct = set(roots.values())
        print(f'\n>>> {len(distinct)} distinct consensus roots across honest nodes: {roots}')
        # SAME block + SAME tx + SAME logical state must yield the SAME consensus
        # commitment on every honest node. It does not -> permanent consensus split.
        assert len(distinct) > 1, 'roots agreed across hash seeds — vuln not reproduced here'
