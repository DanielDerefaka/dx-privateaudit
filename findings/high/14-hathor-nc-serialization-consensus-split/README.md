# High: Non-deterministic serialization of frozenset/set/dict nano-contract state causes honest nodes to compute different consensus state roots -> permanent chain split

**Target:** hathor-core (Hathor Network full node — nano contracts / consensus)  
**Severity:** High  
**Slug:** `hathor-nc-serialization-consensus-split`

## Impact

Two honest full nodes differing only by their default-random hash seed compute different nc_block_root_id for the same block once any contract stores a frozenset/dict-of-str/bytes -> permanent consensus/state split, recoverable only by hard fork.

## Proof of Concept

test_zz_consensus_split_poc.py drives a WhitelistBlueprint(frozenset[str]) through the real verification+nano-execution+consensus pipeline in 3 subprocesses (PYTHONHASHSEED=0/1/2) and emits 3 distinct nc_block_root_id for the identical block. Plus a trie-isolation PoC and a sorted-control PoC proving the fix. Reproduced 3 independent ways against real deps.

## Submission notes / caveats

Nano contracts are a live mainnet feature. Triggering-blueprint deployment is currently allowlist-gated to ~2 Hathor-Labs addresses on public chains (NC_ON_CHAIN_BLUEPRINT_RESTRICTED=True), but open to anyone on localnet/privatenet and on the roadmapped permissionless Blueprint Marketplace (Critical ceiling). State the allowlist reachability caveat; not admin-gated by field type.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `hathor-core/validated_issues/ISSUE-1.md`
- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `hathor-core/AUDIT_REPORT.md`
- [`BUG_REPORT_nc_consensus_split.md`](./BUG_REPORT_nc_consensus_split.md) — write-up, from `hathor-core/BUG_REPORT_nc_consensus_split.md`
- [`POC__test_zz_consensus_split_poc.py`](./POC__test_zz_consensus_split_poc.py) — PoC, from `hathor-core/hathor_tests/nanocontracts/test_zz_consensus_split_poc.py`
