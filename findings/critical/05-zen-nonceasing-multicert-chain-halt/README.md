# Critical: Missing per-block non-ceasing certificate-uniqueness check reaches assert(isBlockTopQualityCert) in ConnectBlock -> poison-block network-wide chain halt

**Target:** Horizen/zen (zend 6.0.0, HEAD e75197bdf / tag v6.0.0)  
**Severity:** Critical  
**Slug:** `zen-nonceasing-multicert-chain-halt`

## Impact

Any miner's single PoW block with two same-scId non-ceasing certs at consecutive epochs aborts every full node and re-crashes on restart (persistent poison-block chain halt).

## Proof of Concept

GoogleTest death test ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert drives real ConnectBlock through the real IsCertApplicableToState path against actual zend 6.0.0 source and aborts at src/main.cpp:3764 (ran GREEN). Static control-flow proof: the assert precedes scVerifier.BatchVerify, so no valid SNARK is needed.

## Submission notes / caveats

Non-ceasing SCs are attacker-creatable and mainnet-active since height 1,363,115; permissionless apart from mining one PoW block. Live bounty asset-list/severity rubric not present in repo (SECURITY.md is disclosure-only) — scope-confirmation gate before submission.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `zen/validated_issues/ISSUE-1.md`
- [`BUGREPORT_nonceasing_multicert_chainhalt.md`](./BUGREPORT_nonceasing_multicert_chainhalt.md) — write-up, from `zen/BUGREPORT_nonceasing_multicert_chainhalt.md`
- [`FINDING_nonceasing_multicert_assert.md`](./FINDING_nonceasing_multicert_assert.md) — write-up, from `zen/.hunt/FINDING_nonceasing_multicert_assert.md`
- [`POC__test_sidechain_blocks.cpp`](./POC__test_sidechain_blocks.cpp) — PoC, from `zen/src/gtest/test_sidechain_blocks.cpp`
