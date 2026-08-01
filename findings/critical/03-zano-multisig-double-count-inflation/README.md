# Critical: Missing intra-transaction uniqueness check on txin_multisig inputs -> multisig double-count coin inflation / escrow theft

**Target:** Zano (hyle-team/zano, legacy multisig consensus, master/release v2.1.19.476)  
**Severity:** Critical  
**Slug:** `zano-multisig-double-count-inflation`

## Impact

A party able to sign for one A-valued multisig/escrow output can list it K times in a single tx that passes full consensus, minting (K-1)*A from nothing and stealing escrow-locked funds.

## Proof of Concept

core_tests gen_multisig_same_tx_double_count replays events through real currency::core full consensus validation and asserts inflation on bob's real wallet2::balance() >= 2A - fee. git diff shows ZERO src/ changes; reproduced end-to-end against a full build of current master.

## Submission notes / caveats

Post-HF4 mainnet realization needs an existing pre-HF4 txout_multisig/escrow output whose signature threshold the attacker can assemble (attacker-controlled-source precondition, no trusted role); pre-HF4 / regtest / CryptoNote forks are permissionlessly exploitable. Note this precondition in the write-up.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `zano/validated_issues/ISSUE-1.md`
- [`ZANO_MULTISIG_DOUBLECOUNT_REPORT.md`](./ZANO_MULTISIG_DOUBLECOUNT_REPORT.md) — write-up, from `zano/ZANO_MULTISIG_DOUBLECOUNT_REPORT.md`
- [`SRC__multisig_same_tx_double_count.cpp`](./SRC__multisig_same_tx_double_count.cpp) — source, from `zano/tests/core_tests/multisig_same_tx_double_count.cpp`
