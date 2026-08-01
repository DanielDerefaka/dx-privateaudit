# Critical: Unvalidated `position` type in nested document-schema properties panics try_from_schema -> deterministic network-wide chain halt

**Target:** dashpay/platform (Dash Platform / Evolution, Rust drive-abci, v4.0.0-rc.1)  
**Severity:** Critical  
**Slug:** `dash-platform-position-type-chain-halt`

## Impact

A single self-signed DataContractCreate with a nested `position: 0.0` deterministically crashes every validator executing the block (network-wide chain halt); any funded identity can also crash nodes via check_tx.

## Proof of Concept

position_type_confusion_experiment shows float 0.0 accepted at full_validation=true then PANIC at try_from_schema/mod.rs:215; end-to-end PoC 2 round-trips a re-signed contract through process_raw_state_transitions to panic; multi-MN PoC 3. Confirmed against a pristine upstream v4.0.0-rc.1 checkout, version-independent across v0/v1/v2 parsers.

## Submission notes / caveats

Merged from ISSUE-1 + ISSUE-2 (same underlying defect, ISSUE-2 is an independent re-verification). Finding is co-located in the dash Core folder but verified against the sibling dashpay/platform checkout. Dash runs Bugcrowd; the exact brief/asset-list/DoS-exclusion is unverifiable unauthenticated (404) — confirm eligibility/tier before submission.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `dash/validated_issues/ISSUE-1.md`
- [`ISSUE-2.md`](./ISSUE-2.md) — write-up, from `dash/validated_issues/ISSUE-2.md`
- [`dash-platform-chain-halt-document-position.md`](./dash-platform-chain-halt-document-position.md) — write-up, from `dash/dash-platform-chain-halt-document-position.md`
- [`SECURITY_FINDING_chain_halt.md`](./SECURITY_FINDING_chain_halt.md) — write-up, from `platform/SECURITY_FINDING_chain_halt.md`
- [`SRC__mod.rs`](./SRC__mod.rs) — source, from `platform/packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/v1/mod.rs`
