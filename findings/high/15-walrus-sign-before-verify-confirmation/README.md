# High: Storage node signs availability confirmations without verifying sliver content (sign-before-verify, WAL-523 class)

**Target:** MystenLabs/walrus (Walrus decentralized storage; Rust storage node)  
**Severity:** High  
**Slug:** `walrus-sign-before-verify-confirmation`

## Impact

A storage node signs a truthful-looking availability attestation for bytes that are not the blob's sliver and never self-heals the corruption (dishonest attestation + suppressed recovery).

## Proof of Concept

poc_signs_confirmation_for_unverifiable_sliver stores+registers a blob on an in-process node, overwrites a shard's primary sliver with a Merkle-invalid sliver via the unverified put_sliver path, then asserts the node still returns Ok/Signed from compute_storage_confirmation while the stored sliver fails Sliver::verify. Executed against a real walrus-service build.

## Submission notes / caveats

Calibrated High, not on-demand Critical — within the <=f Byzantine, single-epoch model it does not by itself lose a certified blob (reconstruction needs corrupting >2f shards). Partly overlaps the acknowledged in-code `//TODO(WAL-523)` on the writer side; the novel consequence is the sign-before-verify confirmation path. Not run through the adversarial pipeline (single top-level report).

## Files in this folder

- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `walrus/AUDIT_REPORT.md`
- [`SRC__node.rs`](./SRC__node.rs) — source, from `walrus/crates/walrus-service/src/node.rs`
