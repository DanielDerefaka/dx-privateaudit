# Critical: GRANDPA justification verification does not bind the finalized block to the votes, allowing warp-sync chain forgery

**Target:** paritytech/smoldot (light client, Rust)  
**Severity:** Critical  
**Slug:** `smoldot-grandpa-warpsync-forgery`

## Impact

One malicious peer makes a warp-syncing light client finalize an attacker-fabricated block and read ALL chain state from an attacker-chosen state root — total collapse of the light-client guarantee.

## Proof of Concept

Two passing #[cfg(test)] tests: grandpa_justification_target_is_unbound_from_votes and warp_sync_adopts_forged_block_with_attacker_state_root drive the REAL warp-sync state machine to adopt a fragment header's attacker-chosen state_root. In-code `// TODO: must check signed block ancestry using votes_ancestries` confirmed on disk at verify.rs:459.

## Submission notes / caveats

Warp sync is the DEFAULT path; any single malicious peer/MITM exploits it. The gap is marked by an in-code `// TODO` — confirm it still reproduces against latest upstream and disclose privately to Parity (responsible disclosure). Not run through the full adversarial pipeline (single top-level report).

## Files in this folder

- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `smoldot/AUDIT_REPORT.md`
- [`SRC__verify.rs`](./SRC__verify.rs) — source, from `smoldot/lib/src/finality/verify.rs`
