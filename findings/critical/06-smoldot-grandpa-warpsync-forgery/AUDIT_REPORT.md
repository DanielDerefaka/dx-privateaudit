# Security Audit Report — smoldot

**Date**: 2026-06-17
**Auditor**: Plamen Automated Security Analysis (whitehat)
**Target**: `paritytech/smoldot` light client — Rust
**Commit**: `386a1f9a4b23c9a56b83c640828756b765ee2d4c` (`smoldot` lib v1.2.0)
**Scope**: Full repository, focused on the consensus/finality verification trust boundary
**Build Status**: Compiled successfully (`rustc 1.95.0`, edition 2024)
**Verification**: `[POC-PASS]` — two passing tests; full crate build; end-to-end through the real warp-sync state machine

---

## Executive Summary

smoldot is a light client: its entire security rests on cryptographically verifying data served by **untrusted** full-node peers. This audit found a **critical soundness vulnerability** in GRANDPA **justification** verification, which is the trust-bootstrap path used by **warp sync** (smoldot's default fast-sync mechanism).

The justification verifier (`finality::verify::verify_justification`) checks that ≥2/3 of the authority set produced valid signatures, but **never binds those votes to the block the justification claims to finalize** — the ancestry/GHOST check is absent (`votes_ancestries` is decoded and discarded; see the `// TODO` at `verify.rs:459`). As a result, an attacker can take **genuine, publicly-available precommits** that the authorities honestly cast for the canonical block `Y`, and wrap them inside a justification that **claims to finalize an arbitrary forged block `B′`**. Verification succeeds.

Through warp sync, this lets **a single malicious peer** make a light client adopt an **attacker-fabricated finalized block with an attacker-chosen state trie root**, starting only from a trusted genesis and the real authority set. The client then reads **all** chain state (runtime code, account balances, transaction inclusion, …) from the attacker's forged state root. This is a total collapse of the light client's security guarantee.

Crucially, this is **not** the "long range attack" the warp-sync module documents as an accepted risk: that attack requires ≥2/3 of validators to **collude and equivocate**. This vulnerability requires **no validator misbehavior at all** — only the replay of honest votes under a forged target.

The issue was confirmed with a full crate build and two passing PoC tests, the second of which drives the **real warp-sync state machine** (the exact code path the production light client uses against the network) to a forged finalized head.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 0 |

### Components Audited

| Component | Path | Role |
|----------|------|------|
| GRANDPA finality verification | `lib/src/finality/verify.rs`, `decode.rs` | commit & justification verification |
| Warp sync state machine | `lib/src/sync/warp_sync.rs` | authority-set bootstrap / fast sync |
| Trie storage-proof verifier | `lib/src/trie/proof_decode.rs` | (audited — **sound**, no finding) |
| Block/header verification | `lib/src/verify/*`, `lib/src/header/*` | (audited — no critical finding) |

---

## Critical Findings

### [C-01] GRANDPA justification verification does not bind the finalized block to the votes, allowing warp-sync chain forgery [VERIFIED]

**Severity**: Critical (Impact: High × Likelihood: High)
**Location**: `lib/src/finality/verify.rs:393-501` (`verify_justification`); reached via `lib/src/sync/warp_sync.rs:1683`
**Confidence**: HIGH — 2 independent analysis agents converged; root cause confirmed by direct code reading; `[POC-PASS]` end-to-end through the real warp-sync state machine.

#### Description

`verify_justification` is responsible for proving that a GRANDPA *justification* finalizes a given block. A sound verifier must establish that ≥2/3 of the authority set cast precommits **for that block (or its descendants)** — in GRANDPA terms, that the justification's target is the GHOST of the precommits, established using the `votes_ancestries` headers.

smoldot's implementation performs every check **except** that one:

```rust
// lib/src/finality/verify.rs  (verify_justification)
for precommit in decoded_justification.precommits.iter() {
    // ... authority-membership check + duplicate check ...

    // TODO: must check signed block ancestry using `votes_ancestries`   // <-- line 459: THE MISSING CHECK

    let mut msg = Vec::with_capacity(1 + 32 + 4 + 8 + 8);
    msg.push(1u8);
    msg.extend_from_slice(&precommit.target_hash[..]);          // precommit's OWN target
    msg.extend_from_slice(&precommit.target_number.to_le_bytes()[..]);
    msg.extend_from_slice(&u64::to_le_bytes(decoded_justification.round)[..]);
    msg.extend_from_slice(&u64::to_le_bytes(config.authorities_set_id)[..]);
    batch.queue(/* verify sig over msg */);
}
batch.verify(&mut randomness).map_err(|_| JustificationVerifyError::BadSignature)?;

// TODO: must check that votes_ancestries doesn't contain any unused entry   // line 497
// TODO: there's also a "ghost" thing?                                       // line 498
Ok(())
```

The signed message binds only `precommit.target_hash`, `precommit.target_number`, `round`, and `set_id`. **The justification's own `target_hash`/`target_number` — the block it claims to finalize — are never referenced anywhere in the function.** They are bound to nothing. The function therefore proves *"≥2/3 of set S signed some precommits in round R"* — **not** *"they finalized block B."*

The warp-sync wrapper supplies the only binding between the justification target and a block:

```rust
// lib/src/sync/warp_sync.rs  (VerifyWarpSyncFragment::verify)
if *fragment_decoded_justification.target_hash != fragment_header_hash      // line 1668
    || fragment_decoded_justification.target_number != fragment_decoded_header.number {
    return (.., Err(VerifyFragmentError::TargetHashMismatch { .. }));
}
// ...
verify::verify_justification(verify::JustificationVerifyConfig { .. })       // line 1683 (the broken fn)
// ...
self.inner.warped_header_state_root = *fragment_decoded_header.state_root;   // line 1736 (ATTACKER-CHOSEN)
```

In warp sync, **both** the fragment header and the justification are supplied by the peer, so the attacker simply makes them match. The light client then adopts the fragment header's `state_root` (line 1736) as the finalized state root. No block ancestry is verified anywhere in warp sync (the module docstring states: *"No attempt is made at verifying blocks"*).

#### Impact

A single malicious peer (any of the full nodes a light client warp-syncs from, or a man-in-the-middle) can make the light client:

1. **Finalize an arbitrary fabricated block `B′`** with an arbitrary block number and parent — `B′` need not exist on, or descend from, the real chain.
2. **Adopt an attacker-chosen state trie root.** Every subsequent storage read (account balances, `:code` runtime, staking, governance, transaction inclusion) is verified against this forged root, so every storage proof the attacker serves verifies. The attacker dictates everything the client believes about chain state.
3. **Install an attacker-chosen authority set** (if `B′`'s digest carries a GRANDPA `ScheduledChange`), permanently controlling all future verification.

For any wallet, dApp, or bridge that relies on a smoldot light client, this means forged balances, forged transaction-inclusion proofs, and forged finality — i.e., **fund loss and total loss of integrity**. Warp sync is smoldot's *default* sync path, the attack uses only **publicly-available genuine signatures**, and it leaves **no on-chain trace**.

#### Why this is NOT the documented "long range attack"

`lib/src/sync/warp_sync.rs:24-52` documents an accepted residual risk: a *long range attack* in which **≥2/3 of validators collude and equivocate** (produce a *second*, conflicting finality proof). That risk is mitigated by equivocation slashing and by keeping the warp-sync starting point recent.

This finding is categorically different and **not covered** by that assumption:

- The documented attack requires validators to **misbehave** (sign a conflicting finalization). This attack requires **zero** validator misbehavior — the validators honestly finalized `Y` exactly once.
- The missing ancestry/GHOST check is precisely what would otherwise force an attacker to obtain signatures over descendants of `B′` (impossible without keys or collusion). Removing it lets *honest* votes for `Y` be redirected onto *any* target `B′`.
- The equivocation-slashing disincentive provides **no** protection here, because no equivocation occurs.

The missing check thus collapses the security from *"needs ≥2/3 collusion + equivocation"* to *"needs only replaying public signatures,"* which is an unaccepted, catastrophic escalation.

#### PoC Result — `[POC-PASS]` (mechanical, end-to-end)

Two tests were added under `#[cfg(test)] mod poc_target_unbound` in `lib/src/finality/verify.rs` (test-only; no change to verification logic). Run:

```
cargo test -p smoldot --lib finality::verify::poc_target_unbound -- --nocapture
```

Output (full build + run):

```
running 2 tests
[PoC rung-2] forged fragment verify result = Ok(([196, 17, 252, ...], 500))
[PoC] verify(justification claiming to finalize forged B' using votes cast for Y) = Ok(())
[PoC] CONFIRMED: finalized target is unbound from the supermajority's actual votes.
[PoC rung-2] CONFIRMED: warp sync finalized attacker block (hash starts 0xc4) at height 500
             and will read ALL chain state from attacker root (starts 0x42).
[PoC] controls pass: signatures + 2/3 threshold ARE enforced; ONLY the target<->votes binding is missing.
test ... warp_sync_adopts_forged_block_with_attacker_state_root ... ok
test ... grandpa_justification_target_is_unbound_from_votes ... ok
test result: ok. 2 passed; 0 failed
```

- **Rung 1** (`grandpa_justification_target_is_unbound_from_votes`): builds a genuine justification finalizing canonical block `Y`, then re-wraps the *exact same precommits* under a justification claiming to finalize forged block `B′` — verification still returns `Ok(())`. **Controls prove signatures and the 2/3 threshold *are* enforced** (a flipped signature byte ⇒ `BadSignature`; 2 of 3 precommits ⇒ `NotEnoughSignatures`), isolating the defect to the missing target↔votes binding.
- **Rung 2** (`warp_sync_adopts_forged_block_with_attacker_state_root`): drives the **real warp-sync state machine** (`start_warp_sync` → `add_source` → `add_request` → `warp_sync_request_response` → `process_one` → `VerifyWarpSyncFragment::verify`) from a trusted genesis + real authority set. A single forged fragment is accepted; the client adopts `B′` (height 500) as finalized; and `desired_requests()` then asks for storage **against the attacker's forged state trie root** (`0x42..`) — proving the client will read all chain state from attacker-controlled storage.

This is the consensus-faithful, "regtest"-equivalent confirmation for a light client: the PoC exercises the **identical** verification and sync code that the production client runs against a live network, fed attacker-crafted data locally.

#### Recommendation (Fix)

Implement the GRANDPA commit-validity (GHOST/ancestry) check that the `// TODO`s describe: every precommit's target must be a descendant-or-equal of the justification target, using `votes_ancestries` to bridge the headers, and `votes_ancestries` must contain no unused entries. Conceptually:

```diff
  for precommit in decoded_justification.precommits.iter() {
      // ... authority-membership + duplicate checks ...
-     // TODO: must check signed block ancestry using `votes_ancestries`
+     // Reject the precommit unless its target is the justification target, or is
+     // reachable from it via the headers in `votes_ancestries` (i.e. the justification
+     // target is an ancestor of the precommit target). Build the ancestry set from
+     // `votes_ancestries` once, verify each header links by parent_hash, and require
+     // every precommit target to resolve to a descendant of `decoded_justification.target_hash`.
+     // Precommits that do not resolve MUST NOT count toward the 2/3 threshold.
      // ... signature queueing ...
  }
+ // Reject the justification if `votes_ancestries` contains entries not needed by any precommit.
```

Until fixed, this mirrors the soundness gap to also re-examine in the **commit** path: `verify_commit` computes `num_verified_signatures` (incremented only for ancestry-confirmed precommits) but gates acceptance on `decoded_commit.precommits.len()` instead (`verify.rs:329`), so unknown-ancestry precommits still count toward the threshold. The threshold comparison should use `num_verified_signatures`.

**Fix scope**: add the ancestry/GHOST verification to `verify_justification` (and switch the commit-path threshold to the verified counter). **Verified**: NO — fix not implemented in this audit; the PoC demonstrates the absence of the check.

---

## Methodology note (how this was found)

This follows the impact-first, exhaustively-enumerated, item-scoped methodology: the target *impact* was fixed precisely ("a malicious peer makes the client accept forged finalized state"), every verification location was enumerated, and each was given to a directed agent asking the under-constraint question — *"can a malicious peer supply this value without a check binding it to truth?"* The finding is the exact structural analog of an under-constrained ZK circuit: **a value that must be cryptographically bound (finalized block ↔ supermajority votes) is decoded but not constrained**, giving the attacker free choice of the "finalized" block.

## Responsible disclosure

This is a live-network-relevant vulnerability in a shipping light client. Before any public discussion: confirm the issue still reproduces against the latest upstream `paritytech/smoldot` (the two `// TODO`s at `verify.rs:459/497-498` are the fingerprint), and report privately to Parity Technologies' security contact with this report and the PoC. Do not run the attack against any client connected to a public network.

## Reproduction

```
git checkout 386a1f9a4b23c9a56b83c640828756b765ee2d4c
cargo test -p smoldot --lib finality::verify::poc_target_unbound -- --nocapture
```
