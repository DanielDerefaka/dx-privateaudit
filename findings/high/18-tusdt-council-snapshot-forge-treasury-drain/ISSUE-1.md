# ISSUE-1: Missing snapshot validation in `submit_snapshot` lets a single council member forge the electorate and drain the treasury

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High (report claimed Critical — see severity note)
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (adversarial + trust-model judgment)
**Confidence**: HIGH

## Summary
A single member of the 5-person governance council can commit a fully attacker-controlled
Merkle snapshot (arbitrary `root`, `circulating_supply = 1`) via `submit_snapshot`, then
self-submit a Funding proposal, self-vote with an empty proof, finalize, and execute —
transferring the entire treasury balance to themselves. The same forged snapshot also decides
the maintainer election, escalating to permanent governance capture. The technical exploit is
fully confirmed against the code; the only open question is severity under the council trust model.

## Location
- `contracts/tusdt-governance/lib.rs` — `submit_snapshot` (L548), `quorum` (L582), `vote`/leaf verify (L711/743), `finalize` (L784/803), `execute` (L835/853), `submit_proposal` (L639/645), `ensure_council` (L879)
- `voting/src/lib.rs` — `verify_merkle_proof` (L105), `leaf_hash` (L78), `voting_power` (L70)
- `contracts/tusdt-treasury/lib.rs` — `release` (L204), `ensure_governance` (L211)
- `contracts/tusdt-election/lib.rs` — `gov_latest_snapshot`/`election_snapshot` (L561), `cast_approval` merkle verify (L681)

## Justification

Every mechanical claim in the report was independently verified against the source:

1. **`submit_snapshot` stores an unvalidated electorate, gated by one council member.**
   `ensure_council()` (L879) passes for any single member of the 5-person `council` Vec.
   `root` and `circulating_supply` are inserted verbatim (L559–566) with no cross-check against
   real subnet stake, no floor, and no threshold/co-sign. CONFIRMED.

2. **`circulating_supply = 1` truncates quorum to zero.** `quorum()` = `1 * 2000 / 10_000 = 0`
   under integer division (L586–588). `finalize` uses `voted_balance >= quorum` (L803), satisfied
   by any non-zero vote. CONFIRMED. (Note: the attacker controls `circulating_supply` outright, so
   this integer-truncation trick is not even required — they can pass quorum for any value.)

3. **Empty proof verifies against a self-chosen root.** `verify_merkle_proof(&[], root, leaf)`
   returns `leaf == root` (voting/src/lib.rs:106–110). The attacker sets
   `root = leaf_hash(self, self, balance, 10_000)` in step 1 and votes with those exact values and
   `proof = []`. `voting_power(balance, 10_000)` is non-zero for any `balance > 0`. CONFIRMED.

4. **The passed proposal pays out.** `execute → treasury.release` (L853); `release` gates on
   `ensure_governance()` (treasury L211), and the governance contract holds the treasury's
   `governance` role after wiring (README step 10), so the transfer to the attacker succeeds. CONFIRMED.

5. **Election escalation.** `tusdt-election` pulls the same governance snapshot as its electorate
   (`gov_latest_snapshot`, election L561) and verifies approvals with the identical
   `verify_merkle_proof` against the same root (L681). The identical forgery installs the attacker as
   maintainer, who then controls the emergency oracle price and all maintainer-only forwarders. CONFIRMED.

6. **No effective on-chain mitigation.** The proposal binds its `snapshot_epoch` at submission (L665)
   and votes prove against that fixed epoch, so a later maintainer snapshot cannot override it.
   `finalize`/`execute` are permissionless, and removing the attacker from council after the
   snapshot+proposal+vote are in place does not undo them. The only intervention window is the few
   blocks between `submit_snapshot` and `vote`, which the attacker executes atomically in sequence.
   CONFIRMED — no veto/cancel path exists.

**Trust-model analysis (the decisive dimension).** The README (L226–230) documents council as a
*limited operational* committee whose granted powers are exactly: `submit_snapshot`, `vault_pause`,
and (per the recent commit) `submit_proposal`. Council is explicitly **not** granted treasury-release
authority or maintainer authority — those are reserved for token-holder voting and the elected
maintainer respectively. Therefore this is **not** "a fully trusted admin using its granted powers"
(which would cap at Low/Informational). It is a **privilege escalation**: a missing-validation defect
lets a narrowly-scoped, semi-trusted role obtain powers the trust model deliberately withheld —
unilateral, irreversible drain of 100% of the treasury plus permanent maintainer capture. The Step 2
Low-cap therefore does **not** apply, and the issue does **not** reduce entirely to "trusted role can
rug." The README note that "any single council member can act on" `submit_snapshot` covers only the
intended act of publishing the *real* electorate; it does not sanction committing a *forged* one, which
is the defect.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | "Trusted admin abuse / by-design — council may submit snapshots (README)" | Step 2 (Roles) | FAILS (partial) | README grants council only snapshot+pause+proposal, NOT treasury/maintainer power; forged (vs real) snapshot is out-of-scope of the documented duty. Escalation beyond role → not pure admin rug. Caps severity consideration but does not invalidate. |
| 2 | "Second-preimage forgery of an 84-byte leaf is infeasible" | Step 4 (Adversarial) | FAILS | Attack needs no preimage break — a single-leaf tree where the caller *chose* the root is accepted; empty proof ⇒ root==leaf. Defect is structural, not cryptographic. |
| 3 | "Maintainer / other council members can intervene mid-attack" | Step 4 (Adversarial) | FAILS | No proposal veto/cancel; proposal binds fixed snapshot_epoch; finalize/execute permissionless; council removal does not undo committed snapshot/vote. No mitigation. |
| 4 | "Submission window (days 20–27) blocks the attack" | Step 4 (Adversarial) | FAILS | Liveness delay only; window recurs monthly and the attacker is the proposer. Does not prevent the attack. |
| 5 | "`circulating_supply = 1` truncation is the linchpin and may be guarded" | Step 3 (Generic: input validation) | FAILS | Attacker controls circulating_supply directly; quorum is defeated for any chosen value, not just via truncation. |

## Severity Note (Critical vs High)
The exploit and impact (total treasury loss + irreversible governance capture) are catastrophic and
verified by a runnable PoC. The single downgrade factor is the precondition: the attacker must **hold
or compromise one of five maintainer-appointed council seats** — a privileged (if limited and
semi-trusted) position, not an unprivileged actor. Under most audit rubrics, a *limited-privileged*
role escalating to total loss lands at **High**, with **Critical** reserved for unprivileged /
minimally-privileged total loss. The report's **Critical** rating is defensible — the irreversible,
protocol-wide capture and the collapse of the maintainer/council separation-of-powers are Critical-grade
consequences. The disagreement is solely about how much the "requires a council seat" precondition
lowers likelihood. Final call: **High**, bordering Critical. Either way the finding is real, in-scope,
and must be fixed.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all referenced files/functions exist and match; mechanism is internally consistent. (One typo in the report: `contracts/tusdt-gnce/lib.rs` → actually `contracts/tusdt-governance/lib.rs`; line numbers are ~off-by-a-few but functions verified.)
- **Step 2 (Privileged Roles)**: Council identified in attack path. Classified SEMI-TRUSTED (limited operational committee), NOT fully-trusted admin. Low-cap NOT applied — issue is privilege escalation beyond documented role scope, not pure admin rug. No early exit.
- **Step 3 (Generic Check)**: input-validation / trust-distribution reasons checked — none hold as invalidations (see table).
- **Step 4 (Adversarial Check)**: preimage-infeasibility, maintainer-intervention, submission-window, and truncation-dependency defenses all FAIL. Judge verdict: VALID; severity adjusted Critical → High on the privileged-precondition dimension.
- **Final Severity**: High (adjusted from claimed Critical).
