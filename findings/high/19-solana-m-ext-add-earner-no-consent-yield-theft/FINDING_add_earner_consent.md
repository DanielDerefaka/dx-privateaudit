# Finding: `add_earner` requires no holder consent → earn manager mints a non-consenting holder's yield to itself (crank variant)

**Status:** CONFIRMED on-chain (`[POC-PASS]`) — reproduced twice against the real compiled `crank.so`: (1) litesvm on host, (2) clean Docker `node:22` container (`linux/amd64`, fresh install). Both: `attacker stole victim yield = 9090909`, victim balance unchanged.
**PoC:** [tests/unit/poc_earner_consent.test.ts](tests/unit/poc_earner_consent.test.ts) — `node_modules/.bin/jest --preset ts-jest tests/unit/poc_earner_consent.test.ts`
**Affected build:** `m_ext` with `--features crank` (and `wm` = crank+migrate). Not present in `no-yield`/`scaled-ui` (no `add_earner`).
**Severity:** High. (No *unconditional* Critical exists in this codebase — see *Scope conclusion*.)

## Scope conclusion (why no Critical)
9+ independent adversarial passes + line-by-line review of both programs confirm the permissionless surface is conservation-sound by construction: **no instruction releases vault M without burning equivalent ext** (principal undrainable by anyone), and the only mint paths (`claim_for`, `claim_fees`) are role-gated *and* collateral-checked (no permissionless inflation). Every high-impact finding therefore requires a semi-trusted role → Medium likelihood → **High** by the Impact×Likelihood matrix. This matches the 4 prior audit firms. The strongest residual permissionless issue is a ≤~1-unit dust rounding deficit (Low/Info, non-extractable). Consequently this finding is the top exploitable issue, at High.

---

## Root cause

[`add_earner`](programs/m_ext/src/instructions/crank/earn_manager/add_earner.rs#L14-L65) is signed **only by an active earn manager**. The enrolled `user` never signs:

```rust
pub struct AddEarner<'info> {
    #[account(mut)]
    pub signer: Signer<'info>,                 // the earn manager — the ONLY signer
    #[account(constraint = earn_manager_account.is_active ...,
              seeds = [EARN_MANAGER_SEED, signer.key().as_ref()], ...)]
    pub earn_manager_account: Account<'info, EarnManager>,
    ...
    #[account(token::mint = global_account.ext_mint, token::authority = user)]
    pub user_token_account: InterfaceAccount<'info, TokenAccount>,   // any holder's ATA
    #[account(init, payer = signer,
              seeds = [EARNER_SEED, user_token_account.key().as_ref()], ...)]
    pub earner_account: Account<'info, Earner>,                      // bound to that holder
}
```

`user` and `user_token_account` are public for every holder, so a manager can enroll **any** ext holder as *its* earner without that holder's involvement.

This composes with two more gaps:

1. [`set_recipient`](programs/m_ext/src/instructions/crank/earner/set_recipient.rs#L11-L41) accepts the **earn manager** as `signer` and does **not** constrain the recipient account's owner (only `token::mint = ext_mint`). So the manager can point the earner's payout at an account the manager owns.
2. [`add_earn_manager`](programs/m_ext/src/instructions/crank/admin/add_earn_manager.rs#L49) / [`configure`](programs/m_ext/src/instructions/crank/earn_manager/configure.rs#L47) allow `fee_bps` up to **100%** (no sub-100 cap). So even without `set_recipient`, a 100% fee routes the entire reward to the manager's fee account.

The honest `earn_authority` crank discovers every on-chain `Earner` PDA and calls [`claim_for`](programs/m_ext/src/instructions/crank/earn_authority/claim_for.rs), which **mints** the reward to `recipient_token_account ?? user_token_account`. In the crank variant these are real, 1:1-M-redeemable ext tokens (the [collateral check at L136](programs/m_ext/src/instructions/crank/earn_authority/claim_for.rs#L136) keeps `ext_supply ≤ vault_M`). So redirected yield = **redeemable funds**, not points.

`earn_authority`-gating on `claim_for` does **not** stop the attack — the attacker doesn't call `claim_for`; the honest crank does, on its normal cycle.

## The victim has no recourse
- Cannot self-remove: [`remove_earner`](programs/m_ext/src/instructions/crank/earn_manager/remove_earner.rs#L18) requires the *manager* to sign.
- Cannot out-redirect: the manager can re-`set_recipient` or use a 100% fee, which `set_recipient` can't counter.
- [`remove_orphaned_earner`](programs/m_ext/src/instructions/crank/remove_orphaned_earner.rs#L22) only works once the manager is `is_active = false`, i.e. after **admin** intervention.
- Only off-chain workaround: move ext to a fresh token account (the `Earner` is seeded by the specific `user_token_account`).

## Secondary impact — enrollment DoS (same root cause)
`Earner` is seeded solely by `user_token_account` and created with `init`. A manager can **squat** a victim's `Earner` PDA, after which the victim's *legitimate* manager can never enroll them (`init` collision) until admin deactivates the squatter.

---

## Proof of Concept (confirmed)

`tests/unit/poc_earner_consent.test.ts`, run against the real compiled `crank.so` under litesvm:

```
[PoC CONFIRMED] non-consenting victim balance unchanged: 100000000
[PoC CONFIRMED] attacker stole victim yield (redeemable ext): 9090909
   lastClaimIndex=1000000000000 newExtIndex=1090909090909
PASS tests/unit/poc_earner_consent.test.ts
```

Flow: admin onboards `attackerManager`; `victim` independently wraps M→ext (100 ext) and never opts into earning; M appreciates 1.1→1.2 (real yield accrues). Then, with **only the manager signing**: `add_earner(victim)` → `set_recipient(attacker_account)`. The **honest** `earn_authority` then `sync`s and `claim_for`s the victim's real balance — minting the victim's entire yield (`9.09 ext`, redeemable) to the attacker while the victim's balance is unchanged.

Build: `anchor build -p m_ext -- --features crank --no-default-features` (exit 0) → `target/deploy/crank.so`.
Run: `node_modules/.bin/jest --preset ts-jest tests/unit/poc_earner_consent.test.ts`.

---

## Severity

Impact × Likelihood → **High**:
- **Impact: High.** Direct theft of redeemable funds. The reward is newly-minted ext fully backed by vault M. Aggregated over many enrolled idle holders it diverts the protocol's *entire distributable yield stream each cycle* (crank has no `claim_fees`; un-enrolled yield otherwise stays as vault reserves), unbounded cumulatively over time.
- **Likelihood: Medium.** Requires an admin-approved active earn manager (semi-trusted partner). Not permissionless.

**Case for Critical:** earn managers are trusted only w.r.t. *their own* earners; reaching into arbitrary non-customers’ holdings is a **trust-boundary violation / privilege escalation**, not "trusted actor acting in scope" (so it is *not* eligible for the fully-trusted −1 downgrade). A single phished/compromised partner key escalates to protocol-wide yield theft + arbitrary-holder DoS, executed by the honest crank (so it reads as normal yield distribution — low detectability). If manager onboarding is low-bar/automated, treat as Critical.

---

## Remediation

1. **Root cause:** require the `user` to sign `add_earner` (or a prior on-chain opt-in account / co-signature). This collapses the entire chain.
2. **Defense in depth:** in `set_recipient`, require `recipient_token_account.owner == earner.user`.
3. **Defense in depth:** cap `fee_bps` below 100% (e.g. a protocol max) in `add_earn_manager`/`configure`, and require `fee_token_account.owner == earn_manager`.
4. Consider returning `remove_orphaned_earner` rent to the earner's `user`, and letting a user self-remove.

Fixes (1)–(3) modify different functions and are independent.
