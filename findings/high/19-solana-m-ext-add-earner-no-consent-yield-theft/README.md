# High: add_earner requires no holder consent -> rogue/compromised earn manager mints a non-consenting holder's yield to itself

**Target:** solana-m-extensions — M^0 m_ext program, 'crank' variant (crank.so; also 'wm')  
**Severity:** High  
**Slug:** `solana-m-ext-add-earner-no-consent-yield-theft`

## Impact

A single rogue/phished/compromised earn-manager key enrolls arbitrary non-consenting ext holders and redirects their newly-minted, 1:1-M-redeemable yield to itself — protocol-wide yield-stream theft plus arbitrary-holder enrollment DoS.

## Proof of Concept

poc_earner_consent.test.ts: add_earner(victim) + set_recipient(attacker) with only the manager signing, then the HONEST earn_authority crank's claim_for mints the victim's full per-cycle yield (9090909) to the attacker while victim balance is unchanged. Reproduced twice against the REAL compiled crank.so (litesvm on host + clean Docker linux/amd64) — real bytecode, not a mock.

## Submission notes / caveats

Gated: requires an admin-approved ACTIVE earn manager (semi-trusted partner), so likelihood is Medium — but a manager reaching into ARBITRARY non-customer holdings is a trust-boundary violation / privilege escalation, not 'trusted actor acting in scope', so not eligible for a fully-trusted downgrade. Author states novel vs 4 prior audit firms (Asymmetric, Sec3, OtterSec, Halborn).

## Files in this folder

- [`FINDING_add_earner_consent.md`](./FINDING_add_earner_consent.md) — write-up, from `solana-m-extensions/FINDING_add_earner_consent.md`
- [`POC__poc_earner_consent.test.ts`](./POC__poc_earner_consent.test.ts) — PoC, from `solana-m-extensions/tests/unit/poc_earner_consent.test.ts`
