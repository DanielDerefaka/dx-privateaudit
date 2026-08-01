# High: Missing snapshot validation in submit_snapshot lets one council member forge the electorate and drain the treasury (+ capture maintainer)

**Target:** TUSDT-SmartContract — ink!/Substrate collateralized stablecoin (Bittensor-subnet)  
**Severity:** High  
**Slug:** `tusdt-council-snapshot-forge-treasury-drain`

## Impact

A single rogue/compromised council member forges a Merkle snapshot (arbitrary root, circulating_supply=1 -> quorum 0), self-votes with an empty proof, and drains 100% of the treasury, escalating to permanent maintainer/governance capture.

## Proof of Concept

drainExploit.ts deploys erc20+treasury+governance to a live substrate-contracts-node and runs the full chain (forged root + circulating_supply=1 -> quorum 0; empty-proof self-vote; finalize->Passed; execute) with REAL cross-contract calls governance.execute -> treasury.release -> erc20.transfer. On-chain: attacker Bob (0 legit stake) moved 400,000,000 TUSDT out of the Emergency fund.

## Submission notes / caveats

Gated: attacker must hold/compromise 1 of 5 maintainer-appointed council seats — but council is granted ONLY snapshot+pause+proposal, NOT treasury or maintainer power (README L226-230), so this is privilege ESCALATION beyond the documented role, not admin-by-design. Three PoC shims are compat/liveness-only and off the auth path. Confirm the system is deployed / holds value on its target subnet (PoC is regtest).

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `TUSDT-SmartContract/validated_issues/ISSUE-1.md`
- [`FINDING-critical-council-treasury-drain.md`](./FINDING-critical-council-treasury-drain.md) — write-up, from `TUSDT-SmartContract/FINDING-critical-council-treasury-drain.md`
- [`VULN-ASSESSMENT-REPORT.md`](./VULN-ASSESSMENT-REPORT.md) — write-up, from `TUSDT-SmartContract/VULN-ASSESSMENT-REPORT.md`
- [`POC__drainExploit.ts`](./POC__drainExploit.ts) — PoC, from `TUSDT-SmartContract/tools/scripts/drainExploit.ts`
