# High: Non-historical voting-power snapshot: veVirtual.balanceOfAt autoRenew path bypasses the time guard, enabling post-snapshot vote acquisition and governance takeover

**Target:** Virtual Protocol — VirtualProtocolDAOV2 / veVirtual (Base mainnet)  
**Severity:** High  
**Slug:** `virtual-vevirtual-governance-snapshot-bypass`

## Impact

An attacker with zero voting power at the proposal snapshot can stake autoRenew afterward and vote with full retroactive weight, enabling a no-timelock governance takeover and full DAO treasury drain.

## Proof of Concept

governanceSnapshotBypass.test.js drains a 500,000 VIRTUAL DAO treasury against the repo's real bytecode; governanceSnapshotBypass.fork.test.js proves the LIVE deployed veVIRTUAL (0x60a2...df8, custodying ~22M locked VIRTUAL) returns full retroactive weight on a Base-mainnet fork. Root cause is a mechanical early-return at veVirtual.sol:124-126 preceding the timestamp guard at :128, contradicting the NatSpec.

## Submission notes / caveats

A live V2 Governor/Defender consumer that realizes the treasury drain is not yet confirmed on basescan — a human must confirm the wired consumer and that governance/veVIRTUAL are in the Immunefi $200k scope. Economically gated (needs quorum-level ~25% veVIRTUAL locked ~2yr via autoRenew). Escalates to Critical on a confirmed live treasury-controlling V2.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `protocol-contracts/validated_issues/ISSUE-1.md`
- [`ISSUE-2.md`](./ISSUE-2.md) — write-up, from `protocol-contracts/validated_issues/ISSUE-2.md`
- [`IMMUNEFI-REPORT-governance-snapshot.md`](./IMMUNEFI-REPORT-governance-snapshot.md) — write-up, from `protocol-contracts/IMMUNEFI-REPORT-governance-snapshot.md`
- [`POC__governanceSnapshotBypass.test.js`](./POC__governanceSnapshotBypass.test.js) — PoC, from `protocol-contracts/test/audit/governanceSnapshotBypass.test.js`
- [`POC__governanceSnapshotBypass.fork.test.js`](./POC__governanceSnapshotBypass.fork.test.js) — PoC, from `protocol-contracts/test/audit/governanceSnapshotBypass.fork.test.js`
