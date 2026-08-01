# High: Permissionless permanent registry query-type squat via zero ReportBlockWindow (runtime path missing the genesis invariant)

**Target:** Tellor Layer L1 (x/registry RegisterSpec)  
**Severity:** High  
**Slug:** `tellor-layer-registry-zerowindow-squat`

## Impact

Anyone can permanently squat and DoS any oracle query type by registering it with a zero report window, stranding any tips later placed on it.

## Proof of Concept

TestZeroWindowSpecAcceptedAndSquats: runtime RegisterSpec accepts ReportBlockWindow=0 that genesis Validate rejects; every SubmitValue then fails ErrSubmissionWindowExpired; re-registration is blocked with AlreadyExists (permanent squat). Keeper-level test against the real RegisterSpec / validateRegisterSpec path.

## Submission notes / caveats

Permissionless and permanent (governance-only recovery); can strand third-party tips on the bricked query type with no refund path. Verification is keeper-level (appropriate for a message-handler logic bug), not full consensus. Same Tellor Layer scope-confirmation caveat as the bridge-overflow finding (info@tellor.io).

## Files in this folder

- [`AUDIT_REPORT.md`](./AUDIT_REPORT.md) — write-up, from `layer/AUDIT_REPORT.md`
- [`POC__zerowindow_dos_test.go`](./POC__zerowindow_dos_test.go) — PoC, from `layer/x/registry/keeper/zerowindow_dos_test.go`
