# High: Permissionless sandwich drain of protocol-owned charge-fee-pool reserves via unguarded ExactSupply(_,0) refill swap (configured 10% oracle guard is dead code)

**Target:** Acala (mandala/karura/acala runtime, transaction-payment pallet)  
**Severity:** High  
**Slug:** `acala-fee-pool-sandwich-drain`

## Impact

Any permissionless account can sandwich the fee-pool refill swap (min_target=0, dead oracle guard) to drain protocol-owned fee-pool reserves, proven draining ~798 of 1000 DOT on the real mandala runtime.

## Proof of Concept

PoC A pallet test (real module_dex + pallet swap logic, +388,807 AUSD extracted, reserve 500,000 -> 120) and PoC B integration test on the FULL REAL mandala runtime (real 0.1% DEX fee, real fee-pool mechanics) draining ~798 of 1000 DOT attacker-native-neutral. MaxSwapSlippageCompareToOracle/PriceSource declared but never read (grep-confirmed dead); cdp-engine applies the identical guard correctly, proving intent.

## Submission notes / caveats

In-scope runtime pallet (index 14); front-running/sandwich/MEV not on the Immunefi out-of-scope list; maps to 'Direct loss of funds'. Permissionless. Per-incident magnitude is bounded by the governance-set fee-pool reserve (a replenishable buffer, not user deposits) and repeatable each refresh cycle — downgraded Critical->High on magnitude. PoCs are inline in the report with executed output, not committed as standalone files.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `Acala/validated_issues/ISSUE-1.md`
- [`REPORT_TXPAYMENT-1.md`](./REPORT_TXPAYMENT-1.md) — write-up, from `Acala/REPORT_TXPAYMENT-1.md`
- [`AUDIT_FINDINGS.md`](./AUDIT_FINDINGS.md) — write-up, from `Acala/AUDIT_FINDINGS.md`
