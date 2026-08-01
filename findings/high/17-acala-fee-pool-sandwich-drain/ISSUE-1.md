# ISSUE-1: Missing slippage/oracle bound on charge-fee-pool refresh swap (`ExactSupply(_, 0)`) lets any permissionless account sandwich-drain protocol-owned fee-pool reserves

## Pipeline Result
**Verdict**: VALID (DOWNGRADED on severity)
**Final Severity**: High
**Original Claimed Severity**: Critical (author noted "High/Critical boundary")
**Pipeline Exit Point**: Step 4 (full pipeline)
**Confidence**: HIGH

## Summary
The `transaction-payment` pallet refills each charge-fee-pool sub-account by selling its **entire** accumulated foreign-token reserve on the DEX with `SwapLimit::ExactSupply(supply_amount, 0)` — `min_target = 0`, no oracle/slippage bound. The pallet declares and the live runtime configures `MaxSwapSlippageCompareToOracle` (10%) + `PriceSource`, but the swap logic never reads them (genuinely dead). The refill is triggered by ordinary permissionless fee-paying transactions, so the protocol-owned reserve can be sandwiched. All code claims verified against source; both PoCs are mechanically sound. Downgraded Critical → High because per-incident magnitude is bounded by the governance-set fee-pool reserve (a replenishable buffer, not user deposits or the main treasury) and realized loss/attacker-profit scale with DEX-pool depth relative to the dumped reserve.

## Location
- `modules/transaction-payment/src/lib.rs:1129-1166` (`swap_from_pool_or_dex`); unguarded swap at **L1146** `SwapLimit::ExactSupply(supply_amount, 0)`
- Dead guard config: `modules/transaction-payment/src/lib.rs:365, 372`
- Reference (correct) impl: `modules/cdp-engine/src/lib.rs:1349-1358`
- Live wiring (unused): `runtime/mandala/src/lib.rs` txn-payment Config — `MaxSwapSlippageCompareToOracle = 10%`, `PriceSource = RealTimePriceProvider`, `DefaultFeeTokens = [AUSD, DOT, LDOT]`

## Justification

### Step 1 — code claims independently verified (all CONFIRMED)
1. **Unguarded swap**: L1142-1146 calls `T::Swap::swap(&sub_account, supply_currency_id, NativeCurrencyId, SwapLimit::ExactSupply(supply_amount, 0))`. `supply_amount = free_balance − min_balance` → the **whole** reserve, with a `min_target` of `0`.
2. **Dead guard**: `grep` of the pallet shows `MaxSwapSlippageCompareToOracle` and `PriceSource` appear ONLY at their Config declarations (L365/L372) and mock wiring — never read in any swap path. Confirmed dead.
3. **Intent proof**: `cdp-engine` (L1349-1358) computes `max_supply_limit` from `MaxSwapSlippageCompareToOracle` + `PriceSource::get_relative_price` and swaps with `ExactTarget` bounded by it. Same guard, correctly applied there → omission in txn-payment is a missing-check bug, not a design choice.
4. **Permissionless reachability**: `swap_from_pool_or_dex` is reached from fee charging (L949 `charge_fee_currency`, L1092/L1108 fallback) during `ChargeTransactionPayment::validate_and_prepare`, and from `with_fee_currency`/`with_fee_path`/`with_fee_aggregated_path` (all `ensure_signed`, L639/L655/L674). Only `enable_charge_fee_pool` is `UpdateOrigin`-gated — one-time setup, already performed live (`DefaultFeeTokens`).
5. **Live config**: mandala wires the 10% guard + real price source + default fee pools (AUSD/DOT/LDOT) to the pallet; the guard is configured yet never consulted.
6. **No hidden DEX guard**: `module-dex` `swap_with_specific_path`/`do_swap_with_exact_supply` enforce only the `minimum_target_amount` floor (here 0) — pure constant-product, no oracle reference.
7. **PoC soundness**: Hand-traced PoC A (0-fee mock, 1M:1M pool, 500k reserve): front-run 1M AUSD→ACA (pool→500k:2M, BOB +500k ACA); protocol dumps 500k AUSD→ACA (pool→400k:2.5M, gets 100k ACA); back-run 500k ACA→AUSD (BOB +1,388,889 AUSD). Net: BOB ACA-neutral, +388,889 AUSD; protocol reserve drained — matches reported `+388,807`. PoC B on real mandala runtime (0.1% fee) extracts ~798 DOT, consistent.

### Step 2 — privileged roles
No trusted role must act maliciously. `enable_charge_fee_pool` is legitimate, already-completed setup; it is a precondition, not the abuse vector. The harm falls on protocol funds via permissionless actors. Trusted-actor cap does NOT apply.

### Step 3 — generic invalidation reasons (all FAIL)
- *"A slippage/oracle guard exists somewhere in the path"* → FAILS: DEX enforces only `min_target` and it is `0`; no oracle in the DEX path; the pallet-level guard is dead.
- *"Admin/permission-gated"* → FAILS: trigger path is `ensure_signed`.
- *"Out of scope / unreachable"* → FAILS: in-scope runtime pallet with default-enabled fee pools.

### Step 4 — issue-specific adversarial reasons
- **Substrate tx-ordering / MEV feasibility** → does NOT invalidate (likelihood nuance). The attacker self-triggers the refill (no victim needed) and controls all three actions. A non-collator faces MEV competition for *capturing* the spread, but the **protocol loss is robust to ordering** — any skew present at refill time realizes the loss regardless of who captures it; a collator/colluding builder captures it deterministically.
- **"Fixed-rate fee design is intentional"** → does NOT invalidate. The fixed `TokenExchangeRate` governs USER fee charging (L1176-1186); the unguarded **DEX refill** is a separate mechanism whose guard is declared, configured, and (per cdp-engine) clearly intended.
- **`#[transactional]` / swap-failure safety** → does NOT invalidate. A swap that *succeeds* at a manipulated price is not a failure; rollback never triggers.
- **Magnitude bound** → HOLDS as a severity DOWNGRADE (not invalidation). Per-incident loss ≤ sub-account reserve at refill (~`pool_size − threshold`, governance-set), the funds are a replenishable fee buffer, and both realized loss and guaranteed attacker profit scale with DEX-pool depth vs. the dumped reserve (PoCs use a worst-case ~1:1 reserve:liquidity ratio). On deep mainstream pairs the per-incident loss is modest; on shallow/long-tail fee-token pairs it approaches the PoC figures.

### Severity calibration
Impact = direct loss of protocol-owned funds but bounded/replenishable and liquidity-dependent (Medium–High). Likelihood = permissionless, self-inducible, recurring (High). Net → **High**, with a defensible Critical on illiquid fee-token pairs. The fix is identical regardless: bound the refresh swap with the already-declared `MaxSwapSlippageCompareToOracle`/`PriceSource` (derive a non-zero `min_target`), mirroring `cdp-engine` — or at minimum pass a `min_target` computed from the fixed `TokenExchangeRate` instead of `0`.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | DEX/path enforces slippage or oracle bound | Step 3 (Generic) | FAILS | `do_swap_with_exact_supply` checks only `min_target` floor; min=0; no oracle in path |
| 2 | Path is admin/permission-gated | Step 3 (Generic) | FAILS | trigger via `ensure_signed` fee txs; only one-time `enable_charge_fee_pool` is gated |
| 3 | Out of scope / unreachable on live config | Step 3 (Generic) | FAILS | default fee pools AUSD/DOT/LDOT enabled on mandala |
| 4 | Substrate tx-ordering makes sandwich infeasible | Step 4 (Adversarial) | PARTIAL | attacker self-triggers; protocol loss robust to ordering; profit-capture is MEV-dependent → likelihood nuance only |
| 5 | Unguarded refill swap is intended design | Step 4 (Adversarial) | FAILS | dead config + correct cdp-engine usage prove the guard was intended here |
| 6 | `#[transactional]` / swap-fail rollback protects | Step 4 (Adversarial) | FAILS | success at bad price is not a failure; no rollback |
| 7 | Magnitude is bounded → not Critical | Step 4 (Adversarial) | HOLDS (downgrade) | per-incident loss bounded by governance reserve; buffer funds; liquidity-dependent |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all 3 components present; 7/7 code claims verified against source.
- **Step 2 (Privileged Roles)**: NO_ISSUE — no trusted role acts maliciously; no cap applied.
- **Step 3 (Generic Check)**: 3 reasons evaluated, 0 held → no early exit.
- **Step 4 (Adversarial Check)**: 4 reasons evaluated; 0 invalidate; 1 (magnitude) holds as a downgrade factor.
- **Final Severity**: High (downgraded from Critical).
