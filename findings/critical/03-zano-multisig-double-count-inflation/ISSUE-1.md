# ISSUE-1: Missing intra-transaction uniqueness check on `txin_multisig` inputs → multisig double-count inflation / theft

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full adversarial check completed; no early exit)
**Confidence**: HIGH

## Summary
A Zano transaction can list the same `txin_multisig` (same `multisig_out_id`) two or more times. The only intra-transaction input-reuse guard is the key-image dedup set, and multisig inputs carry no key image, so they are silently excluded. No other check rejects duplicate multisig inputs, while the balance check adds the source output's `amount` once per duplicate input. One signature set validates all duplicates (normal-mode prefix hash is the same for every input). Result: a single A-valued multisig output spent K times mints (K−1)·A from nothing. Confirmed end-to-end by direct code trace (8/8 links), two independent adversarial refutation agents (both could not refute), and a passing `core_tests` PoC that runs through the real consensus engine and asserts inflation on a real `wallet2` balance.

## Location
- `src/currency_core/tx_semantic_validation.cpp:22-35` — `check_tx_inputs_keyimages_diff` (only dedups key-image inputs)
- `src/currency_core/currency_format_utils_abstract.h:198-227` — `get_key_image_from_txin_v` returns false for `txin_multisig`
- `src/currency_core/currency_format_utils_abstract.h:318-321` — `compare_variant_by_types(ms,ms)` strict `<` on `multisig_out_id`
- `src/currency_core/currency_format_utils_transactions.cpp:306-322` — `validate_inputs_sorting` accepts equal adjacent inputs
- `src/currency_core/blockchain_storage.cpp:5742-5871` — `check_ms_input` / `check_tx_input` validate each input independently, no per-tx multisig-id set
- `src/currency_core/currency_format_utils.cpp:4420-4424` — `prepare_prefix_hash_for_sign` returns `tx_id` for every input in normal mode
- `src/currency_core/currency_format_utils.cpp:654-655` — `check_tx_balance` adds `ms.amount` per input (post-HF4)
- `src/currency_core/currency_format_utils.cpp:3028-3037` — `get_inputs_money_amount` sums all inputs (pre-HF4)
- `src/currency_core/blockchain_storage.cpp:3170-3186` — re-spend mark at connect is warn-only, returns true
- `src/currency_core/blockchain_storage.cpp:6412-6431` — `is_allowed_after_hardfork4`: multisig INPUTS allowed post-HF4
- `src/currency_core/blockchain_storage.cpp:7112` — `check_tx_balance` call site inside `handle_block_to_main_chain`

## Justification
Every link of the exploit chain was independently verified against the actual source:

1. **No intra-tx multisig dedup.** `check_tx_inputs_keyimages_diff` only inserts inputs for which `get_key_image_from_txin_v` returns true; that function handles `txin_zc_input`/`txin_to_key`/`txin_htlc` only and returns false for `txin_multisig`. Grep of the entire validation path found no set keyed on `multisig_out_id` on the main-chain path (the only hits are a connect-time global-index check and an alt-chain cross-*transaction* check at L8439 — neither compares a tx's inputs against each other).
2. **Sorting accepts equal inputs.** `validate_inputs_sorting` rejects only strictly-decreasing order; `compare_variant_by_types(ms,ms)` is strict `<`, so equal `multisig_out_id`s are "not less" → accepted.
3. **Per-input validation only.** `check_ms_input`/`check_tx_input` validate `sigs_count`, `amount`, signatures, and `spent_height==0`/`m_spent_flags[n]==false` for each input. The spent flags are DB state written only at connect, so during validation both duplicate inputs see the source as unspent.
4. **One signature set covers all duplicates.** In normal mode (`flags == 0`), `prepare_prefix_hash_for_sign` returns the plain `tx_id` for every `in_index`. Both inputs reference the same source output (same keys), so a copied signature set validates both.
5. **Balance double-counts.** Post-HF4 `check_tx_balance` adds `ms.amount` per `txin_multisig`; pre-HF4 `get_inputs_money_amount` sums every input. Two identical inputs → `bare_inputs_sum = 2A`, permitting outputs of `2A − fee`. The post-HF4 Schnorr balance proof is constructed over this already-doubled plaintext `bare_inputs_sum`, so it only proves inputs==outputs and cannot catch the duplication.
6. **Block connects.** At connect the second spend-mark hits `spent_height != 0` and merely logs `LOG_PRINT_YELLOW`, overwrites, and returns true — no abort.
7. **Reachable post-HF4.** `is_allowed_after_hardfork4` blocks only `tx_out_bare` outputs (which carry `txout_multisig`), so new multisig outputs can't be created — but `txin_multisig` SPENDS are never disallowed, and pre-HF4 multisig/escrow outputs remain indexed in `m_db_multisig_outs` and spendable. So the double-count reaches the modern balance check.
8. **PoC integrity.** `git diff` shows zero `src/` changes. The three modified test files are legitimate Apple-clang compile fixes (delegating constructor in `block_validation.cpp`; integer-type adjustments in `wallet_tests.cpp`) plus the test registration. The PoC is wired in via `GENERATE_AND_PLAY(gen_multisig_same_tx_double_count)`, which replays events through a real `currency::core` (full consensus validation); with no `mark_invalid_tx`/`mark_invalid_block`, block acceptance is asserted by the harness, and the harm is asserted on bob's real `wallet2::balance() ≥ 2A − fee`.

**Severity = Critical.** Direct, repeatable supply-invariant violation (mint from nothing) plus theft of multisig/escrow-locked funds. No privileged/trusted role is required (the attacker only needs to satisfy the signature threshold of a multisig output they legitimately participate in — a normal-participant capability), so no trusted-actor downgrade applies. The precondition (control/assemble the threshold of an existing pre-HF4 multisig or escrow output) narrows the realized blast radius on the current mainnet but does not lower the severity class; pre-HF4 / regtest / active CryptoNote forks reusing this validation are exploitable permissionlessly and self-contained.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | A multisig dedup check exists elsewhere | Generic (input validation) | FAILS | No `multisig_out_id` uniqueness set on main-chain path; grep confirms |
| 2 | Signature is index-bound; reuse fails on 2nd input | Adversarial (crypto) | FAILS | `prepare_prefix_hash_for_sign` returns `tx_id` for all indices in normal mode; same source keys → one set validates both |
| 3 | Post-HF4 ZC balance proof rejects the doubled sum | Adversarial (crypto) | FAILS | Proof is built over the plaintext `bare_inputs_sum` already doubled at L655; only enforces inputs==outputs |
| 4 | Block connect aborts on double spend-mark | Adversarial (state) | FAILS | Warn-only `LOG_PRINT_YELLOW`, returns true (L3178-3185) |
| 5 | `txin_multisig` spends disallowed post-HF4 (unreachable) | Adversarial (reachability) | FAILS | `is_allowed_after_hardfork4` blocks only `tx_out_bare` outputs; inputs always pass |
| 6 | Requires trusted/privileged role → downgrade | Step 2 (roles) | FAILS | Attacker uses own multisig threshold; normal participant, not admin/owner/governance |
| 7 | Intended/by-design behavior | Generic (design intent) | FAILS | No NatSpec/comment sanctions duplicate ms inputs; key-image dedup shows clear intent to prevent input reuse — multisig simply omitted |
| 8 | Wallet refuses to build such a tx → not exploitable | Adversarial (construction) | FAILS | Wallet `generate_tx_balance_proof` refusal is wallet-side only; attacker hand-crafts the raw tx; consensus accepts it |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — every cited file, function, and line exists; description internally consistent (balance double-count ↔ inflation impact).
- **Step 2 (Privileged Roles)**: NO_ISSUE — no admin/owner/governance/operator role in the attack path; attacker acts with a multisig output they legitimately co-own. No severity cap applied.
- **Step 3 (Generic Check)**: design-intent, access-gating, and unreachable-state categories all evaluated → none HOLDS.
- **Step 4 (Adversarial Check)**: 2 independent opus refutation agents targeting (a) signature reuse and (b) balance-proof/reachability → both returned FAILS (could not refute). Direct orchestrator trace confirms 8/8 mechanism links. PoC integrity verified (no `src/` changes; real-consensus replay).
- **Final Severity**: Critical (confirmed; no adjustment).

## Honest scope caveat (does not affect verdict)
Realized exploitation on the *current* post-HF4 mainnet requires an existing pre-HF4 `txout_multisig`/escrow output whose signature threshold the attacker can assemble (own multisig, or an escrow whose release condition they meet). This is an attacker-controlled-source precondition, not a permissionless-against-arbitrary-victim one — but it does not block the inflation: a party legitimately able to spend an A-valued multisig output can mint/realize ~K·A from it (theft of escrow-locked funds + supply inflation). The team should confirm the on-chain count of spendable pre-HF4 multisig/escrow outputs to finalize the realized blast radius, and apply the recommended intra-tx `multisig_out_id` dedup (plus making the connect-time re-spend mark abort, and covering the alt-chain path), gated behind a hardfork boundary.
