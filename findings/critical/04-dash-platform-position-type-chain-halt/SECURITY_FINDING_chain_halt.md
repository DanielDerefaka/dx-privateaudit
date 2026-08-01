# [CRITICAL] Deterministic chain halt + unauthenticated node-shutdown via type-confused `position` in a nested document-schema property

**Target:** `dashpay/platform` @ `v4.0.0-rc.1` (commit cloned 2026-06-10)
**Component:** `packages/rs-dpp` — data-contract document-type schema parsing (consensus path)
**Severity:** Critical (network-wide liveness failure)
**Status:** Confirmed mechanically (3× `[POC-PASS]`), including end-to-end through the real block-execution pipeline against a live test platform. **Not disclosed to Dash yet** — whitehat, regtest-only, never broadcast.

---

## Summary

`DocumentType::try_from_schema` builds a document type from a contract's JSON schema. For **nested** object properties it sorts the sub-properties by their integer `position` using:

```rust
// packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs:209-217
sorted_properties.sort_by(|(_, value_1), (_, value_2)| {
    let pos_1: u64 = value_1.get_integer(property_names::POSITION).expect("expected a position"); // L211
    let pos_2: u64 = value_2.get_integer(property_names::POSITION).expect("expected a position"); // L214
    pos_1.cmp(&pos_2)
});
```

`get_integer::<u64>()` returns `Err` (→ `.expect()` **panics**) when `position` is:
- missing,
- a **float** (e.g. `0.0`), because `to_integer` only accepts integer `Value` variants and rejects `Value::Float` (`rs-platform-value/src/lib.rs:302-305`),
- negative, or `> u64::MAX` (`IntegerSizeError`).

The document **meta-schema** only constrains `position` as `{"type": "integer", "minimum": 0}` (`schema/meta_schemas/document/v1/document-meta.json:140-143`). JSON-Schema "integer" **accepts a zero-fraction float** (`0.0`) and has **no upper bound**. So a nested `position: 0.0`:

1. **Passes** the meta-schema (so it is NOT rejected during full validation), but
2. **Panics** `get_integer::<u64>()` in `insert_values_nested`, which runs **unconditionally** (it is *not* gated by `full_validation`; called at `try_from_schema/v1/mod.rs:299`), *after* the meta-schema.

This panic fires in **`full_validation = true`** — the validation mode used during **block execution** (`ValidationMode::Validator`). There is **no `catch_unwind`** anywhere in the block-processing pipeline, and the production panic hook shuts the node down:

```rust
// packages/rs-drive-abci/src/main.rs:629
std::panic::set_hook(Box::new(move |info| {
    tracing::error!(panic=%info, "panic");
    cancel.cancel();   // ANY panic => the whole drive-abci node shuts down
}));
```

> Note: `sort_by` only invokes its comparator when there are **≥ 2** nested sub-properties, so the trigger requires an object property with at least two nested sub-properties (one carrying the poison `position`).

## Impact (two attack flavors)

1. **Deterministic chain halt (proposer).** A malicious block proposer (any active masternode/validator) includes a `DataContractCreate` whose document schema has a nested `position: 0.0`. Every validator runs `process_raw_state_transitions` → `transform_into_action` (Validator, `full_validation=true`) → `try_from_schema` → **panic** → the panic hook shuts the node down. All validators crash on the same block → the chain halts until every node is patched.

2. **Unauthenticated node-shutdown DoS (any user).** In `check_tx` the contract is parsed with `full_validation=false` (meta-schema skipped), so **missing / float / negative / huge** nested positions all panic. Any node that runs `check_tx` on a submitted/gossiped transition shuts down. Cheap, repeatable, no prerequisites, no funds beyond a normal identity.

`negative` and `> u64::MAX` are caught by the meta-schema at `full_validation=true` (so they are "only" the check_tx flavor); the **float** slips through the meta-schema and reaches **block execution** — that is the chain-halt path.

## Proof of Concept (mechanical, `[POC-PASS]`)

All three are passing Rust tests added to the repo (full `cargo` build, real consensus code):

1. **Parse layer** — `packages/rs-dpp/.../try_from_schema/v1/mod.rs`, test `position_type_confusion_experiment`:
   `[float_0.0] full_validation=true => *** PANIC ***` while `[valid_u64] => Ok`, `[missing|negative|huge] full_validation=true => clean Err`. Panic at `try_from_schema/mod.rs:215`: `value is not an integer, found float 0`.

2. **Exact block-exec conversion** — same file, test `block_execution_conversion_panics_on_float_position`:
   `DataContract::try_from_platform_versioned(serialized_contract, /*full_validation*/ true, …)` (the call `transform_into_action` makes) **panics**.

3. **End-to-end, live platform** — `packages/rs-drive-abci/.../data_contract_create/mod.rs`, test `float_nested_position_halts_block_execution_security_poc`:
   builds a funded identity on a `TempPlatform`, constructs a **validly-signed** `DataContractCreate` carrying the float position, and feeds it to **`process_raw_state_transitions`** (the real `ProcessProposal`/`FinalizeBlock` entry). Result: **PANIC** → in production the panic hook shuts the validator down.

Run:
```
cargo test -p dpp        --features validation --lib position_type_confusion_poc -- --nocapture
cargo test -p drive-abci --lib float_nested_position_halts_block_execution_security_poc -- --nocapture
```

## Root cause

A type-confusion / under-validation gap: the meta-schema's notion of a valid `position` (any non-negative JSON "integer", including a zero-fraction float, unbounded) is **looser** than what the parser requires (`u64`), and the parser handles the mismatch with `.expect()` (panic) instead of returning a consensus error — on a code path that runs in block execution.

## Recommended fix (minimal)

Make `insert_values_nested` return a consensus error instead of panicking. `sort_by` can't return `Result`, so pre-extract positions fallibly:

```rust
// packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs (insert_values_nested)
let mut keyed: Vec<(u64, &(Value, Value))> = Vec::with_capacity(properties.len());
for prop @ (_, value) in properties.iter() {
    let pos: u64 = value.get_integer(property_names::POSITION).map_err(|_| {
        DataContractError::InvalidContractStructure(
            "nested document property `position` must be a non-negative integer that fits u64".to_string(),
        )
    })?;                                  // returns Result<(), DataContractError> -> `?` is valid here
    keyed.push((pos, prop));
}
keyed.sort_by_key(|(pos, _)| *pos);
let sorted_properties: Vec<_> = keyed.into_iter().map(|(_, prop)| prop).collect();
```

This converts every variant (missing/float/negative/huge) into a clean rejection on **both** the check_tx and block-execution paths. Recommended in addition: tighten the meta-schema `position` to reject non-integer numbers and bound it to `u64` (`maximum`), and audit the codebase for other `get_integer(...).expect(...)` on attacker-controlled values reachable from state-transition processing.

## Disclosure

Report privately to the Dash Platform security process before any public mention; do not broadcast the PoC transition to testnet/mainnet. All confirmation here was on a local `TempPlatform` / regtest-class harness only.
