# ISSUE-2: Unvalidated `position` type in nested document-schema properties panics `try_from_schema` → deterministic chain halt

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full adversarial invalidation pass; no reason held)
**Confidence**: HIGH

## Summary
A nested document-schema property carrying `position: 0.0` (a zero-fraction **float**) passes the JSON document meta-schema (`integer` accepts zero-fraction floats) but panics the Rust parser at `insert_values_nested`'s `get_integer::<u64>(POSITION).expect("expected a position")`. The parse runs unconditionally in `full_validation = true` (block execution), no `catch_unwind` protects the path, and the global panic hook calls `cancel.cancel()` — so a single malicious evonode proposer including such a `DataContractCreate` in a block deterministically crashes every validator that executes it (network-wide chain halt). Independently re-verified against pristine upstream source at **v4.0.0-rc.1**; every code claim holds.

## Location
- Panic site (PRISTINE upstream): `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs:209-217` (`insert_values_nested` sort comparator)
- Integer reader rejecting floats: `packages/rs-platform-value/src/lib.rs:291-307` (`Value::to_integer`)
- Meta-schema `position`: `packages/rs-dpp/schema/meta_schemas/document/v1/document-meta.json:140-143` (`{type: integer, minimum: 0}` — no `maximum`, no float exclusion)
- Unconditional nested call + gated continuity check: `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/v1/mod.rs:240-309` (meta-schema validate at :175-177)
- `ValidationMode::Validator => true`: `packages/rs-drive-abci/.../data_contract_create/mod.rs:40-47`
- Non-graceful caller (catches only `Result::Err`): `packages/rs-drive-abci/.../data_contract_create/state/v0/mod.rs:413-429`
- Panic hook → node shutdown: `packages/rs-drive-abci/src/main.rs:626-634` (installed at :273)
- JSON-Schema validator (decisive): `jsonschema` 0.18.0 dashpay fork commit `aacc1ab`, `jsonschema/src/keywords/type_.rs:374-376` — `is_integer` returns true for `0.0`
- Float→JSON conversion (no normalization): `packages/rs-platform-value/src/converter/serde_json.rs:140`

## Justification
Independent verification (two deep-trace agents + direct source spot-checks) confirmed every link against the pristine upstream tree at `v4.0.0-rc.1` (branch `v3.1-dev`):

1. **The panic is real and in production code.** `try_from_schema/mod.rs:209-217` uses `.expect("expected a position")` in the *nested*-property sort comparator. `Value::to_integer` (lib.rs:291-307) routes `Value::Float` to the catch-all `Err` arm, so `.expect()` panics on a float. The file containing the panic site is **not** in the auditor's local modifications (`git status` shows only test-bearing files modified) — the vulnerable line is upstream-pristine and unfixed.

2. **The float reaches the panic in block execution (Critical path).** In the Validator path, `transform_into_action` → `try_from_platform_versioned(full_validation=true)` → `try_from_schema/v1`. The document meta-schema is validated **first** (v1/mod.rs:175-177) and **accepts** the float, then `insert_values_nested` is called **unconditionally** (v1/mod.rs:299) and panics. Decisively: the `jsonschema` fork's `is_integer` (`type_.rs:375`) is `num.is_u64() || num.is_i64() || num.as_f64()...fract() == 0.` → for `0.0` returns **true**; and `Value::Float` converts to `serde_json::Number::from_f64` with **no** int normalization (serde_json.rs:140), so the validator sees a float-typed `0.0` that satisfies `{"type":"integer"}`. Early `validate_basic_structure`/`validate_advanced_structure` never touch document schemas, so nothing rejects the float earlier.

3. **The panic is uncaught and fatal.** No `catch_unwind` exists in the production block-execution or check_tx path (only `#[cfg(test)]` occurrences). The global `std::panic::set_hook` (main.rs:630) fires at panic time, before unwinding, calling `cancel.cancel()` on the process-wide shutdown token — so even a hypothetical higher `catch_unwind` could not save the node. The ABCI server is an in-process blocking `tenderdash_abci` loop with no tower/tonic panic-to-response middleware. The immediate caller's `match result { Err(...) }` (state/v0/mod.rs:413-429) only handles `Result::Err`, not panics.

4. **Reachability / precondition.** Permissionless-but-authenticated: signature + identity-existence checks run before the parse, so the attacker self-signs with their own registered, funded identity (registration is permissionless via a Core asset lock). `DataContractCreate` has `has_is_allowed_validation() == false` — no spork/allowlist/governance gate. For the block-halt variant the attacker must additionally be a block proposer (evonode); a single Byzantine proposer crafts the block directly in `PrepareProposal` (bypassing its own check_tx) and all validators crash on `ProcessProposal`/`FinalizeBlock`. The panic precedes fee charging and commit, so the attack is free and infinitely repeatable.

5. **On-the-wire feasibility.** The float can only exist in the *serialized* contract form (runtime construction would itself panic); `document_schemas` is a `BTreeMap<String, Value>` whose serialization preserves `Value::Float`. PoC 2 round-trips it (build valid contract → overwrite schemas → re-sign → `process_raw_state_transitions`), which is exactly the validator block-execution entry.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | "DoS / resource exhaustion out of scope" | Generic library | FAILS | Deterministic network-wide **consensus liveness halt** (total network shutdown requiring coordinated patch+restart), not app-layer DoS — canonical Critical for an L1. |
| 2 | "Requires privileged/trusted actor (evonode) → downgrade" | Step 2 roles | FAILS | Masternode/evonode registration is permissionless; BFT security model *must* tolerate Byzantine validators. A single Byzantine proposer halting the network is a catastrophic break of the fault model, not a trusted-actor rug. Not in the FULLY_TRUSTED set (owner/governance/timelock/multisig). No downgrade. |
| 3 | "Already known / already fixed" | Generic | FAILS | `.expect("expected a position")` is pristine upstream at v4.0.0-rc.1; the only references are the auditor's own uncommitted PoC tests. No upstream fix; meta-schema still `{integer, minimum:0}`. |
| 4 | "Float can't survive deserialization / not reachable" | Adversarial (Step 4) | FAILS | `basic`/`advanced` structure validation never parse schemas; serialization preserves `Value::Float`; PoC 2 demonstrates end-to-end panic via `process_raw_state_transitions`. |
| 5 | "Honest proposer's own check_tx rejects it → never enters a block" | Adversarial | FAILS | Byzantine proposer authors the block directly in `PrepareProposal` without self-check_tx; controls its own tx inclusion. |
| 6 | "Meta-schema rejects the float in Validator mode → no chain halt" | Adversarial (decisive) | FAILS | `jsonschema` fork `is_integer` accepts `0.0` (`fract()==0.0`); conversion preserves float type. Confirmed at source. |
| 7 | "Some catch_unwind / ABCI middleware converts panic to a reject" | Adversarial | FAILS | No catch_unwind in path; in-process tenderdash loop; hook fires before unwind regardless. |
| 8 | "Missing input validation on untrusted data" (root-cause check) | Adversarial | CONFIRMS | This *is* the root cause — confirms, does not invalidate. |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — location, mechanism, and impact all present and internally consistent; referenced files exist on disk at `/Users/dx/Documents/audit/platform` (note: the issue targets `dashpay/platform`, a different repo than the `dashpay/dash` working directory).
- **Step 2 (Privileged Roles)**: evonode/proposer present in attack path but is an UNTRUSTED permissionless consensus participant (BFT Byzantine-fault model) — NOT a FULLY_TRUSTED actor. No severity cap applied. No early exit.
- **Step 1.5 (External Protocol Research)**: N/A — no external protocol dependency; all behavior is in-scope Rust.
- **Step 3 + Step 4 (Generic + Adversarial Invalidation)**: 8 invalidation reasons tested (incl. the two decisive ones — meta-schema float acceptance and panic containment) via two independent deep-trace agents + direct source spot-checks of `jsonschema::is_integer` and the Float→JSON conversion. Zero reasons held. Judge verdict: VALID.
- **Final Severity**: Critical (Impact: total loss of chain liveness / network-wide deterministic validator crash; Likelihood: permissionless-authenticated precondition, deterministic, free to repeat). No downgrade.
