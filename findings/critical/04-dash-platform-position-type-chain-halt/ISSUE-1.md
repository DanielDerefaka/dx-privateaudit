# ISSUE-1: Unvalidated `position` type in nested document-schema properties panics `try_from_schema` → unauthenticated node shutdown + deterministic chain halt (Dash Platform)

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (full adversarial analysis + mechanical PoC re-execution)
**Confidence**: HIGH

## Summary
A nested document-schema property whose `position` is a zero-fraction float (`0.0`) passes the JSON meta-schema (`{type: integer, minimum: 0}`) yet panics the Rust parser `insert_values_nested` (`get_integer::<u64>(POSITION).expect("expected a position")`). The parse runs unconditionally (not gated by `full_validation`) and is reached in block-execution mode (`ValidationMode::Validator → full_validation = true`). With no `catch_unwind` in the block path and a panic hook that calls `cancel.cancel()`, a single crafted `DataContractCreate` deterministically crashes every validator processing it (chain halt), and any funded identity can crash any node via `check_tx`. Verified against `dashpay/platform` `4.0.0-rc.1` (latest, protocol version 12). **CONFIRMED VALID — Critical.**

## Location (all verified verbatim against 4.0.0-rc.1)
- Panic site: `packages/rs-dpp/src/data_contract/document_type/class_methods/try_from_schema/mod.rs:209-217` (`insert_values_nested`, `.expect("expected a position")`)
- Integer coercion (rejects `Value::Float`, `IntegerSizeError` for `>u64::MAX`): `packages/rs-platform-value/src/lib.rs:291-307` (`to_integer`)
- Meta-schema (no `maximum`, accepts zero-fraction float): `packages/rs-dpp/schema/meta_schemas/document/v1/document-meta.json:140-143`
- Unconditional nested call + top-level-only `full_validation` block: `try_from_schema/v1/mod.rs:240-309` (gated block 240-263 checks top-level continuity only via `?`; `insert_values_nested` called at 299). Same pattern in `v0/mod.rs:280` and `v2/mod.rs:291` (v2 delegates to V1 parser).
- `full_validation = true` for Validator: `data_contract_create/mod.rs:35-43`
- Panic hook (node shutdown), installed at runtime: `packages/rs-drive-abci/src/main.rs:629-634`, installed `main.rs:273`
- Non-graceful caller (matches only `Result::Err`): `data_contract_create/state/v0/mod.rs:189-196`

## Justification

Every factual claim in the report was checked directly against current code and **all hold**:

1. **Panic site present** — sort comparator at `mod.rs:209-217` uses `.expect("expected a position")` on `get_integer::<u64>(POSITION)`.
2. **`to_integer` rejects floats** — `Value::Float` falls to `other => Err(StructureError(...))`; `U128 > u64::MAX` → `IntegerSizeError`. Confirmed.
3. **Meta-schema accepts `0.0`** — `position: {type: integer, minimum: 0}`, no `maximum`. JSON-Schema "integer" accepts zero-fraction floats. **Mechanically confirmed**: `float_0.0` is accepted by `full_validation=true` validation yet panics.
4. **Unconditional & reaches block execution** — the `if full_validation` block validates only **top-level** position continuity (`v1/mod.rs:249-250`, safe `?`); the nested float is never examined there, and `insert_values_nested` runs unconditionally (`v1/mod.rs:299`). `ValidationMode::Validator` ⇒ `full_validation = true`.
5. **Version-independent** — contract-version map: v1→`try_from_schema:0` (v0 parser), v2/v3→`1` (v1 parser), v4→`2` (v2 parser, delegates to V1 at `v2/mod.rs:291`). ALL three reach the same unconditional `insert_values_nested.expect`. `LATEST_VERSION = PROTOCOL_VERSION_12`. Bug present on every protocol version → current mainnet is exposed regardless of active version.
6. **Fatal in production** — no `catch_unwind` in the production drive-abci block path (only occurrences are inside the author's PoC test module). Panic hook is installed (`main.rs:273`) and cancels the node on any panic. → node crash.
7. **Permissionless** — no allowlist/identity-type/system gate on `DataContractCreate`; validation is identity-nonce + balance/fees only. The `AuthorizedActionTakers` references are intra-contract token/group governance, not a creation gate.

**Mechanical re-execution (by validator, current code, rustc 1.92):** PoC 1 (`position_type_confusion_experiment`) re-run →
`[float_0.0] full_validation=true => PANIC` at `try_from_schema/mod.rs:215: "value is not an integer, found float 0"`. The float is the **unique** variant that panics at `full_validation=true`; `missing`/`negative`/`>u64::MAX` get clean `Err` there. End-to-end PoC 2 (`process_raw_state_transitions`) and multi-MN PoC 3 are the author's executed demonstrations; PoC 1's `full_validation=true` panic plus the verified call-chain corroborate them.

**Severity = Critical.** For a BFT chain, a remotely-triggerable, permissionless, deterministic, network-wide validator crash is total liveness loss. The block-halt requires only a permissionless Evonode proposer — one Byzantine node halting the chain violates the BFT model and is not a trusted-actor downgrade. The `check_tx` flavor needs no special role.

## Caveats Investigated (user's explicit concern)
- **Admin/permission gated?** NO — contract creation is permissionless; no trusted-actor downgrade applies.
- **Out of scope?** OPEN CAVEAT (only one). Dash runs a **Bugcrowd** program; Evolution/Platform is stated in-scope at a high level, but the live brief's exact asset list, DoS-exclusion text, and reward tier are not publicly verifiable (brief returns 404 unauthenticated). Only quotable rule: "no mainnet exploit testing" (respected — PoC is local regtest/`TempPlatform`). Confirm eligibility/tier against the actual Bugcrowd brief before submission.
- **Already known by team?** NO public evidence — `.expect("expected a position")` still on `master`; no GHSA/CVE/issue/PR references it; closest item (#2703) is a distinct "schema too permissive" enhancement with no panic/DoS framing. No code comment acknowledges the panic risk (only the author's own PoC comments).
- **Mainnet exposed?** YES — Platform live on mainnet, permissionless contract creation, version-independent `.expect`.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | Meta-schema rejects `0.0` before the panic (validation ordering) | Adversarial (load-bearing) | FAILS | PoC re-run: `float_0.0` accepted at `full_validation=true`, then panics at mod.rs:215 |
| 2 | Latest protocol version uses a safe `v2` path | Adversarial | FAILS | `v4.rs try_from_schema:2` → `v2/mod.rs:291` delegates to `DocumentTypeV1::try_from_schema` → `insert_values_nested.expect` |
| 3 | Float can't survive on-the-wire deserialization | Adversarial | FAILS | Author PoC 2/3 go serialize→deserialize→`process_raw_state_transitions` and panic; platform serialization preserves `Value::Float` |
| 4 | Requires privileged/trusted role | Step 2 (Roles) | FAILS | No creation gate; permissionless. Block-halt needs only permissionless Evonode → BFT-model violation, no downgrade |
| 5 | Panic is caught (not a real crash) | Adversarial | FAILS | No `catch_unwind` in production block path; panic hook installed (main.rs:273) cancels node |
| 6 | Already fixed/known/duplicate | Step 1.5 (Research) | FAILS | `.expect` present on master; no advisory/issue/PR; #2703 distinct |
| 7 | DoS-only ⇒ lower severity | Step 4 (Severity) | FAILS | Deterministic network-wide BFT chain halt = Critical (total liveness loss) |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — location/description/impact all present; every referenced file/line verified present in `/Users/dx/Documents/audit/platform` (4.0.0-rc.1).
- **Step 2 (Privileged Roles)**: NO_ISSUE — `DataContractCreate` permissionless; no trusted-actor cap.
- **Step 1.5 (External Research)**: Bugcrowd scope UNVERIFIABLE (brief gated); mainnet-exposed CONFIRMED; not-a-known-duplicate CONFIRMED; no public Platform audit found.
- **Step 3/4 (Adversarial)**: 7 invalidation reasons tested, all FAIL. Crux (validation ordering) settled by mechanical PoC re-execution.
- **Final Severity**: Critical (unchanged from claimed).
