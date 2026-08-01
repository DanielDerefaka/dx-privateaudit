# ISSUE-1: Type confusion in legacy transaction post-condition-mode handling makes Leather display a false "no funds will leave your account" confirmation for an Allow-mode transaction

## Pipeline Result
**Verdict**: VALID
**Final Severity**: Critical
**Original Claimed Severity**: Critical
**Pipeline Exit Point**: Step 4 (all six checkers FAILED; Step 4C judge not triggered)
**Confidence**: HIGH

## Summary
The report is confirmed. On Leather's still-shipped legacy Stacks `transactionRequest` path, an
attacker-supplied JWT carrying `postConditionMode: "allow"` (string) defeats two display guards that
compare against the numeric `PostConditionMode.Allow` enum (`= 1`), while `@stacks/transactions@7.5.0`
coerces the same string to Allow mode at signing time. The approval screen therefore suppresses the
"This transaction can transfer any of your assets" warning **and** affirmatively renders a lock icon
with "No transfers (besides fees) will be made from your account or the transaction will abort." — for
a transaction broadcast with post-conditions unenforced. Six independent adversarial checks were run
against the finding; none held.

## Location
- `apps/extension/src/app/features/stacks-transaction-request/post-condition-mode-warning.tsx:13`
- `apps/extension/src/app/features/stacks-transaction-request/legacy-post-conditions/post-conditions.tsx:30`
- `apps/extension/src/app/features/stacks-transaction-request/legacy-post-conditions/no-post-conditions.tsx:16`
- `apps/extension/src/app/store/transactions/post-conditions.hooks.ts:33-35`
- `apps/extension/src/shared/utils/legacy-requests.ts:58-61`
- `apps/extension/src/app/common/transactions/stacks/generate-unsigned-txs.ts:59`
- `apps/extension/src/content-scripts/content-script.ts:77`
- `packages/provider/src/legacy-requests.ts:287-295`

## Justification

### The defect is real in the current published build
Every cited file and line was verified to exist with the quoted code intact. The load-bearing library
claim was confirmed **empirically** rather than from memory: the published `@stacks/transactions@7.5.0`
tarball was downloaded and read directly. `dist/postcondition.js:157-167` defines
`postConditionModeFrom()`, which maps `'allow' -> PostConditionMode.Allow (1)`, and
`dist/builders.js:171` shows `makeUnsignedContractCall` invoking it. The `??` fallback at
`generate-unsigned-txs.ts:59` is nullish-only, so the string survives it.

### Scope gate satisfied (this was the highest risk of disqualification)
The program admits **only the current published Chrome Web Store build**. A live query to Google's own
CRX update-check endpoint (`clients2.google.com/service/update2/crx`, extension id
`ldinpeekobnhjjdofggfgjlcehhmanlj`) returned `version="6.107.0"` /
`LDINPEEKOBNHJJDOFGGFGJLCEHHMANLJ_6_107_0_0.crx`, released 2026-07-23. This matches the report's tested
version and the repo checkout exactly; no newer release exists as of 2026-07-30. Source re-fetched at
the published tag `@leather.io/extension-v6.107.0` confirms all three defect sites present and
unmitigated in the shipped artifact. (Note: chrome-stats.com cache data claiming "6.100.1" is stale and
contradicted by the authoritative endpoint.)

### Reachability is unconditional
`LeatherProvider.transactionRequest` is a live shipped method in `@leather.io/provider@1.6.32`
(`legacy-requests.ts:338-346` selects the real implementation for `platform: 'extension'`; only mobile
gets the placeholder throwers). The content script is injected at `matches: ['*://*/*']`, `all_frames:
true`, `run_at: 'document_start'` with no `externally_connectable` key and no origin allowlist, and its
`document.addEventListener` at `content-script.ts:77` is registered unconditionally — so a page can also
hand-dispatch the `hiroWalletStacksTransactionRequest` CustomEvent without any SDK. `background.ts:47`
routes legacy as the **first** dispatch branch. `legacyRequestRoutes` is mounted unconditionally at
`app-routes.tsx:319`. A Playwright e2e test (`tests/specs/transactions/transactions.spec.ts:76-90`)
drives this exact screen and asserts a real broadcast POST.

### The false reassurance genuinely renders
Traced precisely: `formatPostConditionState` returns `[]` both when the attacker sends
`postConditions: []` and when the field is omitted entirely. `[]` is truthy, so
`post-conditions.tsx:29` does not early-return; `hasPostConditions` is false and `isStxTransfer` is
false for `contract_call`, so `renderPostConditionsContent()` returns `<NoPostConditions />`. No
Suspense boundary engages (the hook is a pure `useMemo`, and the only suspending hook in the subtree is
never mounted with an empty PC list).

### The `IS_TEST_ENV` confound does not exist
`PostConditionModeWarning` has **no `IS_TEST_ENV` guard at all**, so numeric Allow renders the warning in
every build environment. For the string form, `mode === PostConditionMode.Allow` is false and
short-circuits the conjunction at `post-conditions.tsx:30`, making the flag irrelevant. Consequently the
combination the report observed — warning **absent** and lock panel **present** — is impossible for
numeric Allow under any build, and uniquely identifies the string form. The store artifact ships
`WALLET_ENVIRONMENT: production` (`.github/workflows/extension:publish-extensions.yml:66`).

### A deliberate safety control was defeated
`post-conditions.tsx:30` encodes the intent "never show a post-condition panel in Allow mode," and
CHANGELOG PR #1625 records the warning being added deliberately: *"adds a warning for any contract call
that is set to ALLOW mode -- if a user is signing a transaction with ALLOW mode set, any post conditions
displayed will have no effect."* A single type confusion defeats both controls at once. This is a
defeated safety control, not a UX gap — so the out-of-scope clause "approving a transaction after a
**clear and accurate** confirmation screen" does not reach it. The screen is accurate about identity
(contract, function, decoded args, origin) but makes an affirmatively inverted safety claim.

### The team already knew both encodings occur
`rpc-stacks-transaction-request/stacks/post-conditions/post-conditions-details.layout.tsx:16,22` types
the prop `PostConditionMode | PostConditionModeName` and checks
`postConditionMode === PostConditionMode.Allow || postConditionMode === 'allow'`. The modern RPC schema
is string-**only** (`_stacks-helpers.ts:22-24`). The normalizer `rpcPostConditionModeToEnum` exists in a
file whose own comment reads *"These were used with legacy tx requests, so we have to keep them until we
are able to remove that code entirely."* The dual check was simply never backported to the two legacy
guards.

### Severity: Critical, unreduced
Deprecation does **not** narrow the victim population, because the attacker *is* the dApp — it chooses
the legacy API precisely because it is the weaker path. Critically, the `appPermissions` gate is written
by the **modern** `stx_getAddresses` connect flow keyed on the same hostname, so a site that only ever
used the current RPC API has already unlocked the legacy path. Permission-gating is not mitigating: the
program names "Malicious interactions with an already-connected wallet — Submitting malicious
transactions" as Critical, i.e. an already-connected origin is the *assumed precondition* of that
category. Account scoping is real (`selectCurrentAccount` pins the signer to the connected
`accountIndex`/`fingerprint`; Clarity cannot move a non-signer's assets) but "bounded" means the complete
drain of one account's STX, every FT, and every NFT — and `showSwitchAccount` is enabled on this screen,
letting the victim re-target the same false panel at another account.

## Invalidation Reasons Tested

| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|------------------|
| 1 | OS-4 — deprecated/decommissioned component | Step 3 (Generic) | FAILS | Label-only deprecation. Live shipped provider method, unconditional route, e2e test asserts real broadcast. No flag, no kill switch. |
| 2 | OS-3 — unreachable from any deployed entry point | Step 3 (Generic) | FAILS | `*://*/*` content script, no `externally_connectable`, SDK-free DOM dispatch works. Modern `getAddresses` connection unlocks the legacy gate. |
| 3 | EG-5 — upstream input validation blocks the vector | Step 3 (Generic) | FAILS | Zero runtime validation on the whole legacy chain. All normalization sites are modern-path only. TS types erased at runtime. |
| 4 | PoC artifacts non-discriminating / `IS_TEST_ENV` confound | Step 4 (Adversarial) | FAILS | `PostConditionModeWarning` has no `IS_TEST_ENV` guard, so the observed warning-absent + panel-present combination is impossible for numeric Allow in any build. |
| 5 | Root cause mischaracterized; also affects Originator=3 | Step 4 (Adversarial) | FAILS | Both encodings coexist within the legacy flow. Originator passes the guards but is *safer* (denies unspecified transfers for the origin) — a non-defect. |
| 6 | Severity overstated — gated origin, bounded account | Step 4 (Adversarial) | FAILS | Facts true, none reduces severity. Affirmatively false claim defeats the "clear and accurate" exclusion; connected-origin is the assumed precondition of a Critical category. |

## Caveats and triage notes (do not affect the verdict)

1. **Impact-category mislabel.** The report leads with "Tampering with transactions between user approval
   and signing/broadcast." This is the *weaker* fit — nothing mutates after approval; the user approved
   exactly the payload that was signed. The squarely-fitting Critical categories are "Malicious
   interactions with an already-connected wallet — Submitting malicious transactions" and "Wallet
   interaction modification resulting in financial loss." Adjacent mislabel; severity unchanged.
2. **Two of four PoC artifacts are non-probative in isolation.** The on-chain txids do not discriminate
   the bug (numeric `postConditionMode: 1` produces an identical transaction), and the Node script only
   exercises `postConditionModeFrom` inside the library — it never touches the React components. The
   screenshot and the source reading carry the claim. Triage should confirm the screenshot shows the
   warning absent *and* the lock panel present together.
3. **Report understates asset scope.** Allow mode permits NFT transfers too, not only STX and SIP-010
   fungible tokens.
4. **Report text is partially garbled** (`post-condde-warning.tsx`, `makeUnsignedContractCall({
   postConditionMode: 'allowostConditionMode === 1`, "causes demted fund loss"). Cosmetic; the References
   section carries the correct paths.
5. **Prior-disclosure check is incomplete.** No GitHub Security Advisory exists for `leather-io/mono` or
   `leather-io/extension`, and no commit/PR addresses this. Open issue #2326 concerns copy on the
   *modern* path, not this bug. However, the HackerOne program page is client-rendered and could not be
   read — **the HackerOne disclosure list remains UNVERIFIED**, so duplicate status cannot be fully ruled
   out.

## Recommended remediation
Normalize `postConditionMode` at the legacy payload boundary in
`getLegacyTransactionPayloadFromToken` (reuse `rpcPostConditionModeToEnum`, rejecting unknown values),
so display and signer read the same value. Alternatively, backport the modern approver's dual check to
both legacy guards. Add a regression test asserting that a legacy `contract_call` with
`postConditionMode: "allow"` renders the Allow warning and does **not** render `NoPostConditions`.
Consider also making the guards exhaustive over the enum rather than single-equality against `Allow`.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all 10 referenced files exist; quoted code accurate; in-repo
  extension version 6.107.0 matches the PoC.
- **Step 2 (Privileged Roles)**: SKIPPED — no privileged role in the attack path. The attacker is an
  already-connected web origin, which the program names as an in-scope attacker. No `MAX_SEVERITY` cap.
- **Step 1.5 (External Research)**: Chrome Web Store build confirmed 6.107.0 via live CRX endpoint;
  defect sites confirmed at the published tag; no advisory/PR fixing it; `@stacks/connect@7.4.0` does no
  runtime coercion and the token is an unsecured JWT.
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, **0 held**, 0 confirmed. No early exit
  (threshold is >= 2 HOLDS).
- **Step 4 (Adversarial Check)**: 5 reasons generated, 2 filtered as duplicates of Step 3A selections
  (deprecation shim; marginal-deterrence overlap), 3 checked, **0 held**. Step 4C neutral judge **not
  triggered** — no checker returned HOLDS.
- **Final Severity**: Critical (unchanged from claimed).
