# ISSUE-2: A pegout gets signed with another pegout's input amounts during federation migration, freezing the withdrawal and stalling the peg

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High
**Original Claimed Severity**: Not stated as a tier; described as "temporary freezing of funds on the peg-out side + halt of pegout processing and of the federation change"
**Pipeline Exit Point**: Step 4 (ran to completion; no early exit, no judge triggered — zero invalidation reasons held)
**Confidence**: HIGH

> Re-validation of a revised report. A prior run of this issue is at `ISSUE-1.md`. This run used a
> fresh 6-checker adversarial pass and reached the same verdict (VALID / High) via independent
> evidence, including two pieces the prior run did not have: on-chain confirmation of the live
> mainnet federation's script type, and rskj's own upstream mainnet-constants tests.

## Summary
`ReleaseCreationInformation.decodeUtxoOutpointValues()` selects a pegout's segwit input amounts with
`.findFirst()` over the creation receipt's logs, matching only `topic[0]` (the event signature) and
never `topic[1]` (the pegout's own `btcTxHash`). Because rskj's `updateCollections()` can emit two
`pegout_transaction_created` events into one receipt, the batched user-withdrawal pegout is signed
with the migration pegout's amounts. All six adversarial invalidation reasons — three generic, three
issue-specific — were checked against real source and **all six failed**. The issue is confirmed
valid at High.

## Location
- `src/main/java/co/rsk/federate/signing/hsm/message/ReleaseCreationInformation.java:44-52` (defect)
- Propagation: `SegwitSigHashCalculatorImpl.java:28`, `PowHSMSignerMessage.java:119-126`,
  `PowHSMSignerMessageBuilder.java:37`, `BtcReleaseClient.java:437`
- Reachability (rskj, bundled): `BridgeSupport.java:1040-1054`, `:1447`, `:1624-1646`

## Justification

**Step 1 (sweep)** — every claim in the report was verified against real source. The defect exists
verbatim at HEAD (`VETIVER-9.0.2.0-120-gddaa97e`). `git log --all` shows **no upstream fix** on any
branch; the file was refactored twice (`68bf4d8`, `1ccc375`) without ever adding correlation.

**Step 2 (privileged roles)** — a federation change is admin-triggered, but it is a *legitimate,
intended* operation and the federators sign correctly; the code misbehaves. Per the trusted-role
carve-out this is a code defect, not admin abuse. **No severity cap applied.**

**Step 1.5 (external research)** — all three externally-dependent claims verified TRUE against
primary sources:
- PowHSM only **range-checks** the host-supplied `outpointValue` ("must be > 0 and <=
  0xffffffffffffffff"); its `auth` receipt-proof authorizes the *pegout*, not the *amount*. It signs
  whatever the host provides.
- BIP143 commits the spent input's value. The BIP's own rationale states a wrong value yields an
  invalid signature and "no funding might be lost" — which independently corroborates the reporter's
  "not theft, not inflation" framing.
- RSKIP305 (segwit PowPeg) activated on **mainnet** at block 8,052,200 (Reed 8.0.0, ~2025-10-01).

**Steps 3B/4B — all six invalidation reasons FAILED.** The two decisive findings:

1. **The two-event receipt is rskj's own tested, intended behaviour under MAINNET constants.**
   `rskj-core/src/test/java/co/rsk/peg/BridgeSupportPegoutTransactionCreatedEventTest.java:227`
   (`updateCollections_whenPegoutMigrationAndBatchAreCreated_shouldLogPegoutTransactionCreatedEvent`)
   funds both the retiring and active federations, calls `updateCollections` **once**, and asserts
   **two** `logPegoutTransactionCreated` events (`:339-340`). Separately,
   `BridgeSupportProcessFundsMigrationTest.java:248` asserts a migration creates a pegout on *every*
   `updateCollections`. Both files are unmodified upstream. This destroys the strongest objection to
   the report — that its PoC only worked because regtest constants were tweaked.

2. **The live mainnet federation is segwit — verified on-chain, not from docs.** Bridge RPC returns
   federation `3GX89qzyQVaJqUJjq5noZbLJEHuYDvVrHq`, created at RSK block **8,517,961** (after
   `reed800` = 8,052,200). A real Bitcoin spend from it carries a `0020…` P2SH redeemScript with an
   8-item witness and a 5-of-9 ERP witnessScript — textbook P2SH-P2WSH. The segwit path is live.

**Severity.** Impact is High: the RBTC is irreversibly debited at request time
(`TransactionExecutor.java:396-397`), the request is popped from the queue and its UTXOs consumed
(`BridgeSupport.java:1546-1547`), and **no Bridge method can cancel, re-issue, or evict** a stuck
`pegoutsWaitingForSignatures` entry — the only removal is at `:1747` after a full signature quorum.
Likelihood is Medium: it requires a migration in flight — a recurring scheduled event (federation
changes observed at blocks 7,069,806 / 7,781,198 / 8,147,322 / 8,517,961) with a ~3.67-day window
each. High × Medium = **High**. It is correctly **not Critical**: BIP143 guarantees no theft or
inflation, and recovery is a node-only 5-of-9 binary rollout with no hard fork and no consensus
change.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | UP-5 Requires multiple low-probability events to coincide | Step 3 (Generic) | **FAILS** | No mutual-exclusion guard at `BridgeSupport.java:1040-1054`. Migration emits a pegout on *every* `updateCollections` (capped at 50 inputs), proven by rskj's own mainnet test `BridgeSupportProcessFundsMigrationTest.java:248`. Trigger is also publicly steerable: `updateCollections` is permissionless and `getNextPegoutCreationBlockNumber`/`getQueuedPegoutsCount` are open view calls. |
| 2 | US-4 Sequence blocked by intermediate checks | Step 3 (Generic) | **FAILS** | Links 1-5 CONFIRMED unconditionally; both siblings share the RSKIP375 key (`:1263`/`:1542`→`:1626`). The two checks that fire (Bridge ECDSA verify, collision guard) are the *mechanism of harm*, not blockers. Only link 6 (permanent halt) is conditional (~50%, pre-RSKIP559 `HashSet` promotion order). |
| 3 | EG-5 Existing input validation prevents it | Step 3 (Generic) | **FAILS** | No pruning, no re-correlation, no `outpointValues.size()` vs input-count check anywhere. The one btcTxHash correlation (`ReleaseCreationInformationGetter.java:162-163`) resolves the *receipt*, not the *log*, so it is a no-op here. Backstops exist but only change the failure mode. |
| 4 | Segwit gating makes the defect inert | Step 4 (Specific) | **FAILS** | Live mainnet federation confirmed P2SH-P2WSH on-chain. Bug fires in *both* migration directions because `processPegoutRequests` always builds the batch from the **active** (segwit) federation, while `processReleaseTransactionInfo` emits the migration's event with no witness gate. |
| 5 | Active-federation balance gate blocks co-occurrence | Step 4 (Specific) | **FAILS** | Premises correct (batch spends active-only; new fed starts empty) but the conclusion dies on the timeline: active fed is fundable ~16.7 h in via pegins, ~50 h via migration outputs, inside an 88 h window. The gate also *inverts* — it returns before `setNextPegoutHeight` (`:1512-1515` vs `:1556`), freezing the pegout window open so the batch fires on the first solvent `updateCollections`. Refuted outright by rskj's own test at `BridgeSupportPegoutTransactionCreatedEventTest.java:227`. |
| 6 | Severity overstated (liveness/ops-grade, self-resuming) | Step 4 (Specific) | **FAILS** | All premises verified true, but they argue *for* High: "recoverable but requiring urgent coordinated intervention" is the literal High tier, and a 5-of-9 emergency HSM-operator rollout is not routine ops. RBTC burned at request time with zero user recourse. |

## Corrections and strengthening for the report

Nothing below invalidates the finding; all of it makes the submission more accurate and harder to
reject.

1. **The invalid signature never reaches Bitcoin — it is rejected at the Bridge.** `addSignature`
   re-derives the sighash from `provider.getReleaseOutpointsValues(btcTx.getHash())` — the correctly
   btcTxHash-keyed copy — and throws `SignatureException` on verify failure, returning with **zero**
   state mutation (`BridgeSupport.java:1859-1887`, `:1844-1849`). The report says "Bitcoin (and the
   Bridge's `addSignature` re-derivation) verify against `sighash(real_amount)`"; lead with the
   Bridge, since Bitcoin never sees the transaction. Note the irony worth citing: rskj stores these
   values keyed by btcTxHash and uses that key correctly — powpeg-node had the correct key available
   in `topic[1]` and simply did not use it.

2. **A second, harsher failure branch is missing from the report.** When the misattributed list is
   *shorter* than the batch pegout's input count — or empty, via the `orElse(Collections.emptyList())`
   at `ReleaseCreationInformation.java:51` — `SegwitSigHashCalculatorImpl.java:28` throws
   `IndexOutOfBoundsException`. It is reached from `validateTxIsNotAlreadySigned`
   (`BtcReleaseClient.java:437-440`) whose catch covers only `SignerException` (`:451`), so it escapes
   to the blanket `catch (Exception)` at `:300-302`, **skipping `signRelease` entirely** for that
   round. That aborts signing for **all** pegouts, including healthy unrelated ones, every block —
   and because `pegoutSignedCache.putIfAbsent` (`:490`) is never reached in this branch, it re-fires
   forever. This is a broader DoS than the report claims.

3. **The peg-halt is ~50/50, not unconditional — say so.** `RSKIP559` (the `BTC_TX_COMPARATOR`
   ordering) is `tbd1000` and inactive on mainnet, so `getNextPegoutWithEnoughConfirmations` falls
   back to raw `HashSet` iteration (`PegoutsWaitingForConfirmations.java:143-149`). If the *good*
   pegout is promoted first it signs, frees the key, and the halt is temporary. If the *bad* one wins,
   the halt persists until a patch. Stating this pre-empts the reviewer discovering it and treating
   the whole impact section as overclaimed. The **unconditional** floor is: one permanently frozen
   withdrawal plus a reverting `updateCollections` for as long as the first sibling is unsigned.

4. **There is a third emitter, and it does not need a migration at all.** `updateSvpState`
   (`BridgeSupport.java:1053`, settling at `:1144`/`:1184`) also reaches
   `processReleaseTransactionInfo`, emitting `pegout_transaction_created` *after* the batch pegout in
   the same receipt. SVP spend transactions spend the segwit active federation, so they are a second
   victim class — and this gives a co-occurrence path on any federation commit **without** a funds
   migration. This materially widens reachability beyond what the report claims.

5. **Cite rskj's own tests — this is the single strongest addition.** The report's biggest perceived
   weakness is that PoC 2 tweaked regtest constants, which invites "you manufactured the coincidence."
   `BridgeSupportPegoutTransactionCreatedEventTest.java:227-344` asserts two
   `pegout_transaction_created` events from one `updateCollections` under **mainnet** constants, and
   `BridgeSupportProcessFundsMigrationTest.java:248` asserts multi-call migration under mainnet
   constants. Both are unmodified upstream. Citing these converts the trigger from "reporter-induced"
   to "protocol-specified."

6. **Two factual errors to fix before submitting.**
   - The References section cites
     `src/test/java/co/rsk/federate/signing/hsm/message/ReleaseCreationInformationTest.java` — **this
     file does not exist**. Only `ReleaseCreationInformationGetterTest.java` and
     `PowHSMSignerMessageBuilderTest.java` do.
   - The PoC 1 listing in the report text contains
     `import static org.junit.jupiter.i.Assertions.assertNotEquals;` — a corrupted package that will
     **fail to compile**. (The file on disk is correct: `org.junit.jupiter.api.Assertions`.) A
     reviewer who copy-pastes the report's code hits a compile error on first try; fix the report text.

7. **The "not triggerable on demand" hedge is more conservative than the code warrants.** Within a
   migration window the trigger is steerable: `updateCollections` is permissionless, and
   `getNextPegoutCreationBlockNumber()` / `getQueuedPegoutsCount()` / `getActiveFederationCreationBlockHeight()`
   are unauthenticated view calls, so the migration burst and the 360-block pegout window are both
   computable days ahead. Keep the honesty, but state it as "not triggerable at an arbitrary time —
   but steerable to near-certainty *within* a scheduled migration window."

8. **Timing note.** `getRetiringFederationAddress()` currently returns empty — no migration is in
   flight as of this validation, so the bug is not live-exploitable at this instant. It arms at the
   next federation change. Worth stating, as it is the honest framing and does not weaken the finding.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — defect verified verbatim at HEAD; full propagation chain confirmed; no upstream fix on any branch.
- **Step 2 (Privileged Roles)**: NO_CAP — federation change is a legitimate admin operation, not abuse; trusted-role cap explicitly does not apply.
- **Step 1.5 (External Research)**: 3/3 claims VERIFIED TRUE (PowHSM range-check-only, BIP143 amount commitment, mainnet segwit activation).
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, **0 held** → no early exit (2 HOLDS required).
- **Step 4 (Adversarial Check)**: 5 reasons generated, 2 dropped as duplicates of Step 3, 3 checked, **0 held** → Step 4C judge not triggered.
- **Final Severity**: High (Impact High × Likelihood Medium; not Critical — no theft/inflation, recoverable without a fork).
