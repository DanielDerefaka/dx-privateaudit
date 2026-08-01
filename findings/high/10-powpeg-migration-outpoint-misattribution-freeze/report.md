# A pegout gets signed with another pegout's input amounts during federation migration, freezing the withdrawal and stalling the peg

## Summary

During a federation migration the Bridge can create two pegouts in a single `updateCollections` transaction: the migration pegout and a batched user withdrawal. Both emit a `pegout_transaction_created` event into the same receipt. When a federator signs the user withdrawal, powpeg-node picks the segwit input amounts from the *first* such event in the receipt instead of the one that belongs to the transaction it is signing. The first event is the migration pegout, so the withdrawal is signed with the wrong input amounts. Segwit signatures commit the input amount (BIP143), so every federator produces the same invalid signature, the Bridge rejects it, and the withdrawal is stuck in `pegoutsWaitingForSignatures` — a map with no eviction path and no admin override. Once it is stuck, the Bridge's own guard against two pegouts sharing a signing-map key starts throwing on every following `updateCollections`, reverting the call and stalling pegout processing and the federation change.

The two-event receipt is not an inferred edge case: rskj's own test suite asserts it under mainnet constants (`BridgeSupportPegoutTransactionCreatedEventTest.java:227`).

No coins can be stolen — a wrong amount only makes the signature invalid, and the Bridge rejects it before anything reaches the Bitcoin network — but user funds are frozen and the peg-out side of the bridge stalls until the federators ship an emergency fix. Recovery requires a coordinated upgrade of a signing majority, though no hard fork or consensus change.

## Vulnerability details

The federator decodes the segwit input amounts for the pegout it is about to sign in `ReleaseCreationInformation`:

`src/main/java/co/rsk/federate/signing/hsm/message/ReleaseCreationInformation.java`

```java
private List<Coin> decodeUtxoOutpointValues() {
    return transactionReceipt.getLogInfoList().stream()
        .filter(this::isPegoutTransactionCreatedLog)   // matches topic[0] = event signature
        .findFirst()                                    // takes the FIRST match, whatever it is
        .map(LogInfo::getData)
        .map(this::decodePegoutTransactionEventData)
        .map(UtxoUtils::decodeOutpointValues)
        .orElse(Collections.emptyList());
}

private boolean isPegoutTransactionCreatedLog(LogInfo log) {
    Function pegoutTransactionCreatedEvent = BridgeEvents.PEGOUT_TRANSACTION_CREATED.getEvent();
    final byte[] pegoutTransactionCreatedSignatureTopic = pegoutTransactionCreatedEvent.encodeSignatureLong();
    boolean logHasTopics = !log.getTopics().isEmpty();
    return logHasTopics &&
        Arrays.equals(log.getTopics().get(0).getData(), pegoutTransactionCreatedSignatureTopic);
}
```

The `PEGOUT_TRANSACTION_CREATED` event carries the pegout's `btcTxHash` as an indexed parameter in `topic[1]`. `decodeUtxoOutpointValues()` never reads it. It only checks that the log is a `pegout_transaction_created` event at all, then takes the first one. When a receipt contains more than one such event, the wrong one wins.

The rest of the same class already knows how to match the right event. `ReleaseCreationInformationGetter.getInformationFromEvent()` correctly filters the `release_requested` event by its btcTxHash:

```java
boolean hasReleaseRequestEvent = Arrays.equals(logInfo.getTopics().get(0).getData(), releaseRequestedSignatureTopic);
if (hasReleaseRequestEvent && Arrays.equals(logInfo.getTopics().get(2).getData(), pegoutBtcTx.getHash().getBytes())) {
    ...
}
```

The amount path just skips that same correlation.

The wrong amounts flow straight into the signing message. `PowHSMSignerMessageBuilder` reads them from `releaseCreationInformation.getUtxoOutpointValues()`; `SegwitSigHashCalculatorImpl` uses `releaseOutpointsValues.get(inputIndex)` as the BIP143 `prevValue`; and `PowHSMSignerMessage.populateWithSegwitValues()` puts `outpointValues.get(inputIndex)` in the `outpointValue` field sent to the HSM.

### How two events end up in one receipt

`co.rsk.peg.BridgeSupport.updateCollections()` runs, in one RSK transaction:

```java
processFundsMigration(rskTx);   // may create a migration pegout
processPegoutRequests(rskTx);   // may create a batched user-withdrawal pegout
processConfirmedPegouts(rskTx);
...
updateSvpState(rskTx);          // may create an SVP spend tx — a third emitter
```

Both `migrateFunds()` (migration) and `processPegoutsInBatch()` (user withdrawals) reach the same emitter through `settleReleaseRequest() -> processReleaseTransactionInfo() -> eventLogger.logPegoutTransactionCreated(...)`. There is no mutual-exclusion guard between them: no early return, no "already created a pegout this call" flag, no shared state. So during a migration window with a pending withdrawal, one `updateCollections` receipt has the migration event first and the batch event second, each with a different btcTxHash and different amounts. Signing the batch pegout, `findFirst()` returns the migration event.

**This is not an inferred edge case — it is behaviour rskj asserts in its own test suite, under mainnet constants.** `rskj-core/src/test/java/co/rsk/peg/BridgeSupportPegoutTransactionCreatedEventTest.java:227`:

```java
void updateCollections_whenPegoutMigrationAndBatchAreCreated_shouldLogPegoutTransactionCreatedEvent(...)
```

It uses `bridgeMainnetConstants` / `federationMainNetConstants` (`:42-43`), funds the retiring federation (`:252`) **and** the active federation (`:258`), advances to `federationActivationAge + fundsMigrationAgeSinceActivationBegin + 1` (`:261-263`), calls `updateCollections` **once** (`:288`), and then asserts exactly the two-event receipt this report depends on:

```java
assertEquals(2, pegoutsWaitingForConfirmations.getEntries(activations).size());                            // :293
verify(eventLogger, times(1)).logPegoutTransactionCreated(pegoutBatchBtcTxHash, pegoutBatchTxOutpointValues); // :339
verify(eventLogger, times(1)).logPegoutTransactionCreated(migrationTxHash, migrationTxOutpointValues);        // :340
```

Relatedly, `BridgeSupportProcessFundsMigrationTest.java:248` —
`updateCollections_duringMigration_withMoreUtxosThanMaxInputs_whenCalledRepeatedly_shouldCreateAMigrationTxEachTime` —
asserts, again under `BridgeMainNetConstants`, that a migration creates a pegout on *every* `updateCollections` when the retiring federation holds more than `maxInputsPerPegoutTransaction = 50` UTXOs. Both files are unmodified upstream rskj.

So the two-event receipt is the protocol's specified, tested behaviour on mainnet parameters. powpeg-node is the component that fails to handle it.

#### A third emitter, which needs no migration at all

`updateSvpState(rskTx)` also runs inside the same `updateCollections` (`BridgeSupport.java:1053`) and also reaches `processReleaseTransactionInfo` for the SVP spend transaction (settling at `:1144` and `:1184`) — *after* `processPegoutRequests`. SVP spend transactions spend the active federation, which is segwit, so they are a second class of victim under the same defect.

This matters for scoping: it means a poisoned receipt does not strictly require a funds migration. Any federation commit that drives the SVP state machine while a user withdrawal batches in the same call produces the same two-event receipt. The migration path described in this report is the clearest and most impactful instance, not the only one.

### Why the signature is invalid

BIP143 commits the value of the input being spent into the sighash. The federator signs `sighash(migration_amount)` while the real input is worth `real_amount`, so the signature does not verify.

The rejection happens at the **Bridge**, not on the Bitcoin network — no malformed transaction is ever broadcast. `addSignature` re-derives the sighash from the Bridge's own copy of the outpoint values, which *is* correctly keyed by btcTxHash:

```java
// BridgeSupport.java:1859-1867
private Sha256Hash generateInputSigHash(BtcTransaction btcTx, int inputIndex) {
    if (!inputHasWitness(btcTx, inputIndex)) { return generateSigHashForLegacyTransactionInput(...); }
    return provider.getReleaseOutpointsValues(btcTx.getHash())   // keyed by btcTxHash — correct
        .map(releaseOutpointsValues -> releaseOutpointsValues.get(inputIndex))
        .map(prevValue -> generateSigHashForSegwitTransactionInput(btcTx, inputIndex, prevValue))
        ...
}

// BridgeSupport.java:1878
if (!federatorBtcPublicKey.verify(sigHash, decodedSignature)) { ... throw new SignatureException(); }
```

`processSigning` catches that and returns before recording anything (`BridgeSupport.java:1844-1849`), so a rejected signature mutates **no** state at all.

This is worth stating plainly because it sharpens the finding rather than weakening it: rskj stores these values keyed by btcTxHash and consumes them by btcTxHash. The correct key was available to powpeg-node the whole time, as indexed `topic[1]` on the very event it is reading — it simply is not used. The bug is a missing correlation on the off-chain side of an interface whose on-chain side gets it right.

The choice is deterministic, so every federator produces the same invalid signature. The pegout never reaches a valid quorum and stays in `pegoutsWaitingForSignatures`, from which the only exit in the entire codebase is `BridgeSupport.java:1747`, reached only after a full signature quorum. There is no eviction, no timeout, and no admin method to cancel or re-issue the entry.

### A second failure branch: the node throws before signing anything

The above describes what happens when the misattributed list is at least as long as the batch pegout's input count. When it is **shorter** — or empty, via the `orElse(Collections.emptyList())` fallback — the node does not produce a bad signature; it crashes the signing round.

`SegwitSigHashCalculatorImpl.java:28` does an unguarded `releaseOutpointsValues.get(inputIndex)`. This is first reached from `BtcReleaseClient.validateTxIsNotAlreadySigned` (`BtcReleaseClient.java:437-440`), whose `try` catches only `SignerException` (`:451`), and `tryGetReleaseInformation`'s handlers (`:371`, `:377`) cover only `HSMReleaseCreationInformationException`, `FederationCantSignException` and `FederatorAlreadySignedException`. The resulting `IndexOutOfBoundsException` therefore escapes the per-pegout loop entirely and lands in the blanket `catch (Exception)` at `BtcReleaseClient.java:300-302`, **skipping the call to `signRelease`**.

The consequence is broader than a single stuck withdrawal: no pegout is signed that round, including perfectly healthy unrelated ones. And because `pegoutSignedCache.putIfAbsent` (`:490`) is never reached on this path, the poisoned entry is never cached and is re-hit on every best block, indefinitely. Both mainnet transactions are capped by the same `maxInputsPerPegoutTransaction = 50`, so either ordering of list lengths is ordinary — meaning both branches are live.

### The PowHSM does not catch this

Production federators sign with a PowHSM, so the obvious question is whether the HSM re-derives the amount and hides the bug. It does not. The PowHSM authorizes the transaction (its txid corresponds to a pegout committed in RSK state, proven by the receipt merkle proof plus cumulative difficulty), but it does not validate the input amounts. The PowHSM protocol only range-checks the value it is given: "the outpoint value (i.e., amount of the UTXO) for the input that needs to be signed; must be > 0 and <= 0xffffffffffffffff." It then computes the BIP143 sighash from the host-supplied `outpointValue`. This is consistent with the threat model, because a wrong amount can only invalidate a signature, never move funds, so there is no reason for the HSM to re-derive it. The bug behaves the same with a real PowHSM as with the keyfile signers used in the on-chain PoC below.

### It cascades into a peg halt

The stuck pegout keeps its slot in `pegoutsWaitingForSignatures`, keyed by its creation `rskTxHash` (the `updateCollections` transaction). When `processConfirmedPegouts()` later tries to move another pegout created in that same `updateCollections` into the signing map under the same key, the Bridge throws:

```java
private void checkIfEntryExistsInPegoutsWaitingForSignatures(Keccak256 rskTxHash, Map<Keccak256, BtcTransaction> pegoutsWaitingForSignatures) {
    if (pegoutsWaitingForSignatures.containsKey(rskTxHash)) {
        // ... "Entry overriding is not allowed for pegoutsWaitingForSignatures map."
        throw new IllegalStateException(message);
    }
}
```

The Bridge's own comment on this guard describes the collision it prevents as "a critical bug ... resulting in losing funds." The exception reverts `updateCollections`, so it reverts on every following call. Pegout processing stops and the federation migration cannot finish.

Both siblings do share the key: `migrateFunds(rskTx.getHash(), ...)` (`BridgeSupport.java:1263`) and `Keccak256 batchPegoutCreationTxHash = rskTx.getHash()` (`:1542`) both flow into the same `addPegoutToPegoutsWaitingForConfirmations`, and under RSKIP375 the map key is `confirmedPegout.getPegoutCreationRskTxHash()` (`:1626`) — identical for both. `processConfirmedPegouts` promotes exactly one entry per call, so the sibling is necessarily promoted by a later `updateCollections` while the first still holds the key, and the guard throws.

#### How permanent the halt is depends on promotion order

I want to be precise here rather than claim the worst case unconditionally. Which of the two pegouts is promoted first is not controlled by this bug. `RSKIP559` (which would sort promotion by `BTC_TX_COMPARATOR`) is `tbd1000` and **inactive on mainnet**, so `getNextPegoutWithEnoughConfirmations` falls through to plain `HashSet` iteration (`PegoutsWaitingForConfirmations.java:143-149`) — deterministic across nodes, but effectively an unbiased coin flip between the two siblings. That gives two outcomes:

- **The bad batch pegout is promoted first (~50%).** It occupies the key and can never be signed, so the sibling migration entry can never be promoted and `updateCollections` reverts on every call indefinitely. This is the full halt: no migration, no new batch pegouts, no pegout confirmations, no SVP progress.
- **The good migration pegout is promoted first (~50%).** `addSignature` is a *separate* RSK transaction and is unaffected by the `updateCollections` revert, so the migration still reaches quorum and frees the key at `:1747`. The batch pegout is then promoted into the freed key and frozen there permanently — but nothing further collides with it, so `updateCollections` resumes. The halt is temporary; the frozen withdrawal is not.

So the **unconditional** consequence of a two-event receipt is one permanently frozen user withdrawal plus a reverting `updateCollections` for as long as the first sibling remains unsigned. The indefinite peg-wide halt is the worse half of a coin flip, not a certainty. I am flagging this rather than leaving it for a reviewer to discover, because it bounds claim (2) in the Impact section below.

## Impact

In-scope impact: temporary freezing of funds on the peg-out side of the bridge, together with a halt of pegout processing and of the federation change.

When a user withdrawal is batched in the same `updateCollections` as a migration pegout during a federation change:

1. **The user's withdrawal is frozen, with no recourse.** The BTC is undeliverable because every federator computes the same wrong sighash, while the RBTC is already gone: `TransactionExecutor.java:396-397` moves `tx.getValue()` out of the sender's account into the Bridge at inclusion, and once the request is batched it is removed from the queue and its UTXOs are consumed (`BridgeSupport.java:1546-1547`, `:1380`). The only refund path (`refundAndEmitRejectEvent`, `:934-938`) is reachable only at request time. I enumerated the `BridgeMethods` list: there is **no** Bridge method that can cancel, re-issue, or evict a `pegoutsWaitingForSignatures` entry. A code change is strictly required; the user has no workaround.
2. **Pegout processing stops for everyone.** This happens by either of two mechanisms. Where the misattributed list is long enough, the guard collision reverts `updateCollections` on every call, so no pegout advances (see the promotion-order note above for how long this persists). Where it is shorter or empty, the `IndexOutOfBoundsException` branch aborts the entire signing round at `BtcReleaseClient.java:300-302` on every best block, freezing healthy unrelated withdrawals too. Either way the damage is not confined to the pegout that triggered it.
3. **The federation change stalls** (in the ~50% branch where the migration entry is blocked from promotion). Migration cannot complete, so the retiring federation stays active longer than intended. That is undesirable if the change is meant to rotate out a departing or compromised signatory.

Points I want to be straight about so this gets rated correctly:

- This is not theft or inflation. Segwit ties the signature to the exact input amount, so a wrong amount produces a useless signature and nothing more. No BTC is redirected and no RBTC is created. BIP143's own rationale says so explicitly: "In the case that a wrong value is provided and signed, the signature would be invalid and no funding might be lost."
- Nothing malformed reaches the Bitcoin network. The Bridge rejects the signature during `addSignature` with zero state mutation, so this is a liveness failure, not a chain-safety one.
- It is recoverable. After the one-line fix the federators re-derive the correct amounts, re-sign the pegout that is still sitting in Bridge state, the collision clears, and processing resumes. No hard fork and no consensus change are needed. Note the recovery is a **coordinated** one: the bug is deterministic on shared on-chain data, so every unpatched federator computes the identical wrong sighash and nothing moves until a signing majority (5 of 9) has deployed the patched binary. One patched federator recovers nothing. So this is a temporary freeze, not a permanent one, and I am stating that rather than claiming permanent freezing.
- It happens during a federation migration, which is a recurring, publicly scheduled operation, whenever a user withdrawal lands in the same `updateCollections` as a migration pegout. It fires on its own from ordinary withdrawal traffic. An external actor can also cause it on purpose, which is a griefing / denial-of-service move with no profit, since their own withdrawal freezes too. To be accurate about how much control that actor has: it is not triggerable at an arbitrary moment of their choosing, but **within a scheduled migration window it is steerable to near-certainty**. `updateCollections` is permissionless, and `getNextPegoutCreationBlockNumber()`, `getQueuedPegoutsCount()` and `getActiveFederationCreationBlockHeight()` are unauthenticated view calls, so both the migration burst and the 360-block pegout window are computable days in advance.
- It only applies to a segwit (P2SH-P2WSH) federation; legacy sighashes do not commit the input amount and are unaffected. That is the current mainnet federation, which I verified on-chain rather than assuming: the Bridge reports federation `3GX89qzyQVaJqUJjq5noZbLJEHuYDvVrHq` created at RSK block **8,517,961**, after RSKIP305 activated at `reed800` = 8,052,200, and a real spend from that address carries a `0020…` P2SH redeemScript with an 8-item witness stack containing a 5-of-9 ERP witnessScript.
- As of this writing `getRetiringFederationAddress()` returns empty, so no migration is in flight and the bug is not live-exploitable at this instant. It arms at the next federation change. Federation changes have occurred at blocks 7,069,806, 7,781,198, 8,147,322 and 8,517,961, and each migration window is 10,584 RSK blocks (~3.7 days).

## References

- Vulnerable code: `src/main/java/co/rsk/federate/signing/hsm/message/ReleaseCreationInformation.java` (`decodeUtxoOutpointValues`)
- The correct correlation for comparison: `src/main/java/co/rsk/federate/signing/hsm/message/ReleaseCreationInformationGetter.java` (`getInformationFromEvent`)
- Amount propagation: `src/main/java/co/rsk/federate/signing/hsm/message/PowHSMSignerMessage.java` (`populateWithSegwitValues`), `src/main/java/co/rsk/federate/signing/SegwitSigHashCalculatorImpl.java`
- Round-aborting exception path: `src/main/java/co/rsk/federate/signing/SegwitSigHashCalculatorImpl.java:28` (unguarded `get(inputIndex)`), reached from `src/main/java/co/rsk/federate/btcreleaseclient/BtcReleaseClient.java:437-440`, escaping to the blanket handler at `:300-302`
- rskj event emitter and collision guard: `co.rsk.peg.BridgeSupport` (`updateCollections` at `:1040`, `migrateFunds`/`processPegoutsInBatch` -> `settleReleaseRequest` -> `logPegoutTransactionCreated` at `:1447`; `checkIfEntryExistsInPegoutsWaitingForSignatures` at `:1637`; key derivation at `:1624-1635`)
- rskj Bridge-side signature re-derivation and rejection: `co.rsk.peg.BridgeSupport` (`generateInputSigHash` at `:1859-1867`, `verify` at `:1878`, `processSigning` return-without-mutation at `:1844-1849`), and the only removal from the signing map at `:1747`
- **rskj's own tests asserting the trigger under mainnet constants**: `rskj-core/src/test/java/co/rsk/peg/BridgeSupportPegoutTransactionCreatedEventTest.java:227-344` (two `pegout_transaction_created` events from one `updateCollections`) and `rskj-core/src/test/java/co/rsk/peg/BridgeSupportProcessFundsMigrationTest.java:248` (migration creates a pegout on every `updateCollections`)
- Promotion order (why the halt is ~50/50): `co.rsk.peg.PegoutsWaitingForConfirmations:143-149`, with `RSKIP559` inactive on mainnet (`reference.conf`, `rskip559 = tbd1000`)
- Third emitter: `co.rsk.peg.BridgeSupport` `updateSvpState` at `:1053`, settling at `:1144` / `:1184`
- RBTC debited before delivery: `org.ethereum.core.TransactionExecutor:396-397`; request removed and UTXOs consumed at `BridgeSupport:1546-1547`, `:1380`
- Segwit path selection: `src/main/java/co/rsk/federate/signing/hsm/message/SignerMessageBuilderFactory.java:57-59`, `BtcReleaseClient.java:435-438`
- PowHSM outpoint-value handling (range check only): https://github.com/rsksmart/rsk-powhsm/blob/master/docs/protocol.md
- BIP143 (segwit sighash commits the input amount): https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- RSKIP305, segwit PowPeg (P2SH-P2WSH), activated on mainnet at block 8,052,200 in Reed 8.0.0: https://ips.rootstock.io/IPs/RSKIP305.html

## Proof of concept

All testing was done on a local regtest fork. Nothing was broadcast to testnet or mainnet.

There are two PoCs:

- PoC 1 is a unit test against the unmodified signing code. It proves the misattribution and the resulting sighash mismatch directly, in seconds.
- PoC 2 is the full peg. It runs a real federation change on a regtest two-way peg with real federator nodes, injects one user withdrawal during the migration, and shows the withdrawal freeze and the peg halt.

---

### PoC 1 — unit test against the real signing code

Add this test to the repo and run it with the composite build (which compiles rskj-core from source). The assertions encode the buggy behaviour, so the test passing is the proof.

File: `src/test/java/co/rsk/federate/signing/hsm/message/OutpointValuesMisattributionPoCTest.java`

```java
package co.rsk.federate.signing.hsm.message;

import static co.rsk.federate.bitcoin.BitcoinTestUtils.coinListOf;
import static co.rsk.federate.bitcoin.BitcoinTestUtils.createP2PKHAddress;
import static co.rsk.federate.bitcoin.BitcoinTestUtils.createPegout;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import co.rsk.bitcoinj.core.Address;
import co.rsk.bitcoinj.core.BtcTransaction;
import co.rsk.bitcoinj.core.Coin;
import co.rsk.bitcoinj.core.NetworkParameters;
import co.rsk.bitcoinj.core.Sha256Hash;
import co.rsk.crypto.Keccak256;
import co.rsk.federate.EventsTestUtils;
import co.rsk.federate.signing.SegwitSigHashCalculatorImpl;
import co.rsk.federate.signing.utils.TestUtils;
import co.rsk.peg.BridgeSerializationUtils;
import co.rsk.peg.constants.BridgeConstants;
import co.rsk.peg.constants.BridgeMainNetConstants;
import co.rsk.peg.federation.Federation;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.ethereum.core.Block;
import org.ethereum.core.TransactionReceipt;
import org.ethereum.vm.LogInfo;
import org.junit.jupiter.api.Test;

/**
 * ReleaseCreationInformation.decodeUtxoOutpointValues() selects the segwit outpoint values with
 * findFirst() over the pegout_transaction_created logs, matching only topic[0] (the event
 * signature) and never topic[1] (the pegout's btcTxHash). rskj's updateCollections() emits a
 * migration pegout_transaction_created first and a batch pegout_transaction_created second into
 * one receipt, so signing the batch pegout picks the migration pegout's input amounts. Segwit
 * (BIP143) commits the input amount, so the resulting signature is invalid and the withdrawal
 * freezes.
 */
class OutpointValuesMisattributionPoCTest {

    private static final BridgeConstants BRIDGE = BridgeMainNetConstants.getInstance();
    private static final NetworkParameters BTC_PARAMS = BRIDGE.getBtcParams();

    @Test
    void batchPegoutIsSignedWithMigrationPegoutOutpointValues_soSigHashIsWrong() {
        Federation federation = TestUtils.createP2shP2wshErpFederation(BTC_PARAMS, 9);
        Address user = createP2PKHAddress(BTC_PARAMS, "user");

        // Migration pegout: created first in updateCollections. Input amount A = 0.50 BTC.
        List<Coin> migrationOutpointValues = coinListOf(50_000_000);
        BtcTransaction migrationPegout =
            createPegout(BTC_PARAMS, federation, migrationOutpointValues, Collections.singletonList(user));

        // Batch (user) pegout: created second. Input amount B = 1.00 BTC (distinct).
        List<Coin> batchOutpointValues = coinListOf(100_000_000);
        BtcTransaction batchPegout =
            createPegout(BTC_PARAMS, federation, batchOutpointValues, Collections.singletonList(user));

        assertNotEquals(migrationPegout.getHash(), batchPegout.getHash());
        assertNotEquals(migrationOutpointValues, batchOutpointValues);

        // One updateCollections receipt with both pegouts' events, migration emitted first
        // (the order BridgeSupport.updateCollections produces: processFundsMigration then
        // processPegoutRequests, each calling settleReleaseRequest -> logPegoutTransactionCreated).
        Keccak256 updateCollectionsRskTxHash = TestUtils.createHash(1);
        List<LogInfo> logs = new ArrayList<>();
        logs.add(EventsTestUtils.createReleaseRequestedLog(
            updateCollectionsRskTxHash, migrationPegout.getHash(), Coin.COIN));
        logs.add(EventsTestUtils.createPegoutTransactionCreatedLog(
            migrationPegout.getHash(), BridgeSerializationUtils.serializeOutpointsValues(migrationOutpointValues)));
        logs.add(EventsTestUtils.createReleaseRequestedLog(
            updateCollectionsRskTxHash, batchPegout.getHash(), Coin.COIN));
        logs.add(EventsTestUtils.createPegoutTransactionCreatedLog(
            batchPegout.getHash(), BridgeSerializationUtils.serializeOutpointsValues(batchOutpointValues)));

        TransactionReceipt updateCollectionsReceipt = new TransactionReceipt();
        updateCollectionsReceipt.setLogInfoList(logs);

        // Sign the batch pegout (its release_requested topic[2] == batchPegout hash).
        ReleaseCreationInformation releaseInfo = new ReleaseCreationInformation(
            (Block) null, updateCollectionsReceipt, updateCollectionsRskTxHash, batchPegout);

        List<Coin> selectedOutpointValues = releaseInfo.getUtxoOutpointValues();

        // The defect: findFirst() returns the migration pegout's amounts (A), not the batch's own (B).
        assertEquals(migrationOutpointValues, selectedOutpointValues,
            "batch pegout received the migration pegout's outpoint values");
        assertNotEquals(batchOutpointValues, selectedOutpointValues,
            "the selected values are not the batch pegout's own amounts");

        // The impact: the sighash the federator would sign (wrong amount A) differs from the one
        // the Bridge re-derives and verifies against in addSignature (real amount B), so the
        // signature is rejected and the pegout can never accumulate a quorum.
        Sha256Hash sigHashThatWouldBeSigned =
            new SegwitSigHashCalculatorImpl(selectedOutpointValues).calculate(batchPegout, 0);
        Sha256Hash sigHashBridgeWillVerify =
            new SegwitSigHashCalculatorImpl(batchOutpointValues).calculate(batchPegout, 0);

        assertNotEquals(sigHashBridgeWillVerify, sigHashThatWouldBeSigned,
            "federator signs the wrong BIP143 sighash for the batch pegout, so the signature is invalid");
    }
}
```

Build and run:

```bash
# powpeg-node builds against rskj-core built from source (composite build)
git clone https://github.com/rsksmart/rskj.git rskj
cat > DONT-COMMIT-settings.gradle <<'EOF'
includeBuild('./rskj') {
    dependencySubstitution {
        all { DependencySubstitution dependency ->
            if (dependency.requested instanceof ModuleComponentSelector
                    && dependency.requested.group == 'co.rsk'
                    && dependency.requested.module == 'rskj-core'
                    && (dependency.requested.version.endsWith('SNAPSHOT') || dependency.requested.version.endsWith('RC'))) {
                def targetProject = project(":${dependency.requested.module}")
                if (targetProject != null) {
                    dependency.useTarget targetProject
                }
            }
        }
    }
}
EOF
./configure.sh   # fetches gradle-wrapper.jar
./gradlew test --tests "co.rsk.federate.signing.hsm.message.OutpointValuesMisattributionPoCTest"
# BUILD SUCCESSFUL
```

---

### PoC 2 — full regtest peg (federation change, migration, concurrent withdrawal)

This uses the project's Rootstock Integration Tests harness (https://github.com/rsksmart/rootstock-integration-tests). It stands up bitcoind in regtest, a genesis federation, and a second federation, where every federator node is the real `federate-node` jar. It then runs the standard `00_00_07-change-federation.js` scenario, which performs a real federation change and migration. I made two kinds of edits:

- One change to a Bridge regtest constant, plus one small test injection, to make the migration and the withdrawal land in the same `updateCollections` reliably inside a single short run.
- A few edits that only exist to run the x86 RIT stack on an Apple Silicon machine. These are environment plumbing and have nothing to do with the bug. They are listed at the end so it is clear what is signal and what is setup.

#### Environment

- bitcoind 0.18.1 (the harness requires the old `generate` / `signrawtransaction` RPCs)
- Java 17
- Node.js 18+
- the `federate-node` fat jar, built as in PoC 1

`.env` in the rootstock-integration-tests directory:

```
POWPEG_NODE_JAR_PATH=/path/to/powpeg-node/build/libs/federate-node-SNAPSHOT-9.1.0.0-all.jar
CONFIG_FILE_PATH=./config/regtest-all-keyfiles
LOG_HOME=/path/to/rit-logs
BITCOIND_BIN_PATH=/path/to/bitcoin-0.18.1/bin/bitcoind
JAVA_BIN_PATH=/path/to/java
BITCOIN_DATA_DIR=/path/to/rit-bitcoindata
INCLUDE_CASES=00_00_07-change-federation.js
```

#### Change 1 (Bridge regtest constant) — makes the migration span many updateCollections

On mainnet the federation holds a large UTXO set, so a migration is spread over many `updateCollections`, which is exactly when a user withdrawal is likely to be batched alongside a migration pegout. In a small regtest the federation has only a handful of UTXOs, so the migration finishes in one or two `updateCollections` and the coincidence rarely happens on its own. Setting `maxInputsPerPegoutTransaction = 1` makes the migration move one UTXO per `updateCollections`, so it spans many of them and reliably overlaps the withdrawal. This changes only how often the trigger fires, not the bug.

**To be explicit about what this constant change does and does not do**, since it is the natural thing to challenge in this report: it compresses the schedule so the coincidence occurs within a single short regtest run. It does not manufacture a state that mainnet cannot reach. The two claims it accelerates are both asserted by rskj's own test suite under `BridgeMainNetConstants`, not by me:

- that a migration and a batch pegout can be created in one `updateCollections`, emitting two `pegout_transaction_created` events — `BridgeSupportPegoutTransactionCreatedEventTest.java:227-344`;
- that a migration creates a pegout on every `updateCollections` when the retiring federation holds more than `maxInputsPerPegoutTransaction` UTXOs — `BridgeSupportProcessFundsMigrationTest.java:248`.

With mainnet's `maxInputsPerPegoutTransaction = 50` and `numberOfBlocksBetweenPegouts = 360`, a migration of N UTXOs spans `ceil(N/50)` consecutive `updateCollections` calls at roughly one per 3 minutes, inside a 10,584-block (~88 h) window that contains about 29 batch-pegout cycles. Accidental overlap therefore scales with the federation's UTXO count and approaches certainty for a large N; and, as noted in the Impact section, an actor who wants the overlap can simply steer it. Independently of all of that, the defect itself is proven by PoC 1 against completely unmodified code.

File: `rskj-core/src/main/java/co/rsk/peg/constants/BridgeRegTestConstants.java`

```java
// was: maxInputsPerPegoutTransaction = 10;
maxInputsPerPegoutTransaction = 1;   // migration moves one UTXO per updateCollections, so it overlaps a concurrent batch pegout

// was: numberOfBlocksBetweenPegouts = 50;
numberOfBlocksBetweenPegouts = 1;    // let a user pegout batch as soon as funds exist
```

Rebuild the fat jar after this change so the federator nodes pick it up.

#### Change 2 (test injection) — one user withdrawal during the migration, and a check for the stuck pegout

File: `lib/tests/change-federation.js`, inside the `should migrate utxos` test.

Add `sendTxToBridge` to the imports:

```js
const {
    // ... existing imports ...
    sendTxToBridge,
} = require('../2wp-utils');
```

Inject the withdrawal right before the first migration `updateCollections` (`await rskUtils.waitAndUpdateBridge(rskTxHelper)`), and replace the block's closing assertions with the stuck-pegout check:

```js
// Mining to activate the migration age
await rskUtils.mineAndSync(
    rskTxHelpers,
    FUNDS_MIGRATION_AGE_SINCE_ACTIVATION_BEGIN + 1
);

// --- injection: a user withdrawal during the migration window ---
// The next updateCollections runs processFundsMigration() (emits pegout_transaction_created #1,
// the migration) then processPegoutRequests() (emits pegout_transaction_created #2, this batch)
// into one receipt. Signing the batch pegout, decodeUtxoOutpointValues() picks event #1's
// amounts, so the batch is signed with the migration's amounts and stays stuck.
const pocPegoutSender = await rskTxHelper.newAccountWithSeed('poc-pegout-sender');
await rskUtils.sendFromCow(rskTxHelper, pocPegoutSender, btcToWeis(3));
await rskTxHelper.unlockAccount(pocPegoutSender);
// Small amount (>= the 0.0025 BTC minimum) so the new/active federation can fund it from its
// pegin UTXOs at the first migration updateCollections.
await sendTxToBridge(rskTxHelper, new BN(btcToWeis(0.003).toString()), pocPegoutSender, true);
// ----------------------------------------------------------------

// Start migration
await rskUtils.waitAndUpdateBridge(rskTxHelper);
const bridgeStateAfterUpdatingCollections = await getBridgeState(rskTxHelper.getClient());
expect(bridgeStateAfterUpdatingCollections.pegoutsWaitingForConfirmations.length)
    .to.be.greaterThan(0, 'There should be at least one pegout waiting for confirmations.');

await wait(1000);
await rskUtils.mineAndSync(rskTxHelpers, BTC_TO_RSK_MINIMUM_CONFIRMATIONS);
const blockNumberAfterConfirmations = await rskTxHelper.getBlockNumber();
if (isRunningHsms()) {
    await rskUtils.mineAndSync(rskTxHelpers, HSM_DIFFICULTY_TARGET + 1);
    await waitForHsmsToBeSynchedToThisBlock(rskTxHelper, blockNumberAfterConfirmations);
}
await wait(1000);
await rskUtils.waitAndUpdateBridge(rskTxHelper);

const checkPegoutIsBroadcasted = async () => {
    const currentBridgeState = await getBridgeState(rskTxHelper.getClient());
    if (currentBridgeState.pegoutsWaitingForSignatures.length === 0 &&
        currentBridgeState.pegoutsWaitingForConfirmations.length === 0) {
        return true;
    }
    await wait(1000);
    await rskUtils.waitAndUpdateBridge(rskTxHelper);
    return false;
};
await retryWithCheck(checkPegoutIsBroadcasted, (pegoutIsBroadcasted) => pegoutIsBroadcasted);

// --- observation: is a pegout stuck in waitingForSignatures? ---
// Drive more confirmation + updateCollections rounds. The migration pegout signs correctly; the
// batch pegout was signed with the migration's amounts, so it can never leave waitingForSignatures.
for (let round = 0; round < 12; round++) {
    await rskUtils.mineAndSync(rskTxHelpers, BTC_TO_RSK_MINIMUM_CONFIRMATIONS);
    await wait(1000);
    await rskUtils.waitAndUpdateBridge(rskTxHelper);
    const s = await getBridgeState(rskTxHelper.getClient());
    console.log(`[PoC] round ${round}: waitingForConfirmations=${s.pegoutsWaitingForConfirmations.length} waitingForSignatures=${s.pegoutsWaitingForSignatures.length}`);
}

const finalPocState = await getBridgeState(rskTxHelper.getClient());
const stuck = finalPocState.pegoutsWaitingForSignatures;
console.log('[PoC] FINAL pegoutsWaitingForSignatures:', JSON.stringify(stuck));
if (stuck.length > 0) {
    console.log('[PoC] BUG REPRODUCED ON-CHAIN: a pegout is stuck in pegoutsWaitingForSignatures.');
    console.log('[PoC] Federators repeatedly fail to produce a valid signature (wrong BIP143 outpoint amounts).');
}
// Passes when a user-withdrawal pegout is frozen in waitingForSignatures.
expect(stuck.length, 'A pegout should be stuck in waitingForSignatures').to.be.greaterThan(0);
return;
// ----------------------------------------------------------------
```

`BN` and `btcToWeis` are already imported at the top of this file; `sendTxToBridge`, `sendFromCow`, `newAccountWithSeed`, `unlockAccount`, `mineAndSync`, `waitAndUpdateBridge`, `getBridgeState`, and `retryWithCheck` are already used elsewhere in it.

#### Run

```bash
npm install
npm run test-fail-fast
```

#### Observed output

The federation change runs to the migration, the injected withdrawal is created, and a pegout is stuck in `pegoutsWaitingForSignatures` for the whole observation window:

```
[PoC] User pegout request (0.003 BTC) created and mined.
[PoC] round 0:  waitingForConfirmations=3  waitingForSignatures=1
[PoC] round 1:  waitingForConfirmations=3  waitingForSignatures=1
...
[PoC] round 11: waitingForConfirmations=3  waitingForSignatures=1
[PoC] FINAL pegoutsWaitingForSignatures: [ { "rskTxHash":"a3cfe79b15cec5daf02ef8acbe4b59ae0bdfc57255e101b1290eb0991c2b7721", "btcRawTx":"0200000000010132..." } ]
[PoC] BUG REPRODUCED ON-CHAIN: a pegout is stuck in pegoutsWaitingForSignatures.
[PoC] Federators repeatedly fail to produce a valid signature (wrong BIP143 outpoint amounts).
```

The federator node logs show the Bridge guard throwing on every `updateCollections` after the pegout is stuck (200+ times in one run), which is the peg halt:

```
java.lang.IllegalStateException: An entry for the given rskTxHash a3cfe79b15cec5daf02ef8acbe4b59ae0bdfc57255e101b1290eb0991c2b7721
already exists. Entry overriding is not allowed for pegoutsWaitingForSignatures map.
    at co.rsk.peg.BridgeSupport.checkIfEntryExistsInPegoutsWaitingForSignatures(BridgeSupport.java:1644)
```

And the federation change cannot complete, because migration is blocked:

```
should complete retiring the old federation:
  The retiring federation size should be -1.
  + expected - actual
  -3
  +-1
```

#### Environment-only edits (not part of the bug)

These were needed only to run the x86 RIT stack natively on an Apple Silicon machine. They do not affect the result and can be ignored on a normal Linux x86 machine, where the harness runs as-is.

- `lib/federate-runner.js`: cap each federator JVM heap so several nodes fit in RAM.
  ```js
  const args = ['-Xmx1200m', '-Xss32m', '-cp', this.options.classpath, `-Drsk.conf.file=${this.options.configFile}`];
  ```
- `lib/2wp-utils.js`: fix a pre-existing typo in the unused `createPegoutRequest` helper (`ethToWeis` is not imported in that file), so the file loads. The injection above does not use this helper.
  ```js
  // was: new BN(ethToWeis(amountInRBTC))
  await sendTxToBridge(rskTxHelper, new BN(btcEthUnitConverter.btcToWeis(amountInRBTC)), rskAddress, false);
  ```
- `lib/tests/change-federation.js`, in the `before` hook: let the new federation's nodes peer at block 0 before the first block is mined, so they receive block 1 by propagation instead of a state sync (the state sync intermittently wedges a node when running the JVMs under x86 emulation).
  ```js
  await wait(60000);
  await rskUtils.waitForSync(rskTxHelpers);
  ```
- `lib/federation-utils.js`, `startNewFederationNodes`: start all but the last new-federation node (all member pubkeys are still committed to the Bridge, so the federation address is unchanged and the signing quorum is online). This only reduces JVM count under emulation.
  ```js
  const nodesToStart = Math.max(1, newFederationConfig.length - 1);
  for (let i = 0; i < nodesToStart; i++) { ... }
  ```

## Suggested fix

Match the `pegout_transaction_created` event by its btcTxHash, the same way the getter already matches `release_requested`:

```java
private List<Coin> decodeUtxoOutpointValues() {
    byte[] wantedBtcTxHash = pegoutBtcTx.getHash().getBytes();
    return transactionReceipt.getLogInfoList().stream()
        .filter(this::isPegoutTransactionCreatedLog)
        .filter(log -> Arrays.equals(log.getTopics().get(1).getData(), wantedBtcTxHash)) // topic[1] = btcTxHash
        .findFirst()
        .map(LogInfo::getData)
        .map(this::decodePegoutTransactionEventData)
        .map(UtxoUtils::decodeOutpointValues)
        .orElse(Collections.emptyList());
}
```

Add a regression test with a receipt that carries two `pegout_transaction_created` events (a migration and a batch), and assert the correct one is selected for each pegout. The existing tests only ever build a receipt with a single instance of this event — `ReleaseCreationInformationGetterTest.addCommonPegoutLogs` (`:498-510`) and `PowHSMSignerMessageBuilderTest` (`:286-290`) both add exactly one — which is why this went unnoticed. Note that `PowHSMSignerMessageBuilderTest:262-296` deliberately adds *other* extra logs (`rejected_pegin`, `release_requested`) to look realistic, so the gap is specifically multiplicity of the same event, not variety of events.

Two things are worth fixing beyond the one-line correlation:

- **Assert the list length matches the pegout's input count** before signing. This is not merely defence in depth: it converts the `IndexOutOfBoundsException` branch described above, which currently escapes into `BtcReleaseClient`'s blanket handler and aborts the signing round for every pegout, into a contained per-pegout failure. Right now a single misattributed pegout can stop unrelated healthy withdrawals from being signed on every block.
- **Apply the same correlation to the SVP path.** The SVP spend transaction is settled through the same `processReleaseTransactionInfo` emitter, so it is exposed to the identical defect whenever its event is not the first in the receipt.
