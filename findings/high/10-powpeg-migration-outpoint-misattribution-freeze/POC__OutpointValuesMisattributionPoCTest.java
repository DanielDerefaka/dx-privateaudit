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
 * PoC — outpoint-value misattribution in ReleaseCreationInformation.decodeUtxoOutpointValues().
 *
 * ReleaseCreationInformation selects the segwit outpoint (prevout) values via
 * transactionReceipt.getLogInfoList().stream().filter(isPegoutTransactionCreatedLog).findFirst(),
 * matching ONLY the event-signature topic[0] and NEVER correlating topic[1] (the pegout's
 * btcTxHash) to the pegout actually being signed.
 *
 * rskj BridgeSupport.updateCollections() runs processFundsMigration() (emits a migration
 * pegout_transaction_created FIRST) and then processPegoutRequests() (emits the batch/user
 * pegout_transaction_created SECOND) inside ONE rsk transaction, so ONE receipt can carry both
 * events. When the federator later signs the BATCH pegout, findFirst() returns the MIGRATION
 * pegout's input amounts.
 *
 * Because segwit (BIP143) commits the spent-input amount into the sighash, signing with the wrong
 * amount yields a signature the Bitcoin network rejects -> the user-withdrawal batch pegout can
 * never confirm -> funds frozen.
 */
class OutpointValuesMisattributionPoCTest {

    private static final BridgeConstants BRIDGE = BridgeMainNetConstants.getInstance();
    private static final NetworkParameters BTC_PARAMS = BRIDGE.getBtcParams();

    @Test
    void batchPegoutIsSignedWithMigrationPegoutOutpointValues_soSigHashIsWrong() {
        Federation federation = TestUtils.createP2shP2wshErpFederation(BTC_PARAMS, 9);
        Address user = createP2PKHAddress(BTC_PARAMS, "user");

        // MIGRATION pegout: created first in updateCollections. Input amount A = 0.50 BTC.
        List<Coin> migrationOutpointValues = coinListOf(50_000_000);
        BtcTransaction migrationPegout =
            createPegout(BTC_PARAMS, federation, migrationOutpointValues, Collections.singletonList(user));

        // BATCH pegout (user withdrawals): created second. Input amount B = 1.00 BTC (distinct).
        List<Coin> batchOutpointValues = coinListOf(100_000_000);
        BtcTransaction batchPegout =
            createPegout(BTC_PARAMS, federation, batchOutpointValues, Collections.singletonList(user));

        // Preconditions: two distinct pegouts with distinct input amounts.
        assertNotEquals(migrationPegout.getHash(), batchPegout.getHash());
        assertNotEquals(migrationOutpointValues, batchOutpointValues);

        // ONE updateCollections receipt carrying BOTH pegouts' events, migration emitted FIRST
        // (exactly the order BridgeSupport.updateCollections produces:
        //  processFundsMigration -> settleReleaseRequest -> logPegoutTransactionCreated, then
        //  processPegoutRequests -> settleReleaseRequest -> logPegoutTransactionCreated).
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

        // The federator is signing the BATCH pegout (its release_requested topic[2] == batchPegout hash).
        ReleaseCreationInformation releaseInfo = new ReleaseCreationInformation(
            (Block) null, updateCollectionsReceipt, updateCollectionsRskTxHash, batchPegout);

        List<Coin> selectedOutpointValues = releaseInfo.getUtxoOutpointValues();

        // ---- THE DEFECT ----
        // Correct: the batch pegout must be signed with its OWN input amounts (B).
        // Actual:  findFirst() returns the MIGRATION pegout's amounts (A).
        assertEquals(migrationOutpointValues, selectedOutpointValues,
            "BUG: batch pegout received the migration pegout's outpoint values");
        assertNotEquals(batchOutpointValues, selectedOutpointValues,
            "BUG: the selected values are NOT the batch pegout's own amounts");

        // ---- THE IMPACT ----
        // sighash the federator/HSM signs (wrong amount A) vs sighash the Bridge re-derives and
        // verifies against in addSignature (the batch pegout's real amount B, read from
        // provider.getReleaseOutpointsValues(btcTxHash) -- correctly keyed, unlike this code path).
        // They differ => the signature is rejected at BridgeSupport:1878 with no state mutation =>
        // the user-withdrawal batch pegout can never reach a quorum => funds frozen.
        Sha256Hash sigHashThatWouldBeSigned =
            new SegwitSigHashCalculatorImpl(selectedOutpointValues).calculate(batchPegout, 0);
        Sha256Hash sigHashBridgeWillVerify =
            new SegwitSigHashCalculatorImpl(batchOutpointValues).calculate(batchPegout, 0);

        assertNotEquals(sigHashBridgeWillVerify, sigHashThatWouldBeSigned,
            "BUG: federator signs the wrong BIP143 sighash for the batch pegout => invalid signature => funds frozen");
    }
}
