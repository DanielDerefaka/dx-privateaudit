# Finding: Non-ceasing sidechain — two certificates for the same scId in one block reach a reachable `assert` in `ConnectBlock`, aborting every validating node (network-wide chain halt)

**Severity:** HIGH → **likely CRITICAL** (Liveness / Consensus-DoS — network-wide node crash, persistent "poison block" crash-loop). Not a value-conservation bug; no fund loss. *Severity raised after caveat review (.hunt/CAVEATS_nonceasing_multicert_assert.md): the crash precedes SNARK verification, so the attack is **permissionless** — no sidechain proving key, no admin — gated only by mining one PoW block.*
**Status:** CONFIRMED by code trace (all load-bearing claims verified against source). Mechanical `ASSERT_DEATH` PoC written (`src/gtest/test_sidechain_blocks.cpp` → `ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert`); execution pending a successful build.
**Component:** Sidechain certificate block validation (`src/main.cpp`).
**Affected feature is live on mainnet:** non-ceasing sidechains active since height **1,363,115** (`src/zen/forks/fork10_nonceasingsidechainfork.cpp`).

---

## Summary

For a **non-ceasing** sidechain (v2, `withdrawalEpochLength == 0`), `ConnectBlock` enforces with a bare `assert` that *every* certificate in a block is the block-top-quality certificate for its scId:

```cpp
// src/main.cpp:3761-3764  (ConnectBlock, forward per-cert loop)
bool isBlockTopQualityCert = highQualityCertData.count(cert.GetHash()) != 0;
if (sidechain.isNonCeasing())   // For non-ceasing SC cert should always be top quality
{
    assert(isBlockTopQualityCert);
}
```

The invariant "a block contains at most one certificate per non-ceasing scId" is enforced **only at mempool admission** (`pool.certificateExists`, main.cpp:1322), and **nowhere in block validation** (`CheckBlock` / `ContextualCheckBlock` / `CheckCertificatesOrdering`). `CheckCertificatesOrdering` was deliberately *relaxed* for non-ceasing SCs to permit multiple certificates at strictly increasing epochs in one block.

Therefore a block whose `vcert` contains two certificates for the same non-ceasing scId at consecutive epochs `N` and `N+1` (in that block order) is accepted by every pre-connection check, but `HighQualityCertData()` records only the **last** one (epoch `N+1`) as top-quality. When `ConnectBlock` processes the epoch-`N` certificate first, `isBlockTopQualityCert == false`, `isNonCeasing() == true`, and the `assert` fires → `abort()` → the node process dies.

Because the block is written to disk by `AcceptBlock` *before* `ActivateBestChain`/`ConnectBlock` attempts to connect it, every node that restarts re-reads the block and re-crashes: a persistent crash-loop that halts the network until operators intervene (`invalidateblock` / reindex / patched binary).

Asserts are live in production builds — `configure.ac` defines no `-DNDEBUG` (standard Bitcoin/Zcash practice: `assert()` is used as a consensus guard).

---

## Root cause — exact code trace

### 1. Block-level uniqueness is mempool-only

The only check that rejects a second certificate for a non-ceasing scId is in `AcceptToMemoryPool`:

```cpp
// src/main.cpp:1322  (mempool admission ONLY)
if (sc.isNonCeasing() && pool.certificateExists(cert.GetScId()))
{
    state.Invalid(... "bad-sc-cert-conflict");
    return MempoolReturnValue::INVALID;
}
```

A miner assembling a block directly (bypassing its own mempool) is not subject to this. Grep of every `isNonCeasing()` site in `main.cpp` confirms there is **no** block-validation equivalent — the other sites are the two asserts (3764, 2886) and the `assert(!isNonCeasing())` branches inside `HighQualityCertData` (999, 2967, 3792).

### 2. `CheckCertificatesOrdering` explicitly allows multi-epoch certs for non-ceasing SCs

```cpp
// src/main.cpp:1047-1079  (comment + code)
// ... Originally, it also checked that a block did not contain 2 or more certs
// referring to different epochs (invalid only for v0/v1) ...
// Now: only rejects DECREASING epoch order, and within an epoch decreasing quality.
```

`vcert = [cert(epoch=N), cert(epoch=N+1)]` for one scId passes: epochs are strictly increasing. No rejection.

### 3. `HighQualityCertData` records only ONE cert per scId (the last/highest-epoch)

```cpp
// src/main.cpp:980-1009  (connect variant)
std::set<uint256> visitedScIds;
for (auto itCert = blockToConnect.vcert.rbegin(); itCert != blockToConnect.vcert.rend(); ++itCert) {
    if (visitedScIds.count(itCert->GetScId()) != 0)
        continue;                                   // <-- epoch-N cert skipped (scId already visited)
    ...
    else
        res[itCert->GetHash()] = uint256();         // <-- only epoch-N+1 recorded
    visitedScIds.insert(itCert->GetScId());
}
```

Reverse iteration visits epoch `N+1` first → inserted into `res` and `visitedScIds`. Epoch `N` is then `continue`-skipped → **absent** from `res`.

### 4. `ConnectBlock` processes certs in forward (block) order; epoch-N cert reaches the assert

```cpp
// src/main.cpp:3654  forward loop
for (unsigned int certIdx = 0; certIdx < block.vcert.size(); certIdx++) {
    ...
    // 3720: applicability check — epoch N == lastTopQualityCertReferencedEpoch+1 (next expected) → PASSES
    CValidationState::Code ret_code = view.IsCertApplicableToState(cert);
    if (ret_code != ...OK) return state.DoS(100, ...);   // clean reject — NOT taken for epoch-N
    ...
    // 3761:
    bool isBlockTopQualityCert = highQualityCertData.count(cert.GetHash()) != 0;  // = 0 for epoch-N
    if (sidechain.isNonCeasing()) {        // = true
        assert(isBlockTopQualityCert);     // 3764: assert(false) → abort()
    }
}
```

The epoch-`N` certificate is the **first** processed (forward order) and is fully applicable to state (it references the next expected epoch `lastTopQualityCertReferencedEpoch+1`), so it passes `IsCertApplicableToState` and reaches the `assert`. The epoch-`N+1` cert is never processed — the node has already aborted.

### 5. Symmetric crash on the disconnect path

```cpp
// src/main.cpp:2880-2888  (DisconnectBlock)
bool isBlockTopQualityCert = highQualityCertData.count(cert.GetHash()) != 0;
...
if (sidechain.isNonCeasing()) { assert(isBlockTopQualityCert); }  // 2886
```

If such a block ever connected (e.g. on a node with asserts disabled) and were later disconnected, the disconnect path asserts identically.

---

## Why this is NOT inflation (scope clarification)

The accompanying value-conservation analysis (`.hunt/depth_reorg.md`, Candidate 1) confirmed the inflation hypothesis is **unreachable**: the `if (isBlockTopQualityCert)` gate at main.cpp:3774 means the epoch-`N` cert's `UpdateSidechain` is never called, so `lastTopQualityCertReferencedEpoch` stays `N-1`. If asserts were hypothetically compiled out (`-DNDEBUG`), the epoch-`N+1` cert then fails its own cross-epoch precondition (`coins.cpp:1804/1824`, `(N+1) != (N-1)+1`) and the block is cleanly rejected (`bad-sc-cert-not-updated`). Residual balance error = 0 in both build modes. This is purely a **liveness / consensus-DoS**.

---

## Attack model & impact

**Precondition:** a non-ceasing sidechain (`version=2`, `withdrawalEpochLength=0`) referenced by the crafted certs. Non-ceasing SCs are live on mainnet (since height 1,363,115), **and** sidechain creation is permissionless — so the attacker can stand up their own non-ceasing SC and does not depend on a third-party one existing.

**Attacker capability (NO proving key required):**
1. Two **well-formed** certificates for the same non-ceasing SC at consecutive epochs `N`, `N+1`, with **dummy proofs of valid size** — not cryptographically valid. The SNARK proofs are only *queued* (`LoadDataForCertVerification`, main.cpp:3730) and verified by `BatchVerify()` at **main.cpp:3969**, which is **after** the assert at 3764. Every field cert-N must satisfy in `IsCertApplicableToState` (coins.cpp:1172 — epoch = lastTop+1, quality, BWT ≤ balance, resolvable cumulative-tree root, proof+vk *size*) is craftable from public on-chain data. The node crashes before any proof is checked.
2. Ability to **mine one PoW block** and place both certs in `vcert` directly, bypassing the mempool admission check at main.cpp:1322. (`CheckBlock`/`ContextualCheckBlock` do not run `IsCertApplicableToState`, so cert-N+1's epoch mismatch is never caught pre-connect; cert-N at certIdx 0 crashes before cert-N+1 is examined.)

**Trigger:** the crafted block becomes a connection target (chain tip extension or during reorg) → `ConnectBlock` → `abort()`.

**Blast radius:** every validating full node that attempts to connect the block aborts. The block is persisted to disk pre-connection (`AcceptBlock` before `ConnectBlock`), so restarting nodes re-attempt and re-crash → persistent network-wide halt requiring manual operator recovery (`invalidateblock`/reindex/patched binary). No fund loss.

**Severity = HIGH, arguably CRITICAL** (Impact High: network-wide chain halt + crash-loop; Likelihood Medium–High: the only gate is mining one block — no special privileges, no proving key. Any existing miner/pool can do it on their next found block). The lone likelihood reducer is the PoW requirement; everything else is permissionless and self-satisfiable. See full caveat analysis in .hunt/CAVEATS_nonceasing_multicert_assert.md.

---

## Mechanical PoC — [POC-PASS] (built and executed against zend 6.0.0, x86_64)

Result: `[ OK ] ...ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert (125 ms)` / `[ PASSED ] 1 test.` — the `ASSERT_DEATH` confirmed `ConnectBlock` aborts at `assert(isBlockTopQualityCert)` (main.cpp:3764). Run with `--gtest_death_test_style=threadsafe` (zend is multithreaded; the default fork-based death test deadlocks on inherited mutexes).


`src/gtest/test_sidechain_blocks.cpp` →
`SidechainsConnectCertsBlockTestSuite.ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert`

Builds a non-ceasing SC (`version=2`, `withdrawalEpochLength=0`, `lastTopQualityCertReferencedEpoch=1987`), a block with `vcert = [cert(epoch=1988), cert(epoch=1989)]` for that scId, and asserts via `ASSERT_DEATH(..., "isBlockTopQualityCert")` that `ConnectBlock` aborts. The epoch-1988 cert references the next expected epoch (1987+1) so it passes `IsCertApplicableToState` and reaches the assert; the epoch-1989 cert is recorded as the sole top-quality cert by `HighQualityCertData`.

Run (inside the x86_64 build container, once built):
```
src/zen-gtest --gtest_filter='*ConnectBlock_MultipleCerts_NonCeasing_SameScId_TriggersAssert*'
```
Expected: PASS (the death test observes the `assert(isBlockTopQualityCert)` abort).

---

## Recommendation

Enforce the "≤1 certificate per non-ceasing scId per block" rule at **block validation**, not only at mempool admission, and reject the block gracefully instead of asserting:

- In `CheckCertificatesOrdering` (or `ContextualCheckBlock`), for each non-ceasing scId, reject (`state.DoS(100, ..., "bad-sc-cert-multiple-noceasing")`) any block carrying more than one certificate for that scId.
- Replace the two reachable `assert(isBlockTopQualityCert)` consensus guards (main.cpp:3764 and the disconnect mirror at 2886) with a `state.DoS(100, ...)` rejection so a malformed block can never abort the process.

Both changes are required: the block-level uniqueness check closes the reachability, and demoting the asserts to graceful rejections provides defense-in-depth against any other path that could make a non-ceasing cert non-top.
