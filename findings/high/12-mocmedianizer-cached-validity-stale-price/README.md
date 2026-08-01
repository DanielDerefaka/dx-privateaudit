# High: Cached validity in Medianizer serves expired / voided / quorum-invalid prices as valid via peek()/read()

**Target:** Money on Chain / RSK MoCMedianizer (Amphiraos-Oracle)  
**Severity:** High  
**Slug:** `mocmedianizer-cached-validity-stale-price`

## Impact

Expired, voided or quorum-invalid oracle prices keep passing peek().has / read() and downstream require(has) fund gates until someone happens to call poke().

## Proof of Concept

Truffle regression test (3 passing: expiry, PriceFeed.poke, PriceFeed.void all leave peek().has=true while compute().has=false) plus a forked-mainnet script showing 3 of 4 LIVE deployed RSK medianizers already peek.has=true / compute.has=false at pristine block 9068970, empirically refuting the 'feeders post often enough' defense.

## Submission notes / caveats

The cached boolean is the documented IMoCBaseOracle.peek() integration guard and gates a require(has) in the production consumer MoCState.sol. Rated High (oracle-component), not standalone Critical — no in-scope permissionless-theft PoC is bundled with this bug alone. Expiry trigger is unpermissioned (no trusted-admin cap). Distinct from upstream issue #9.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `Amphiraos-Oracle/validated_issues/ISSUE-1.md`
- [`ISSUE-1-submission.md`](./ISSUE-1-submission.md) — write-up, from `Amphiraos-Oracle/validated_issues/ISSUE-1-submission.md`
- [`SRC__ISSUE-1-CachedValidity-truffle-test.js`](./SRC__ISSUE-1-CachedValidity-truffle-test.js) — source, from `Amphiraos-Oracle/validated_issues/poc/ISSUE-1-CachedValidity-truffle-test.js`
- [`SRC__ISSUE-1-fork-mainnet-cached-validity.js`](./SRC__ISSUE-1-fork-mainnet-cached-validity.js) — source, from `Amphiraos-Oracle/validated_issues/poc/ISSUE-1-fork-mainnet-cached-validity.js`
