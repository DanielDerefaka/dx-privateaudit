# High: Pegout signed with another pegout's segwit input amounts during federation migration (findFirst over pegout_transaction_created ignores btcTxHash) -> frozen withdrawal + peg/migration halt

**Target:** powpeg-node (Rootstock PowPeg federation signing node)  
**Severity:** High  
**Slug:** `powpeg-migration-outpoint-misattribution-freeze`

## Impact

A batched user withdrawal is signed with the migration pegout's BIP143 input amounts, permanently freezing the withdrawal and (conditionally) reverting every subsequent updateCollections, halting pegouts and federation rotation on the live PowPeg bridge.

## Proof of Concept

Committed unit test batchPegoutIsSignedWithMigrationPegoutOutpointValues_soSigHashIsWrong runs against real ReleaseCreationInformation + SegwitSigHashCalculatorImpl under BridgeMainNetConstants; a full regtest two-way-peg (rootstock-integration-tests, real federate-node jars) shows the withdrawal stuck in pegoutsWaitingForSignatures ('BUG REPRODUCED ON-CHAIN').

## Submission notes / caveats

Arms only during a federation migration window (getRetiringFederationAddress() currently empty; fires at next scheduled rotation). The single frozen user withdrawal is unconditional; the network-wide halt is ~50% conditional on pre-RSKIP559 HashSet ordering. Recoverable via coordinated 5-of-9 signer upgrade (no hard fork) — which is why final severity is capped at High.

## Files in this folder

- [`report.md`](./report.md) — write-up, from `powpeg-node/report.md`
- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `powpeg-node/validated_issues/ISSUE-1.md`
- [`ISSUE-2.md`](./ISSUE-2.md) — write-up, from `powpeg-node/validated_issues/ISSUE-2.md`
- [`POC__OutpointValuesMisattributionPoCTest.java`](./POC__OutpointValuesMisattributionPoCTest.java) — PoC, from `powpeg-node/src/test/java/co/rsk/federate/signing/hsm/message/OutpointValuesMisattributionPoCTest.java`
