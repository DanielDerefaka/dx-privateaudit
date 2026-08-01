# Critical: Missing cross-state validation on x/mint MaxSupply drives ecosystem mint supply negative, panicking BeginBlocker into an unrecoverable total chain halt

**Target:** allora-chain L1 (x/mint emissions/inflation module)  
**Severity:** Critical  
**Slug:** `allora-mint-maxsupply-chain-halt`

## Impact

A routine MaxSupply reduction that passes every validation gate makes every validator panic in BeginBlocker every block, permanently halting the network with recovery only via hard fork.

## Proof of Concept

TestPoC_UnrecoverableChainHaltViaMaxSupplyRegression (real keepers: Params.Validate() accepts the bricking value, GetEcosystemMintSupplyRemaining = -2.81e25, BeginBlocker panics on blocks 2 and 3); poc_regtest_mint_halt.sh drives the real allorad binary + CometBFT to a CONSENSUS FAILURE with a baseline arm that commits blocks normally.

## Submission notes / caveats

Trigger is a mutable whitelist-admin MsgUpdateParams (semi-trusted, not x/gov/timelock) OR a genesis author needing no key — the genesis vector forecloses a purely-privileged framing. SECURITY.md rubric names 'chain halts' as Critical impact-only. Frame around the genesis/no-key vector to pre-empt a trusted-role downgrade.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `allora-chain/validated_issues/ISSUE-1.md`
- [`report-mint-maxsupply-chain-halt.md`](./report-mint-maxsupply-chain-halt.md) — write-up, from `allora-chain/report-mint-maxsupply-chain-halt.md`
- [`advisory-mint-maxsupply-chain-halt.md`](./advisory-mint-maxsupply-chain-halt.md) — write-up, from `allora-chain/advisory-mint-maxsupply-chain-halt.md`
- [`POC__poc_halt_test.go`](./POC__poc_halt_test.go) — PoC, from `allora-chain/x/mint/module/poc_halt_test.go`
