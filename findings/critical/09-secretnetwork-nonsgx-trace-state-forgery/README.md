# Critical: Unauthenticated remote execution traces in non-SGX replay nodes enable arbitrary cross-module state forgery / native SCRT minting

**Target:** SecretNetwork (scrtlabs/SecretNetwork non-SGX replay subsystem)  
**Severity:** Critical  
**Slug:** `secretnetwork-nonsgx-trace-state-forgery`

## Impact

A network MITM (or rogue SGX backend) on the plaintext gRPC trace link forges arbitrary bank/staking/gov state on non-SGX replay nodes — spendable SCRT minted from nothing, escalating to canonical chain-state forgery / chain-halt under non-SGX voting power.

## Proof of Concept

PoC1 TestPoC_NonSGXTraceInflation (production ApplyCrossModuleOps forges a spendable 10T uscrt bank balance) and PoC2 over real TCP with production EcallClient using insecure.NewCredentials(); PoC3 live single-validator regtest via mocksgx. The sole harness change faithfully mirrors production store registration; git status confirms no production code modified.

## Submission notes / caveats

Genuine-but-gated: the Critical ceiling (canonical forgery / unlimited mint at >=2/3 non-SGX voting power) is conditioned on a non-SGX validator deployment scrtlabs is actively onboarding; the present-tense PoC-proven floor is single-node (High) via plaintext-link MITM. Present both tiers honestly; the non-SGX feature line is experimental.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `SecretNetwork/validated_issues/ISSUE-1.md`
- [`ISSUE-2.md`](./ISSUE-2.md) — write-up, from `SecretNetwork/validated_issues/ISSUE-2.md`
- [`BUG_BOUNTY_REPORT.md`](./BUG_BOUNTY_REPORT.md) — write-up, from `SecretNetwork/BUG_BOUNTY_REPORT.md`
- [`POC__MAINNET_POC.md`](./POC__MAINNET_POC.md) — write-up, from `SecretNetwork/MAINNET_POC.md`
- [`POC__poc_nonsgx_inflation_test.go`](./POC__poc_nonsgx_inflation_test.go) — PoC, from `SecretNetwork/x/compute/internal/keeper/poc_nonsgx_inflation_test.go`
- [`POC__poc_grpc_e2e_test.go`](./POC__poc_grpc_e2e_test.go) — PoC, from `SecretNetwork/x/compute/internal/keeper/poc_grpc_e2e_test.go`
