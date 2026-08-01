# Critical: Post-condition-mode type confusion renders a false 'nothing will leave your account' confirmation for an Allow-mode legacy Stacks tx

**Target:** Leather wallet (leather-io extension, published Chrome build 6.107.0)  
**Severity:** Critical  
**Slug:** `leather-postcondition-allow-mode-drain`

## Impact

A connected dApp sends a legacy contract_call with postConditionMode:'allow' (string) and Leather affirmatively tells the user nothing can leave their account while broadcasting an unrestricted Allow-mode tx that can drain their STX, every FT and every NFT.

## Proof of Concept

Playwright e2e (transactions.spec.ts) drives the exact legacy-tx screen against real published code and asserts a real broadcast POST; screenshot shows the Allow-warning ABSENT + lock-panel PRESENT (a combination impossible for numeric Allow), and the string->Allow(1) coercion was confirmed by reading the published @stacks/transactions@7.5.0 tarball.

## Submission notes / caveats

Live shipped artifact confirmed via Google CRX endpoint (v6.107.0, released 2026-07-23) matching the repo tag. Maps to the Leather HackerOne Critical category 'Malicious interactions with an already-connected wallet'. DUPLICATE status UNVERIFIED (HackerOne disclosure list is client-rendered and could not be read; no GitHub advisory/PR fixes it) — dup-check before submission.

## Files in this folder

- [`ISSUE-1.md`](./ISSUE-1.md) — write-up, from `leather/validated_issues/ISSUE-1.md`
- [`REPORT.md`](./REPORT.md) — write-up, from `leather/REPORT.md`
- [`POC__transactions.spec.ts`](./POC__transactions.spec.ts) — PoC, from `leather/mono/apps/extension/tests/specs/transactions/transactions.spec.ts`
