# High: Concurrency TOCTOU in provider voucher accounting -> unbounded theft of service

**Target:** DRAIN — ERC-8190 signed-voucher payment-channel LLM inference marketplace (reference + 4 live handshake58.com providers)  
**Severity:** High  
**Slug:** `drain-voucher-toctou-theft-of-service`

## Impact

One signed voucher for a single request yields N concurrent full completions (100x demonstrated), draining a provider's off-chain inference budget at an arbitrary multiple of what it is paid.

## Proof of Concept

exploit-race.mjs opens one channel, signs ONE voucher, fires N concurrent stream:true requests; observed 100/100 delivered (~400k tokens, ~$9 retail) with on-chain claimed $0. Reproduced against the REAL unmodified provider/src/index.ts and the REAL DrainChannel contract on a local anvil chain (chainId 137); only the external OpenAI upstream is mocked.

## Submission notes / caveats

Loss is the operator's off-chain LLM budget, not in-contract TVL — the program must score provider-operator loss (the contracts themselves are fund-safe). Defect is replicated verbatim in 4 live marketplace providers; README.md:226 promises providers ARE protected from double-spend (novel, not marked known).

## Files in this folder

- [`ISSUE-2.md`](./ISSUE-2.md) — write-up, from `DRAIN/validated_issues/ISSUE-2.md`
- [`FINDING-1-toctou-unbounded-theft-of-service.md`](./FINDING-1-toctou-unbounded-theft-of-service.md) — write-up, from `DRAIN/findings/FINDING-1-toctou-unbounded-theft-of-service.md`
- [`POC__exploit-race.mjs`](./POC__exploit-race.mjs) — PoC, from `DRAIN/poc/exploit-race.mjs`
