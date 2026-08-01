# ISSUE-2: Concurrency TOCTOU in provider voucher accounting leads to unbounded theft of service

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High
**Original Claimed Severity**: High
**Pipeline Exit Point**: Step 4 (4D — no adversarial reason held; neutral judge not required)
**Confidence**: HIGH

## Summary
The DRAIN provider validates voucher sufficiency and nonce against in-memory channel state
*before* the long `await` on the upstream LLM call, and records the charge only *after* it, with
no atomic reservation in between. N concurrent requests carrying one voucher therefore all read
identical pre-update state, all pass every guard, and all are served. All seven invalidation
reasons tested — three from the generic library, four issue-specific and adversarially generated —
failed against the code. The defect is real, permissionless, structural (not a narrow timing win),
and present in four live marketplace providers as well as the live-deployed reference provider.

## Location
- `provider/src/drain.ts:89-205` — `validateVoucher` (`await readContract` at :103; `previousTotal`
  read at :135; nonce check at :156)
- `provider/src/drain.ts:210-233` — `storeVoucher` (sole mutator: `totalCharged += cost` at :226)
- `provider/src/index.ts:126-133` — pre-auth with `minOutputTokens = 50`
- `provider/src/index.ts:158-210` — streaming branch; `storeVoucher` at :201 runs only after the
  `for await` loop fully drains, i.e. after delivery
- `provider/src/storage.ts:129-131,136-139` — `getChannel` (by-reference / `null`), `updateChannel`
  (last-write-wins)
- `providers/hs58-claude/src/index.ts:184,188,229,270` — same shape, live marketplace provider,
  attacker-controlled `max_tokens: req.body.max_tokens || 4096`

## Justification

**Step 1** verified every claimed location against source. **Step 2** found no privileged role in
the attack path — the attacker is an ordinary permissionless consumer with a funded wallet
(README.md:70), so no trust-model severity cap applies. **Step 1.5** was a no-op: no external DeFi
protocol behaviour is load-bearing.

**Step 3 (generic, 0/3 held).** No application-level rate limiter, connection cap, mutex or queue
exists in any of the five providers — middleware is `cors()` + `express.json()` and no limiter is
even a dependency; Railway's documented defaults (10k concurrent connections, no per-IP limit) sit
~100x *above* the demonstrated N=100. The PoC's 400 ms mock does not exaggerate the race window —
it **understates** it, because the window closes only when the stream fully drains, so a real
token-by-token completion widens it by an order of magnitude. Every guard in the request path was
traced against the 2nd..Nth concurrent request and none blocks: the `minOutputTokens=50` pre-auth
is a lower-bound floor constant in N; `amount > deposit` bounds one voucher, not aggregate
delivery; the nonce guard short-circuits entirely because `lastVoucher` is `undefined`; signature
verification is stateless and verifies the same signature N times.

**Step 4 (adversarial, 0/4 held).** The strongest reason — that shared-reference `ChannelState`
bounds the per-channel take — is *factually correct about the mechanism* and corrects the report
(see Corrections below), but raises rather than lowers the per-channel ratio and does not survive
as an invalidation, since `DrainChannel.open` has no minimum deposit or duration and channel
rotation costs ~$0.001-0.01 of gas. The duplicate/marginal-impact argument fails two independence
tests: fixing FINDING-3 leaves FINDING-1 losing `(N-1)·c` per burst permanently (`DrainChannel.sol`
reverts for any amount never signed, so delivered-minus-signed is unrecoverable at *any* threshold
setting), and fixing FINDING-2 with a post-cost recheck alone leaves FINDING-1 fully working. The
"documented reference-implementation gap" defense fails on mechanism and on scope: "add rate
limiting" is a throughput control, not mutual exclusion (a limiter permitting 5 concurrent requests
still yields 5x theft per voucher); "use a database" is strictly weaker than the fix, which the
report itself says can be an in-process mutex requiring no database at all; no doc anywhere warns
about concurrency, atomicity or races, while README.md:226 affirmatively *promises* providers are
protected against double-spend; and the four Handshake58 providers carry no such caveat at all.
The Polygon RPC chokepoint is real (upstream hardcodes viem's default `https://polygon-rpc.com`
with no config path) but bounds arrival rate, not the ratio — throttled reads 402 *before* the LLM
call, so they subtract from the provider's loss without ever adding to the attacker's cost.

**Severity.** High is retained. The loss is the operator's off-chain inference spend, not in-contract
TVL — the contracts are fund-safe — but it is permissionless, repeatable, requires no privileged
role, needs only ~$0.01 of gas per cycle, and violates a documented protocol guarantee
(README.md:226, "Provider | Double-spend | USDC locked in contract"). The affected components
include four deployed marketplace providers and a reference provider the project itself advertises
as "Online" at a live URL with a real API key.

## Invalidation Reasons Tested

| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | AM-3 Circuit breaker / rate limit bounds damage | Step 3 (Generic) | FAILS | No limiter in any of 5 providers; no dep; bare Dockerfile; Railway defaults 10k concurrent, no per-IP cap; upstream LLM quotas bound rate not ratio, and are charged to the victim's key |
| 2 | IM-4 Theoretical max vs realistic impact | Step 3 (Generic) | FAILS | Window closes only after `for await` fully drains, so a real stream *widens* it vs the 400 ms mock; race is structural, not a timing win |
| 3 | EG-5 Existing validation prevents the vector | Step 3 (Generic) | FAILS | All six guards traced with concrete values; none is a function of N; nonce guard short-circuits on `undefined lastVoucher` |
| 4 | Shared-ref `ChannelState` bounds take to ~2N/channel | Step 4 (Adversarial) | FAILS | Mechanism claim correct and verified against `provider/data/vouchers.json`; but burst-2 ratio is ~197x at N=100 and channel rotation costs ~$0.01 |
| 5 | Marginal over FINDING-2+3; score the pair once | Step 4 (Adversarial) | FAILS | Survives both independence tests; F3 is the config-dependent Low-Medium finding, a doubly weak yardstick; dedup runs the other way (F1 subsumes F2) |
| 6 | Documented reference-impl gaps cover it | Step 4 (Adversarial) | FAILS | Neither caveat covers a control-flow race; no concurrency warning exists anywhere; README.md:226 promises the opposite; live providers carry no caveat |
| 7 | Polygon RPC chokepoint caps N in production | Step 4 (Adversarial) | FAILS | viem 2.44.4 default `polygon-rpc.com` confirmed from node_modules; retries 429s; throttled reads 402 before the LLM call so they cost the provider nothing |

## Corrections the report should absorb (none change the verdict)

1. **Mechanism overstated.** `provider/src/drain.ts:43-45`'s claim that "after N concurrent requests
   the stored `totalCharged` reflects one charge, not N" holds **only on a never-before-seen
   channel**. On a channel with prior stored state, all N alias the same object by reference and
   accounting accumulates correctly. Per-channel take is therefore ~2N deliveries before the
   accounting self-corrects. "The attack repeats across vouchers" is wrong for the same channel;
   "repeats across channels" (~$0.001-0.01 gas each) is exactly right.
2. **"Unbounded" is loose.** N is bounded in production by
   `min(RPC throughput, upstream LLM concurrency, window width)`. The *ratio* remains linear in N
   and the demonstrated 100x is reachable under realistic parameters, so the impact class stands —
   but the adjective should be qualified.
3. **Dollar figures are retail at config defaults.** The deployed provider documents lower rates
   than `config.ts` defaults, and true upstream cash cost is lower still. The report does label
   them "retail", so the framing is honest; the over-delivery ratio is pricing-independent.
4. **"on-chain claimed $0"** is inherited from FINDING-3's threshold behaviour. Better stated as:
   the provider recovers at most one voucher per burst, and `(N-1)/N` of delivered value is
   unrecoverable at *any* threshold setting.
5. **If the program dedups**, fold FINDING-2 into FINDING-1 as the bounded special case at
   FINDING-1's severity — not the reverse. FINDING-3 is a different function and a different fix
   and should not be merged with either.

## Note on conflicting checker evidence
Two Step 4 checkers disagreed on per-channel accumulation. The reason-5 checker assumed each burst
re-creates fresh state (yielding "~27 bursts / ~$9,957 per channel"); the reason-4 checker proved
via unbroken object-identity tracing *and* the PoC's own persisted `provider/data/vouchers.json`
(100 stored voucher rows against `totalCharged = 90150`) that burst 2 accumulates correctly on a
shared reference. The better-evidenced analysis was adopted: **~2N deliveries per channel**, with
the inflated single-channel figure discarded.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all file/function/line references verified; PoC harness diff
  independently confirmed to be three env-gated network redirects only, no guard removed
- **Step 2 (Privileged Roles)**: SKIPPED — no privileged role in the attack path; no severity cap
- **Step 1.5 (External Research)**: SKIPPED — no external DeFi protocol dependency
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, 0 held → no early exit at 3C
- **Step 4 (Adversarial Check)**: 5 reasons generated, 1 dropped as duplicate of IM-4, 4 checked,
  0 held → Step 4C judge not required
- **Final Severity**: High (unchanged from claimed)
