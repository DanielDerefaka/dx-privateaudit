# ISSUE-1: Cached Validity in Medianizer Lets Expired or Quorum-Invalid Prices Remain Valid

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High
**Original Claimed Severity**: High (oracle component); Critical-risk downstream
**Pipeline Exit Point**: Step 4 (full pipeline; no early exit)
**Confidence**: HIGH

## Summary
`Medianizer.peek()`/`read()` return a cached `has` validity flag written only by `poke()`, never re-checking feed expiry, quorum (`min`), or the live feed set. Expired or quorum-invalid prices are therefore served as valid until the next `poke()`. The bug is real, contradicts the contract's own documented API, was observed live on 3 of 4 deployed RSK mainnet medianizers at a pristine fork block, and reaches a production consumer (`MoCState.sol`) that gates fund operations on `require(has)` with no independent freshness check.

## Location
- `contracts/medianizer/medianizer.sol:76-90` — `poke()`, `peek()`, `read()` cache behavior
- `contracts/medianizer/medianizer.sol:92-131` — `compute()` live validity checks
- `contracts/price-feed/price-feed.sol:31-39` — feed-level `now < zzz` expiry

## Justification
All three components of the initial sweep verified verbatim against the source. `poke()` (medianizer.sol:76-81) is the sole writer of `val`/`has`; `peek()`/`read()` (83-90) return the storage variable without consulting `compute()` (92-131), which is the only code that performs the live per-feed `DSValue.peek()` and `ctr < min` checks. The divergence is genuine.

Six independent adversarial checkers (3 generic-library + 3 issue-specific) were run; **all six failed to invalidate** the finding:

- **AM-1 / US-2 (state self-resets):** FAILS. The only automatic reset is `PriceFeed.post()` → `med_.poke()`, which fires only when a feeder posts — precisely the event whose absence creates the staleness. Reachable indefinite-divergence states are trivially enumerable (feeder outage; `setMin`/`unset`/`PriceFeed.void()` with no subsequent post). Additionally `PriceFeed.poke(val,zzz)` (price-feed.sol:42-46) and `PriceFeed.void()` (55-58) update/kill a feed **without** poking the medianizer, so the cache lags even while feeds are actively updated. No heartbeat, keeper registry, or on-chain incentive to `poke()` exists anywhere in the repo.
- **TI-4 (heartbeat keeps prices fresh):** FAILS — it inverts. The bug manifests exactly when the heartbeat fails, so a liveness argument cannot refute it. `minValues: 1` across all configs means a single feeder outage suffices; the window is unbounded (T + until an arbitrary future poke), not 300s.
- **`compute()` is a public live accessor:** FAILS. The sole published integration interface, `IMoCBaseOracle` (README), exposes only `peek()`; `compute()` appears in no integration doc. The README documents `peek()`'s boolean as "the price is out of time limit" — a live time-validity signal the cache does not deliver. The cache violates the contract's own documented API semantics.
- **Fork evidence is a fork-clock artifact:** FAILS — evidence is genuine. Headline C-01 samples were taken at block 9068970's real timestamp with no `evm_increaseTime` (the warps are snapshot-reverted). The RIF/USD control reading `compute.has=true` at the same block proves the EVM clock was not advanced. 3 of 4 mainnet medianizers were genuinely already stale-served-as-valid at a real block — empirically refuting the "feeders post frequently enough" defense.
- **No attacker-controlled trigger:** FAILS to invalidate (proposed DOWNGRADE_TO_medium). An oracle-staleness exploit needs the attacker to *detect and time* a payoff, not to *cause* the outage; permissionless `poke()` cannot be interleaved into the attacker's own atomic transaction to flip `has` false; and passive user harm alone qualifies. Its valid kernel (liveness precondition, not attacker-summonable) bears on severity, not validity.

**External research:** The cached-`has` model is inherited from the MakerDAO/DappHub keeper oracle, where staleness is a documented operational risk mitigated only by keeper incentives (Tub/Vox read `pip.read()`/`peek()` directly). However: (1) no public disclosure covers the **medianizer-level** cached-`has` problem — upstream issue #9 is scoped to the distinct `PriceFeed.zzz` TTL layer; the CoinFabrik MoC audit flags only a naming nitpick in the oracle. (2) MoC's own production consumer `RDOC-Contract/MoCState.sol` reads `priceProvider.peek()` and does `require(has, "Oracle have no Price")` with no `poke()` first, and `Proxy_Oracle/ProxyMoCMedianizer.peek()` is a pure pass-through — so the broken boolean is load-bearing for real fund operations.

**Severity:** No Step-2 admin cap applies, because trigger 1 (feed expiry) is unpermissioned and stands alone regardless of the two governance-gated triggers. Claimed High is retained rather than downgraded to Medium: the one Medium recommendation rests on "requires total feeder outage under min=1," a low-likelihood premise that the live-mainnet observation (3/4 oracles already in the stale state at a real block) materially undercuts, and the boolean reaches a `require(has)`-gating production consumer. Standalone Critical is **not** supported — a fully quantified unpermissioned economic-theft PoC is not shown in-scope (the fund-moving PoC is the separate privileged-post H-01), and no in-scope consumer exists. This matches the report's own calibration ("Medium/High, avoid standalone top-severity"). Medium is a defensible alternative; the pipeline lands on High.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | AM-1 separate function resets state | Step 3 (Generic) | FAILS | Only `post()`→`poke()` resets; disabled by the outage that causes the bug; `poke(val,zzz)`/`void()` skip the medianizer |
| 2 | US-2 previous op always resets variable | Step 3 (Generic) | FAILS | Reset conditional, not guaranteed; enumerable indefinite-stale states; no on-chain poke incentive |
| 3 | TI-4 update frequency prevents staleness | Step 3 (Generic) | FAILS | Inverts — bug requires heartbeat failure; unbounded window; `min=1` → single outage suffices |
| 4 | `compute()` is a public live accessor | Step 4 (Specific) | FAILS | Published `IMoCBaseOracle` exposes only `peek()`; README documents boolean as live time-limit signal; cache violates documented API |
| 5 | Fork evidence is a fork-clock artifact | Step 4 (Specific) | FAILS | Sampled at pristine block, no warp; RIF/USD control proves clock not advanced; live-chain fact |
| 6 | No attacker-controlled trigger | Step 4 (Specific) | FAILS (→ severity) | Attacker times payoff, not cause; atomic exploit beats permissionless poke; passive harm qualifies; caps to High/Medium |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all cited files/functions/lines verified verbatim; mechanism internally consistent.
- **Step 2 (Privileged Roles)**: NO CAP — triggers 2 & 3 are governance-gated, but the unpermissioned expiry trigger (1) stands alone, so the issue does not reduce to trusted-admin abuse.
- **Step 1.5 (External Research)**: Cached model inherited from MakerDAO keeper oracle (documented staleness risk). No prior public disclosure of the medianizer-level variant (issue #9 is feed-TTL layer). Production consumers (MoCState.sol, Proxy_Oracle) trust `peek()` with no forced refresh.
- **Step 3 (Generic Check)**: 3 reasons selected, 3 checked, 0 held → no early exit.
- **Step 4 (Adversarial Check)**: 5 reasons generated, top 3 checked, all FAILS; no 4B HOLDS → Step 4C judge not triggered. One checker recommended Medium on likelihood grounds, weighed and overruled in favor of High.
- **Final Severity**: High (unchanged from claimed oracle-component severity; standalone Critical not supported).
