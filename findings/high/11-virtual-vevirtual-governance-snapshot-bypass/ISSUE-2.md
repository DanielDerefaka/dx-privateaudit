# ISSUE-2: Non-historical voting-power snapshot in `VirtualProtocolDAOV2` via `veVirtual.balanceOfAt` (autoRenew bypasses the time guard)

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High (escalates to Critical on a deployment where the lock-based Governor/Defender is the live, value-controlling governance)
**Original Claimed Severity**: High → Critical (conditional)
**Pipeline Exit Point**: Step 4 (full pipeline; no early invalidation)
**Confidence**: HIGH

## Summary
`veVirtual.balanceOfAt(account, timestamp)` is not a historical checkpoint — it sums the account's **current** `locks[]` array, and for `autoRenew` locks `_balanceOfLockAt` returns full weight **before** the `timestamp < lock.start` guard. Because `VirtualProtocolDAOV2._getVotes` (and `Defender.countVotes`) source voting weight from `balanceOfAt(account, proposalSnapshot)`, an account holding zero power at the snapshot can stake `autoRenew` afterward and have full weight counted retroactively at the snapshot timepoint — defeating the OZ Governor snapshot, the single primitive that pre-commits voting power. The code defect is unambiguous and mechanically proven; severity is gated by capital and deployment preconditions.

## Location
- `contracts/token/veVirtual.sol:93-102` (`balanceOfAt` — iterates current `locks[]`)
- `contracts/token/veVirtual.sol:115-137` (`_balanceOfLockAt` — `autoRenew` early-return at L124-126 precedes the time guard at L128)
- `contracts/governance/VirtualProtocolDAOV2.sol:231-237` (`_getVotes` → `_token.balanceOfAt`)
- `contracts/governance/VirtualProtocolDAOV2.sol:247-266` (`_castVote` reads weight at `proposalSnapshot`)
- `contracts/governance/Defender.sol:278-281` (`countVotes` → `veVirtual.balanceOfAt(voter, finalizedAt)` — second consumer)
- `contracts/token/StakedToken.sol:149-176` (`stake` hardcodes `autoRenew=true`; same defective `balanceOfAt` at L99-143)

## Justification

### Root cause — confirmed in source
`balanceOfAt` (veVirtual.sol:93-102) loops over `locks[account]` (the present array) and sums `_balanceOfLockAt(lock, timestamp)`. It reads no per-timestamp checkpoint, so a lock created *after* a queried timestamp still contributes to that timestamp's result.

`_balanceOfLockAt` (L115-137):
```solidity
uint256 value = _calcValue(lock.amount, lock.autoRenew ? maxWeeks : lock.numWeeks);
if (lock.autoRenew) {
    return value;            // L124-126 — returns full weight, unconditional on time
}
if (timestamp < lock.start || timestamp >= lock.end) {
    return 0;                // L128 — guard is unreachable for autoRenew locks
}
```
For an `autoRenew` lock, the function returns full weight for **any** `timestamp`, including a timestamp *before the lock existed*. This directly contradicts the function's own NatSpec (L90-91: "If the timestamp is before the lock was created, it will return 0"). The non-autoRenew path *does* honor the guard (returns 0 for `timestamp < lock.start`), confirming the historical-zero behavior was intended — the autoRenew early-return is the defect.

### Reachability / consumer wiring
- `VirtualProtocolDAOV2._getVotes` (L236) reads `_token.balanceOfAt(account, timepoint)`, and `_castVote` (L256) passes `proposalSnapshot(proposalId)` as the timepoint. `_token` is `IVEVirtual` — `balanceOfAt` is the only voting-power source.
- `Defender.countVotes` (L278) independently reads `veVirtual.balanceOfAt(voter, proposal.finalizedAt)`. Same root cause; a voter can stake `autoRenew` after `finalizedAt` and still be counted.
- `veVirtual.stake(amount, numWeeks, autoRenew=true)` is permissionless; `StakedToken.stake` hardcodes `autoRenew=true`. The autoRenew path is the default, trivially reachable state — not an edge case.

### Attack path (permissionless, no privileged role)
1. Proposal `P` created; `proposalSnapshot(P) = T`. Attacker holds 0 veVIRTUAL.
2. `votingDelay` elapses → `P` Active. Attacker calls `veVirtual.stake(amount, maxWeeks, true)` — a new lock with `start > T`.
3. `castVote(P, For)` → `weight = balanceOfAt(attacker, T)` returns full staked weight (autoRenew bypasses the `T < lock.start` guard).
4. With `forVotes ≥ quorum` and `forVotes > againstVotes`, `P` → `Succeeded`. `VirtualProtocolDAOV2` inherits **no** `GovernorTimelockControl` (verified: no `TimelockController`/`GovernorTimelock` in `contracts/governance/`), so `execute(...)` runs arbitrary calls immediately.

### Why this is a real defect, not by-design
- NatSpec explicitly promises historical-zero behavior that the autoRenew path violates.
- Git commit `a35aa7b` ("voting power should [be] the amount at voteStart") changed `_getVotes(account, block.timestamp)` → `_getVotes(account, proposalSnapshot)`, showing clear intent for snapshot-frozen voting. The fix corrected the call site but left the non-historical data source, so the exploit survives the attempted fix for autoRenew locks.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | Attack requires a trusted/privileged role | Step 2 (Roles) | FAILS | Attacker is a permissionless staker + voter; proposer needs only `proposalThreshold` (can be low/0). `setTotalSupply` is admin-set but is normal operation, not an attack gate. No trusted-actor downgrade applies. |
| 2 | Behavior is intended (balanceOfAt not meant to be historical) | Step 4 (Generator) | FAILS | NatSpec L90-91 and the non-autoRenew guard both implement historical-zero; commit `a35aa7b` shows snapshot intent. Defect, not design. |
| 3 | Non-autoRenew path already returns 0 for future locks, so the snapshot is fine | Step 4 (Generator) | FAILS | Correct for non-autoRenew, but `StakedToken.stake` and the default `veVirtual.stake(...,true)` use autoRenew, which bypasses the guard entirely. Attack uses the autoRenew path. |
| 4 | Vulnerable consumer (VirtualProtocolDAOV2 / Defender) not deployed on mainnet | Step 4 (Generator) | DOWNGRADE (severity only) | Report concedes the V2 Governor consumer was not located live; the safe `contracts/dev/veVirtualToken.sol` (checkpointed) backs the deployed legacy DAOs. This limits realized likelihood/fund-loss but does not invalidate a real bug in in-scope governance code. Caps the *base* rating below Critical. |
| 5 | Not exploitable — capital must be locked, no free votes | Step 4 (Generator) | DOWNGRADE (severity only) | True: autoRenew locks cannot be withdrawn early (`withdraw` requires `autoRenew==false`); attacker must lock quorum-level capital ~`maxWeeks` (~2 yrs). Reduces likelihood to Medium; the bug's contribution is reactive, post-snapshot timing with no warning window, not zero-cost voting. |

## Severity Calibration
- **Impact: High** — where the Governor/Defender controls treasury/upgrades, a passed proposal executes arbitrary calls with no timelock → governance takeover / full treasury drain. PoC drains 500,000 VIRTUAL in one executed proposal.
- **Likelihood: Medium** — requires quorum-level veVIRTUAL (~25% of supply) locked ~2 years (real, recoverable-but-locked capital) AND a live, value-controlling lock-based Governor consumer; the V2 Governor was not confirmed live on mainnet during review.
- Impact High × Likelihood Medium = **High** (severity matrix). Escalates to **Critical** only on a deployment where the lock-based V2 Governor/`Defender` is the live treasury/upgrade-controlling governance and veVIRTUAL is concentrated enough for one actor to reach quorum+majority. The report's own "High → Critical conditional" framing is consistent with this; the conditional-Critical is a deployment-dependent escalation, not the defensible base rating.

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — all three components present (location, mechanism, impact); every cited file/function/line verified to exist and match the report (read of veVirtual.sol, VirtualProtocolDAOV2.sol, StakedToken.sol, Defender.sol, GovernorCountingVP.sol, IVEVirtual.sol).
- **Step 2 (Privileged Roles)**: NO_ISSUE — attack path is permissionless; no trusted-actor cap applies.
- **Step 3 (Generic Check)**: Verified orchestrator-direct (mechanical, fully decidable from 4 files). No generic invalidation reason holds.
- **Step 4 (Adversarial Check)**: 5 issue-specific reasons considered (above). Two design/reachability reasons FAIL; two deployment/capital reasons are genuine severity limiters (DOWNGRADE), not invalidators. Judge verdict: VALID at High.
- **Final Severity**: High (conditional Critical on deployment) — adjusted down from the report's headline Critical due to capital + deployment-uncertainty preconditions, consistent with the report's own honest calibration.

## Note on verification method
The core claim is purely mechanical (an early `return` preceding a guard, in a function used verbatim as the governance voting-power source) and is fully decidable by reading the cited contracts. All consumer wiring (`_getVotes`, `_castVote`, `Defender.countVotes`), the hardcoded-autoRenew default (`StakedToken.stake`), and the absence of a timelock were verified directly. No external-protocol research was required.
