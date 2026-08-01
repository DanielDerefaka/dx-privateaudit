# ISSUE-1: Non-historical voting-power snapshot in VirtualProtocolDAOV2 (veVirtual.balanceOfAt) enables post-snapshot vote acquisition

## Pipeline Result
**Verdict**: VALID
**Final Severity**: High (Critical-conditional — see Justification)
**Original Claimed Severity**: High → Critical (conditional)
**Pipeline Exit Point**: Step 4 (confirmed by direct code verification; no invalidation reason held)
**Confidence**: HIGH

## Summary
`VirtualProtocolDAOV2` weights votes via `veVirtual.balanceOfAt(account, proposalSnapshot)`, but `balanceOfAt` is not a historical checkpoint — it sums the account's *current* locks, and for `autoRenew` locks returns full weight while skipping the time guard. A permissionless attacker holding zero voting power at the proposal snapshot can stake afterward and have full weight counted at the snapshot timepoint, defeating the Governor's snapshot primitive. Where this Governor controls a treasury (no timelock), this enables governance takeover and fund theft.

## Location
- `contracts/token/veVirtual.sol:93-102` (`balanceOfAt`) and `:115-137` (`_balanceOfLockAt`)
- `contracts/governance/VirtualProtocolDAOV2.sol:231-237` (`_getVotes`), `:247-266` (`_castVote`)
- `contracts/token/StakedToken.sol` (`stake` hard-codes `autoRenew = true`)
- `contracts/governance/Defender.sol:278` (second consumer, same source)

## Justification
Every load-bearing claim was verified directly against the repository source:

1. **`_getVotes` sources weight from `balanceOfAt`** — confirmed at `VirtualProtocolDAOV2.sol:236` (`return _token.balanceOfAt(account, timepoint);`).
2. **Weight is read at the snapshot** — confirmed at `:256` (`_getVotes(account, proposalSnapshot(proposalId), params)`).
3. **`balanceOfAt` is non-historical** — confirmed at `veVirtual.sol:98` (loops over the *current* `locks[account]` array, not a checkpoint).
4. **`autoRenew` bypasses the time guard** — confirmed at `veVirtual.sol:124-126`: for `autoRenew` the function `return value;` **before** the `if (timestamp < lock.start ...)` guard at `:128`. A lock created after the snapshot therefore returns full weight when queried at the snapshot timestamp. This contradicts the contract's own NatSpec at `:90-91` ("If the timestamp is before the lock was created, it will return 0"), which is strong evidence the behavior is an unintended defect, not by design. (For non-`autoRenew` locks the guard at `:128` *does* return 0 for a post-snapshot lock — so the exploit is specific to the `autoRenew` path, which is the default via `StakedToken` and is permissionlessly reachable via `veVirtual.stake(amount, weeks, true)`.)
5. **No timelock** — `VirtualProtocolDAOV2` inherits `Governor, GovernorSettings, GovernorStorage, GovernorCountingVP`; no `GovernorTimelockControl`. A `Succeeded` proposal can be executed immediately. Confirmed.
6. **Second consumer** — `Defender.countVotes` at `Defender.sol:278` reads the same `veVirtual.balanceOfAt(voter, proposal.finalizedAt)`, inheriting the same defect.

The supplied Hardhat PoC is consistent with the verified code: the same `balanceOfAt(attacker, snapshot)` query returns 0 before the post-snapshot stake and full weight after.

**Adversarial checks (none invalidated the finding):**
- *"Time guard catches the post-snapshot lock."* Refuted — the guard is unreachable for `autoRenew` (early `return` at `:125`).
- *"Behavior is intended."* Refuted — the function's own NatSpec promises 0 for pre-creation timestamps, and commit `a35aa7b` shows the team intended snapshot-frozen voting; the fix corrected the call site but not the data source.
- *"Trusted-role dependency."* Not applicable — the attack path (`stake` + `castVote`) is fully permissionless. `setTotalSupply`/`setMaxWeeks` are admin functions but are not part of the attack.

**Severity calibration (why High, not auto-Critical):** The bug does not mint votes — the attacker must still amass quorum (~25% per whitepaper) and a `forVotes > againstVotes` majority, and full retroactive weight requires an `autoRenew` lock, which cannot be withdrawn (`veVirtual.sol:206`) without first toggling off and waiting ~`maxWeeks` (~2 years). Impact High × Likelihood Medium ⇒ **High**. It escalates to **Critical** where this V2 Governor (or `Defender`) is confirmed live controlling a treasury/upgrade rights with veVIRTUAL concentrated enough for one actor to reach quorum+majority. The reporter honestly notes the vulnerable consumer was not located deployed on Base mainnet (only the `veVirtual` token is live), which is the reason the realized fund-loss tier is held at conditional rather than unconditional Critical. For a code audit the contract is in-scope and the defect is real regardless of current deployment.

## Invalidation Reasons Tested
| # | Reason | Source | Verdict | Evidence Summary |
|---|--------|--------|---------|-----------------|
| 1 | Time guard returns 0 for post-snapshot lock | Generic (input/state validation) | FAILS | autoRenew early-returns at veVirtual.sol:125 before guard at :128 |
| 2 | Behavior intended / by-design | Adversarial (design intent) | FAILS | NatSpec :90-91 promises 0; commit a35aa7b shows snapshot intent |
| 3 | Requires trusted role to act maliciously | Step 2 (privileged role) | FAILS | Attack path stake()+castVote() is permissionless |
| 4 | Capital lock (~2yr) makes attack unprofitable | Adversarial (economic) | DOWNGRADE-only | Real precondition; affects likelihood, not validity. Treasury > lock ⇒ profitable |
| 5 | Consumer not deployed with value at risk | Adversarial (impact reachability) | DOWNGRADE-only | Caps unconditional Critical; code is in-scope and defect is real |

## Pipeline Trace
- **Step 1 (Initial Sweep)**: PASSED — location, mechanism, and impact all present and verified to exist at claimed lines.
- **Step 2 (Privileged Roles)**: NO_ISSUE — attack path is permissionless; no trusted-role cap applies.
- **Step 3 / 4 (Generic + Adversarial Check)**: No invalidation reason held against the code. Two reasons downgrade-only (economic cost, deployment status), neither negates the defect.
- **Final Severity**: High (Critical-conditional on a live value-controlling deployment).
