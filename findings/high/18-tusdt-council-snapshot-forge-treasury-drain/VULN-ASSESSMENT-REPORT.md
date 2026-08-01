# TUSDT Smart Contracts — Vulnerability Assessment

**Target:** ink!/Substrate workspace @ commit `d1ba301` (`main`), 7 contracts (~7k LOC).
**Method:** phase-gated audit — recon → invariant catalog → 6 parallel breadth lenses (one per contract cluster) → depth traces → 4 validation gates. Source-level verification of every reported item; the pre-existing critical was re-derived independently from the code.
**Baseline:** `cargo test --workspace` → **21/39 tests FAIL** in `tusdt-election` (pre-existing, introduced by the `d1ba301` "finalized mainnet params" commit). Not modified.

Severity = impact × likelihood. Trust-model note: **maintainer** (elected) and **council** (5, any-1-acts) are semi-trusted insiders; a finding that only a maintainer/council key can trigger is a centralization/insider risk, called out as such.

---

## C1 · CRITICAL — A single council member forges the voting snapshot and drains the treasury (re-confirmed)

**Status:** Previously found and PoC-confirmed on regtest (`FINDING-critical-council-treasury-drain.md`, `tools/scripts/drainExploit.ts`). **Independently re-verified in source during this pass** — every link holds.

**Root cause.** `submit_snapshot` is gated by `ensure_council()` only (any 1 of 5) and stores a fully attacker-supplied `root` + `circulating_supply` with no validation:
- [governance/lib.rs:547-575](contracts/tusdt-governance/lib.rs#L547-L575) — writes `root`/`circulating_supply` verbatim.
- [governance/lib.rs:582-591](contracts/tusdt-governance/lib.rs#L582-L591) — `quorum = circulating_supply * quorum_bps / 10_000`; with `circulating_supply = 1` this truncates to **0**.
- [voting/src/lib.rs:105-111](voting/src/lib.rs#L105-L111) — `verify_merkle_proof` with an **empty proof** returns `leaf == root`. Attacker sets `root = leaf_hash(self, self, HUGE, 10_000)` and votes those exact values.
- [governance/lib.rs:744-751](contracts/tusdt-governance/lib.rs#L744-L751) → weight > 0; [:803-812](contracts/tusdt-governance/lib.rs#L803-L812) finalize sees quorum 0 met + 100% approval → **Passed**; [:835-856](contracts/tusdt-governance/lib.rs#L835-L856) execute → `treasury.release` → [treasury/lib.rs:204-259](contracts/tusdt-treasury/lib.rs#L204-L259) pays out.

**Impact.** Total unilateral treasury drain by one council member with zero legitimate stake. The **same forged root** is the electorate for the maintainer election ([election_snapshot](contracts/tusdt-governance/lib.rs#L534-L539), consumed verbatim by the election — see WIRE-03), escalating to maintainer capture → arbitrary oracle price (F10) → full protocol capture.

**Remediation.** k-of-n threshold on `submit_snapshot`; anchor `root`/`circulating_supply` to real on-chain subnet stake with a `circulating_supply` floor; reject trivial/empty proofs (min depth + leaf/node domain separation); snapshot quorum/approval thresholds into the proposal at submission.

---

## F2 · MEDIUM — Liquidation seizes 100% of collateral; the owner's residual equity is captured by the protocol, never returned

**Confidence:** high on behavior; severity gated on intent. Found independently by two lenses (auction + vault).

**Root cause.** `settle_liquidation_auction` sells the **entire** `auction.collateral_balance` to the winner and returns nothing to the borrower:
- [vault/lib.rs:880-898](contracts/tusdt-vault/lib.rs#L880-L898) — winner receives `collateral_sold − transaction_fee` (the full collateral).
- Winning-bid TUSDT enters the vault; principal is burned, interest → treasury ([:899-906](contracts/tusdt-vault/lib.rs#L899-L906)); the **surplus** `winning_bid − debt − fee` stays in the vault and is later swept to treasury via the permissionless [claim_surplus_tusdt](contracts/tusdt-vault/lib.rs#L538-L550).

A vault is liquidatable at `debt > collateral_value / 1.2` — i.e. collateral is worth ~1.2× debt, `min_bid = debt + 11% fee` ([risk.rs:65-76](contracts/tusdt-vault/risk.rs#L65-L76)). The ~9–20% of collateral value above debt+fee never returns to the owner. Standard CDPs (Maker) return post-penalty residual to the vault owner; this design does not.

**Impact.** Liquidated borrowers lose collateral value materially exceeding their debt on marginal dips. **Confirm intent:** if surplus-to-protocol is the intended penalty model it's a documented Medium; if unintended it's a High systemic value transfer away from users.

**Remediation.** After covering debt + liquidation fee, return residual collateral (or residual auction proceeds) to the vault owner; or switch to partial liquidation.

---

## F3 · MEDIUM — Deployed economic parameters diverge from documentation and were shipped with failing tests

**Root cause.** Commit `d1ba301` ("finalized mainnet params") changed defaults without updating docs, without reconciling inline comments, and without a green test suite:

| Param | Code default | Documented / comment | File |
|---|---|---|---|
| Oracle `min_submitter_stake` | `1e10` | `1e12` (its own adjacent comment + governance) | [oracle/lib.rs:17-18](contracts/tusdt-oracle/lib.rs#L17-L18) |
| Vault `interest_rate` | `1_000` bps = **10%** | 5% APR | [params.rs:5](contracts/tusdt-vault/params.rs#L5), README:214 |
| Vault `liquidation_fee` | `1_100` bps = **11%** | 1% (README + [risk.rs:63](contracts/tusdt-vault/risk.rs#L63) comment) | [params.rs:6](contracts/tusdt-vault/params.rs#L6) |
| `borrow_cap` | `5e12` | comment says "10 Thousand" | [params.rs:7](contracts/tusdt-vault/params.rs#L7) |

Plus **21 failing `tusdt-election` tests** at this commit.

**Impact.** The oracle stake floor is 100× below intent, halving the Sybil cost to influence the ≥3-reporter median (compounds F6/F7). Interest and liquidation-fee economics are 2× / 11× their documented values — either undocumented intent or transposition errors, each materially changing user cost. Shipping with red tests removes the safety net that would have caught these.

**Remediation.** Reconcile every default against a single source of truth; fix the oracle stake constant (or its comment); update README; make CI green before tagging a mainnet build.

---

## F4 · MEDIUM — Maintainer election does not revoke the outgoing council

**Root cause.** `elect_maintainer` / `activate` rotate only the maintainer account; council membership changes **only** via `set_council` (maintainer-gated):
- [governance/lib.rs:385-395](contracts/tusdt-governance/lib.rs#L385-L395) (elect_maintainer touches only `self.maintainer`), [election/lib.rs activate](contracts/tusdt-election/lib.rs) (never touches governance council), [set_council](contracts/tusdt-governance/lib.rs#L409-L428).

**Impact.** After an election installs a new maintainer, the **previous** (possibly just-defeated / adversarial) council retains `submit_snapshot` (→ C1 treasury drain, → swing the *next* election) and `vault_pause` for an unbounded window until the new maintainer manually re-seats. A losing faction can drain on the way out. Amplifies C1 across every governance transition.

**Remediation.** Clear/rotate the council atomically on `elect_maintainer` (e.g. reset to empty or to a maintainer-supplied set inside the same activation call); or enforce a re-seat before council powers are usable.

---

## F5 · MEDIUM-LOW — Deviation-cap circuit breaker can freeze all liquidations during a fast crash

**Root cause.** `ensure_within_deviation` is applied to **every** validator commit path ([oracle/lib.rs:295](contracts/tusdt-oracle/lib.rs#L295), [:529-545](contracts/tusdt-oracle/lib.rs#L529-L545)); only governance's `commit_round_governance` bypasses it. If the true price moves > `max_price_deviation` (10%) faster than the validator commits, honest commits revert with `PriceDeviationExceeded`, the price freezes, and after `max_oracle_age_ms` (30 min) the vault's [validate_price_data](contracts/tusdt-vault/lib.rs#L1104-L1120) returns `OraclePriceStale`, reverting `current_collateral_price` and therefore `trigger_liquidation_auction` — exactly when liquidations are needed → bad debt.

**Nuance (tempers severity).** Deviation is measured against the *last committed* price and there is **no min-interval between rounds**, so a diligent validator can *step* the price down in ≤10% increments (even several commits per block) to track the crash. The DoS only bites a validator that commits the true median once and gives up. This is the flip side of the known no-rate-limit "price-walk" issue — one missing control causes both.

**Remediation.** Widen/disable the deviation cap when the feed is near-stale, or provide a rate-limited catch-up path; pair with a min-interval + cumulative-drift bound (which also fixes price-walk).

---

## F6 · LOW-MEDIUM — No-bid liquidation auction permanently freezes the vault

**Root cause.** Setting `liquidation_auctions[(owner,vault_id)]` ([vault/lib.rs:837](contracts/tusdt-vault/lib.rs#L837)) makes every owner op revert via `ensure_not_in_liquidation` ([vault_access.rs:10-31](contracts/tusdt-vault/vault_access.rs#L10-L31)). The flag is cleared **only** by `settle_liquidation_auction`, which requires a finalized auction with a bid ([:870-872](contracts/tusdt-vault/lib.rs#L870-L872)); `finalize_auction` reverts `AuctionHasNoBids` when `bid_count == 0`. No cancel/expire path exists in the vault. If collateral falls below `min_bid` (debt + 11%) no rational bidder appears; recovery hinges entirely on the auction `admin` backstop being set and funded.

**Impact.** Owner collateral irrecoverable + permanent protocol bad debt when the admin backstop is absent. (This is the prior audit's "no-bid auction lock", re-scoped to the vault-freeze consequence.)

**Remediation.** A governance/permissionless path to cancel a finalized no-bid auction and clear the vault flag (re-liquidate or return to the owner).

---

## F7 · LOW-MEDIUM — `borrow_cap` is enforced on `total_supply`, which drifts up as fees/interest mint to treasury and are never burned

**Root cause.** Cap check is `token.total_supply() + amount > borrow_cap` ([vault/lib.rs:648-655](contracts/tusdt-vault/lib.rs#L648-L655)), but `borrow_token`/`repay_token` mint fees + realized interest to the treasury ([:662-666](contracts/tusdt-vault/lib.rs#L662-L666), [:708-716](contracts/tusdt-vault/lib.rs#L708-L716)) which are never burned. Supply monotonically outgrows outstanding debt, so borrow headroom shrinks until borrows revert `BorrowCapExceeded` even at low net debt.

**Impact.** Long-run denial of the core borrow function; "supply cap" conflated with "debt cap". Governance can raise the cap (timelocked) → degraded availability, not permanent.

**Remediation.** Measure the cap against outstanding debt, not token total supply.

---

## F8 · LOW — Interest accrual over-charges by a full hour each accrual and can advance the accrual clock past `now`

**Root cause.** `borrowed_hours = elapsed / MS_PER_HOUR + 1` (`saturating_add(1)`) and `last_interest_accrued_at` is advanced by `borrowed_hours * MS_PER_HOUR`, which can exceed `now` ([interest.rs:29-35](contracts/tusdt-vault/interest.rs#L29-L35), [:69-80](contracts/tusdt-vault/interest.rs#L69-L80)). Frequent small accruals each re-charge a full hour on current debt.

**Impact.** Borrowers pay above the advertised ~5.13% APY model (protocol-favoring; not attacker-profitable). Fairness/spec mismatch. **Remediation:** charge only fully-elapsed hours; never advance the clock beyond `now`.

---

## F9 · LOW — Known governance-lifecycle issues (re-confirmed)

- **CEI in `execute`** — status set to `Executed` *after* `treasury.release` ([governance/lib.rs:853-858](contracts/tusdt-governance/lib.rs#L853-L858)). Not currently reentrant (no token hooks) but flip the flag first.
- **In-flight proposals read live thresholds** — `finalize` reads `self.quorum(...)` / `self.params.approval_bps` ([:803-812](contracts/tusdt-governance/lib.rs#L803-L812)), so a maintainer `update_params` mid-vote retroactively moves the bar. Snapshot thresholds into the proposal at submission.
- **Treasury native existential-deposit over-booking** — `distribute` reconciles balances upward only (`saturating_sub`), stranding a small native amount / DoS-ing a native release ([treasury/lib.rs:178-179](contracts/tusdt-treasury/lib.rs#L178-L179)). Not stealable.

---

## F10 · LOW-MEDIUM (insider/centralization) — Unbounded emergency oracle price + irreversible governance role

- **WIRE-02:** a single maintainer key can set an **arbitrary** collateral price via `oracle_commit_round` → `commit_round_governance`, which skips `ensure_within_deviation` entirely (only `price != 0`) ([oracle/lib.rs:306-317](contracts/tusdt-oracle/lib.rs#L306-L317)). It drives all vault risk math with no deviation ceiling, rate limit, or timelock → mass unjust liquidation or over-borrow on key compromise. Documented as "emergency" but unbounded and single-account.
- **WIRE-01:** no forwarder anywhere reaches `*.update_governance` / `treasury.set_governance` ([external_calls.rs](contracts/tusdt-governance/external_calls.rs)), so after wiring the governance role on every protocol contract is **permanently frozen** at the current governance contract — any future governance-contract bug is unrecoverable and there is no migration path.

**Remediation.** Bound + timelock the emergency price (or make it a delta-limited catch-up); add a guarded, timelocked governance-migration forwarder.

---

## Leads (not-yet-findings — need external info or intent)

- **PRIM-01** — `multiplier_bps` is never clamped to ≤10_000 on-chain ([voting/src/lib.rs:70-90](voting/src/lib.rs#L70-L90)); a committed leaf with an inflated multiplier amplifies (not dampens) voting power. On-chain-exploitable only via a malicious/buggy snapshot — for the malicious-council case it is subsumed by C1 (and quorum uses raw balance). Worth an on-chain clamp as defense-in-depth.
- **PRIM-02** — leaf encodes `balance` as fixed-width `u128` while the chain-extension `StakeInfo` source is `Compact<u64>` ([env/src/lib.rs:216-236](env/src/lib.rs#L216-L236)); an off-chain snapshot-generator encoding drift silently fails every proof (liveness). Needs the generator to verify.
- **F6/F7 median control** — with `MIN_REPORTERS = 3` a 2-of-3 reporter minority sets the median ([oracle/lib.rs:603-606](contracts/tusdt-oracle/lib.rs)); combined with F3's low stake floor, cheaper than intended. Bounded by deviation cap + validator commit timing.
- **Election edge cases** — first-voter compresses the voting window (GOV-03), incumbent emergency-election churn (GOV-04), superseded cross-subnet transition leaves `active_netuid` stale (GOV-05), permissionless registration stall (WIRE-08). All incumbent-recoverable / self-limiting.
- **Spec drift** — README says proposal submission is stake-gated for token-holders; code is council-only and `min_proposer_stake` is dead (GOV-06). README `vault::new` CLI omits the `netuid` arg (WIRE-05).

---

## Coverage & limitations

**Covered (all 7 contracts + shared crates):** erc20, vault (+interest/risk/params/access), auction, oracle, treasury, governance (+external_calls), election, voting, primitives, env. Lenses run: access-control, state/lifecycle, token/value accounting, arithmetic/economic, crypto/merkle, external-interaction, DoS/griefing, upgrade/init/governance, cross-contract wiring. Six parallel breadth agents + orchestrator source verification.

**Explicitly disproved (documented so they aren't re-opened):** free-token / debt-vanishes / double-settle / reentrancy in the vault money path (mint/burn controller-gated, no hooks; native transfers run no code; borrow/repay/settle net out) · treasury split conserves the delta exactly (`split_delta`, remainder→Emergency) · erc20 approve-race is textbook only, no drain · merkle leaf-vs-node second-preimage (84- vs 64-byte preimages; leaf derived from caller) · wrong-epoch proofs, hotkey double-count, proposal double-execute/re-finalize · candidate-stake / chain-extension spoofing (reads fail closed) · deployer→governance hand-off front-run / re-seizure (all `ensure_governance`/`ensure_controller`) · `claim_surplus_tusdt` theft (sink hard-coded to treasury) · integer_sqrt / day_of_month / from_integer overflow · external_calls selector spoofing (typed refs).

**Limitations.** The off-chain snapshot generator and the Bittensor chain-extension stake source are out of repo — PRIM-01/PRIM-02 and the "is the electorate real" question (root of C1) can only be closed against those. Test baseline is red (21 election failures); dynamic PoCs beyond the existing on-chain drain script were not re-run this pass — findings are source-verified. No finite audit proves absence of vulnerabilities; this covers the in-scope contracts at commit `d1ba301` under the trust model above.
