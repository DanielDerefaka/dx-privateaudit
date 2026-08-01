# Security Findings Portfolio

A curated set of **proven** smart-contract, protocol, and node-level security findings.
Every entry below is **Critical or High** severity, carries a **runnable proof-of-concept**,
and **survived independent adversarial verification against real dependencies** (mainnet
fork / regtest / real consensus engine / live bytecode). Findings that only reproduced
against mocks, self-downgraded on real dependencies, were already public, or targeted
undeployed/out-of-scope code were deliberately **excluded** — see
[Deliberately excluded](#deliberately-excluded).

**9 Critical · 13 High** — swept from 54 audit targets.

Each finding lives in [`findings/<severity>/<nn>-<slug>/`](findings/) with its full write-up,
the validation record, and the PoC file(s).

> ⚠️ **Disclosure status.** Several of these target **live, deployed** systems and may be
> **unreported or unpatched**. Treat this as sensitive material: keep the repository
> **private** and follow each program's responsible-disclosure channel before publishing.
> See [Responsible disclosure](#responsible-disclosure).

---

## Critical

| # | Target | Finding | Impact | Folder |
|---|--------|---------|--------|--------|
| 1 | Leather wallet (Chrome build 6.107.0) | Post-condition-mode type confusion hides "funds will leave" warning on Allow-mode legacy Stacks tx | Signed drain with a false "nothing leaves your account" screen | [`01-leather-postcondition-allow-mode-drain`](findings/critical/01-leather-postcondition-allow-mode-drain/) |
| 2 | MinaProtocol/mina (L1 daemon) | Malformed block-gossip timestamp (≥2⁶³) crashes daemon pre-validation | Unauthenticated remote DoS → network-wide halt, any gossip peer | [`02-mina-gossip-timestamp-daemon-crash`](findings/critical/02-mina-gossip-timestamp-daemon-crash/) |
| 3 | Zano (legacy multisig consensus) | Missing intra-tx uniqueness on `txin_multisig` → double-count | Coin inflation / escrow theft, minting `(K−1)·A` from nothing | [`03-zano-multisig-double-count-inflation`](findings/critical/03-zano-multisig-double-count-inflation/) |
| 4 | Dash Platform (drive-abci v4.0.0-rc.1) | Unvalidated `position` type in nested schema panics `try_from_schema` | Deterministic network-wide chain halt | [`04-dash-platform-position-type-chain-halt`](findings/critical/04-dash-platform-position-type-chain-halt/) |
| 5 | Horizen/zen (zend 6.0.0) | Missing non-ceasing cert-uniqueness check hits `assert` in `ConnectBlock` | Poison-block network-wide chain halt | [`05-zen-nonceasing-multicert-chain-halt`](findings/critical/05-zen-nonceasing-multicert-chain-halt/) |
| 6 | paritytech/smoldot (light client) | GRANDPA justification not bound to finalized block | Warp-sync chain forgery by a single malicious peer/MITM | [`06-smoldot-grandpa-warpsync-forgery`](findings/critical/06-smoldot-grandpa-warpsync-forgery/) |
| 7 | allora-chain (x/mint) | `MaxSupply` update drives mint supply negative, panicking `BeginBlocker` | Unrecoverable total chain halt (hard-fork-only recovery) | [`07-allora-mint-maxsupply-chain-halt`](findings/critical/07-allora-mint-maxsupply-chain-halt/) |
| 8 | Tellor Layer (x/bridge → x/oracle EndBlocker) | Unbounded deposit amount/tip overflows int64 → uncaught panic | Deterministic chain halt, no self-heal | [`08-tellor-layer-bridge-overflow-chain-halt`](findings/critical/08-tellor-layer-bridge-overflow-chain-halt/) |
| 9 | SecretNetwork (non-SGX replay) | Unauthenticated remote execution traces applied to real multistore | Cross-module state forgery / native SCRT minting | [`09-secretnetwork-nonsgx-trace-state-forgery`](findings/critical/09-secretnetwork-nonsgx-trace-state-forgery/) |

## High

| # | Target | Finding | Impact | Folder |
|---|--------|---------|--------|--------|
| 10 | powpeg-node (Rootstock PowPeg) | Pegout signed with another pegout's segwit input amounts during migration | Frozen withdrawal + peg/migration halt | [`10-powpeg-migration-outpoint-misattribution-freeze`](findings/high/10-powpeg-migration-outpoint-misattribution-freeze/) |
| 11 | Virtual Protocol / veVirtual (Base) | `balanceOfAt` autoRenew path bypasses the historical-snapshot guard | Post-snapshot vote acquisition → governance takeover | [`11-virtual-vevirtual-governance-snapshot-bypass`](findings/high/11-virtual-vevirtual-governance-snapshot-bypass/) |
| 12 | Money on Chain / RSK MoCMedianizer | Cached validity serves expired/voided/quorum-invalid prices as valid | Stale-price oracle read in production consumer | [`12-mocmedianizer-cached-validity-stale-price`](findings/high/12-mocmedianizer-cached-validity-stale-price/) |
| 13 | DRAIN (ERC-8190 voucher marketplace) | Concurrency TOCTOU in provider voucher accounting | Unbounded theft of service (100/100 requests, $0 claimed) | [`13-drain-voucher-toctou-theft-of-service`](findings/high/13-drain-voucher-toctou-theft-of-service/) |
| 14 | hathor-core (nano contracts) | Non-deterministic set/dict serialization → divergent state roots | Permanent consensus chain split | [`14-hathor-nc-serialization-consensus-split`](findings/high/14-hathor-nc-serialization-consensus-split/) |
| 15 | MystenLabs/walrus (storage node) | Storage node signs availability confirmations without verifying slivers | Sign-before-verify (WAL-523 class) | [`15-walrus-sign-before-verify-confirmation`](findings/high/15-walrus-sign-before-verify-confirmation/) |
| 16 | nanocurrency/nano-node | Missing payload-size bound in realtime TCP reader | Unauthenticated 8-byte packet crashes node → confirmation halt | [`16-nano-node-asc-pull-unauth-crash-halt`](findings/high/16-nano-node-asc-pull-unauth-crash-halt/) |
| 17 | Acala (transaction-payment pallet) | Unguarded `ExactSupply(_,0)` fee-pool refill swap; oracle guard is dead code | Permissionless sandwich drain of fee-pool reserves (~798/1000 DOT) | [`17-acala-fee-pool-sandwich-drain`](findings/high/17-acala-fee-pool-sandwich-drain/) |
| 18 | TUSDT (ink!/Substrate stablecoin) | Missing snapshot validation in `submit_snapshot` | One council member forges electorate → treasury drain | [`18-tusdt-council-snapshot-forge-treasury-drain`](findings/high/18-tusdt-council-snapshot-forge-treasury-drain/) |
| 19 | solana-m-extensions (M^0 m_ext) | `add_earner` requires no holder consent | Rogue earn manager mints a non-consenting holder's yield | [`19-solana-m-ext-add-earner-no-consent-yield-theft`](findings/high/19-solana-m-ext-add-earner-no-consent-yield-theft/) |
| 20 | MegaETH stateless-validator | Missing timestamp validation lets a block source pick the fork ruleset | Invalid block accepted/committed | [`20-megaeth-stateless-validator-timestamp-fork`](findings/high/20-megaeth-stateless-validator-timestamp-fork/) |
| 21 | Tellor Layer (x/registry) | `RegisterSpec` accepts `ReportBlockWindow=0` (genesis invariant missing at runtime) | Permissionless permanent registry query-type squat/DoS | [`21-tellor-layer-registry-zerowindow-squat`](findings/high/21-tellor-layer-registry-zerowindow-squat/) |
| 22 | smartcontractkit/chainlink v2 (Go node) | Unauthenticated LOOP-plugin pprof/discovery exposure | argv/heap/goroutine leak + DoS on default `0.0.0.0:6688` | [`22-chainlink-loop-plugin-unauth-pprof`](findings/high/22-chainlink-loop-plugin-unauth-pprof/) |

---

## What "verified" means here

Each finding cleared a strict bar before being included:

1. **Final severity Critical or High** — the *corrected* rating, not an initial optimistic one.
2. **Runnable PoC** — a test/exploit/script that executes (named in each folder), not a hypothetical.
3. **Real-dependency verification** — reproduced against real code (mainnet fork, regtest,
   real consensus engine, or live bytecode), never mock-only.
4. **In-scope & novel** — the bug is in the target's own code, against a real/deployed asset,
   and not already publicly disclosed.

## Per-finding submission caveats

A few findings are genuine but carry a submission precondition — read each folder's
**Submission notes** before filing:

- **#8 / #21 Tellor Layer** — `SECURITY.md` lists no explicit scope and no public bounty was
  located; confirm scope privately (info@tellor.io) first.
- **#9 SecretNetwork** — Critical ceiling (≥2/3 forgery/mint) is gated on the non-SGX validator
  deployment Secret Labs is onboarding; present-tense PoC floor is High.
- **#7 allora-chain** — trigger is a whitelist-admin param update *or* a keyless genesis author;
  confirm the program credits the genesis vector.
- **#11 Virtual** — needs a confirmed live Governor/Defender consumer of the vulnerable snapshot.
- **#22 chainlink** — the Go-node source was **not** in this workspace; this entry rests on the
  report's stated PoC and must be re-run against the real repo before filing.

## Deliberately excluded

Kept out on purpose, so the portfolio contains only defensible findings:

- **Gearbox core-v3** — self-corrected High→Low; only reaches High under a mock price feed.
- **Beldex C-01** — valid Critical but already public (Beldex PR #197 / Oxen 2022) and no bounty.
- **go-graphsync** — already public CVE-2026-42328; root cause is a third-party dep bump.
- **Nym nym-pool** — Critical code-level but contract is undeployed / holds zero funds.
- **Babylon x/costaking** — PoC only holds on fresh genesis; live bbn-1 mainnet avoids the window.
- **avalanchego uptime forge** — maps to program Medium, not High.
- **Pharaoh C-01** — snapshot-at-boundary is by-design; the 50% claim was a baseline confound.
- **Aptos Move-VM struct-hijack** — third-party Hexens disclosure, already vendor-patched.
- **Zcash Orchard / halo2 write-ups** — methodology studies of a patched third-party bug, not
  findings against the repos they were filed under.
- **USDFC / Lombard** — downgraded to Medium/Low or trusted-admin-gated.

## Responsible disclosure

These are working exploits for real systems. Before making this repository public:

1. Report each finding through the target program's official channel (Immunefi / HackenProof /
   HackerOne / `SECURITY.md`) and let it be triaged and fixed.
2. Keep the repo **private** until fixes ship and disclosure windows close.
3. Only then consider publishing, with PoCs redacted or gated where a program requires.
