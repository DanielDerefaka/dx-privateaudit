# Cached Validity in Medianizer Lets Expired or Quorum-Invalid Prices Remain Valid

`Medianizer.peek()` and `Medianizer.read()` return the last cached `(price, has)` written by `poke()`.
They do not re-check feed expiry, the current feed set, or the current `min` quorum. Once the cache has
been set to `has = true`, the public oracle API can keep saying the price is valid even after every live
validity check says it is not.

**Severity:** High  
**Impact in scope:** High Smart Contract Impact  

## Brief/Intro

Consumers are told to use `IMoCBaseOracle.peek()` and to stop using the oracle when the returned boolean is
false. The medianizer does not actually make that boolean a live freshness check. It serves the cached
boolean from the last `poke()`, so expired, voided, or quorum-invalid prices can keep passing downstream
`require(has)` checks until somebody happens to call `poke()` again.

## Vulnerability Details

The feed contract has the live expiry check:

```solidity
function peek() external view returns (bytes32,bool)
{
    return (bytes32(val), now < zzz);
}
```

The medianizer also has a live check in `compute()`. It calls every whitelisted feed, keeps only feeds
whose own `peek()` returns `true`, and then rejects the result when the live count is below `min`:

```solidity
(wut, wuz) = DSValue(values[bytes12(i)]).peek();
if (wuz) {
    ...
    ctr++;
}

if (ctr < min) {
    return (bytes32(val), false);
}
```

The bug is that none of this is used by the consumer-facing API. `poke()` copies one result into storage:

```solidity
function poke() external {
    (bytes32 val_, bool has_) = compute();
    val = uint128(val_);
    has = has_;
    emit LogValue(val_);
}
```

Then `peek()` and `read()` only return that storage:

```solidity
function peek() external view returns (bytes32, bool) {
    return (bytes32(val), has);
}

function read() external view returns (bytes32) {
    require(has);
    return bytes32(val);
}
```

So the medianizer has two different truths at the same time:

```text
compute()  -> live oracle state
peek()     -> last cached oracle state
read()     -> last cached oracle state, with require(has)
```

The divergence is not limited to a feeder outage. I reproduced three separate paths:

1. A feed expires naturally. `PriceFeed.peek()` becomes false, `Medianizer.compute()` becomes false,
   but `Medianizer.peek()` and `read()` remain true until `poke()`.
2. `PriceFeed.poke(val, zzz)` updates a feed value without calling `med.poke()`. The underlying feed and
   `compute()` move to the new price, while `Medianizer.peek()` still serves the old cached price.
3. `PriceFeed.void()` kills a feed by setting `zzz = 0` without calling `med.poke()`. The feed and
   `compute()` are invalid, while the medianizer still reports the last cached price as valid.

The published integration example in the README exposes only this interface:

```solidity
interface IMoCBaseOracle {
  function peek() external view returns (bytes32, bool);
}
```

The same README says that when the boolean is false, the consumer should not use the price because it is
out of time limit. That is the invariant this bug breaks: the boolean returned by `peek()` is not a live
out-of-time-limit signal.

## Impact Details

The immediate impact is stale or quorum-invalid oracle data being accepted as valid. This is not just a
mock-only behavior. On a local RSK mainnet fork at block `9068970`, three deployed Money on Chain
medianizers were already in the bad state at the pristine fork timestamp:

```text
BTC/USD   peek.has=true compute.has=false
ETH/BTC   peek.has=true compute.has=false
BTC/USDT  peek.has=true compute.has=false
```

The fourth medianizer, RIF/USD, was still fresh at that exact block, but moved into the same bad state
after one hour with no `poke()`:

```text
RIF/USD after +1h/no poke: peek.has=true compute.has=false
```

That means a consumer that trusts `peek().has` or calls `read()` can continue minting, redeeming,
settling, liquidating, or valuing collateral against a price that the live oracle computation already
marks invalid.

This maps to **High Smart Contract Impact**. I am not claiming standalone Critical here because I am not
including a permissionless theft transaction tied only to this bug. The issue is still High because the
expiry trigger is unpermissioned, the state was observed on deployed mainnet medianizers, and the boolean
is the documented integration guard.

## References

- `contracts/medianizer/medianizer.sol:76-90` — `poke()`, `peek()`, and `read()` cache behavior.
- `contracts/medianizer/medianizer.sol:92-131` — `compute()` performs the live feed/quorum checks.
- `contracts/price-feed/price-feed.sol:31-39` — feed-level expiry check.
- `contracts/price-feed/price-feed.sol:42-58` — `poke()` and `void()` change feed state without refreshing the medianizer.
- `README.md` — documented `IMoCBaseOracle.peek()` integration interface and boolean semantics.

## Proof of Concept

I used two PoCs for the reproduction:

- a local Truffle test that demonstrates expiry, `PriceFeed.poke()`, and `PriceFeed.void()` divergence; and
- a local forked-mainnet test against the deployed RSK medianizers at block `9068970`.

Both PoC files are included below in full.

### PoC file 1 — local Truffle regression test

Save as `issue/poc/ISSUE-2-CachedValidity-truffle-test.js`:

```javascript
const MoCMedianizer = artifacts.require('./MoCMedianizer.sol');
const PriceFeed = artifacts.require('./price-feed/PriceFeed.sol');

const BN = web3.utils.BN;

function assertBnEq(actual, expected, message) {
  const a = new BN(actual);
  const e = new BN(expected);
  assert(a.eq(e), `${message}: expected ${e.toString(10)}, got ${a.toString(10)}`);
}

function sendRpc(method, params = []) {
  return new Promise((resolve, reject) => {
    web3.currentProvider.send(
      { jsonrpc: '2.0', id: Date.now(), method, params },
      (err, response) => {
        if (err) return reject(err);
        if (response && response.error) return reject(new Error(response.error.message || JSON.stringify(response.error)));
        resolve(response ? response.result : undefined);
      }
    );
  });
}

async function latestTimestamp() {
  const block = await web3.eth.getBlock('latest');
  return Number(block.timestamp);
}

contract('cached medianizer validity', accounts => {
  const owner = accounts[0];
  const anyone = accounts[1];

  async function deployLiveOracle(priceText = '10000', ttl = 60) {
    const medianizer = await MoCMedianizer.new({ from: owner });
    const feed = await PriceFeed.new({ from: owner });

    await medianizer.setMin(1, { from: owner });
    await medianizer.set(feed.address, { from: owner });

    const price = web3.utils.toWei(priceText, 'ether');
    const expiry = (await latestTimestamp()) + ttl;
    await feed.post(price, expiry, medianizer.address, { from: owner });

    const peek = await medianizer.peek();
    assert.strictEqual(peek[1], true, 'setup failed: medianizer should start valid');
    assertBnEq(peek[0], price, 'setup failed: cached medianizer price');

    return { medianizer, feed, price, expiry };
  }

  it('keeps peek()/read() valid after the only feed expires', async () => {
    const { medianizer, feed, price, expiry } = await deployLiveOracle('10000', 60);

    await sendRpc('evm_increaseTime', [120]);
    await sendRpc('evm_mine');

    const after = await latestTimestamp();
    assert(after > expiry, `test setup failed: now=${after}, expiry=${expiry}`);

    const feedPeek = await feed.peek();
    const compute = await medianizer.compute();
    const medPeek = await medianizer.peek();
    const medRead = await medianizer.read();

    console.log('expiry case: feed.peek.has=', feedPeek[1], 'compute.has=', compute[1], 'medianizer.peek.has=', medPeek[1]);
    console.log('expiry case: medianizer.read() still returns', medRead.toString());

    assert.strictEqual(feedPeek[1], false, 'underlying feed is expired');
    assert.strictEqual(compute[1], false, 'fresh compute sees the expired feed and returns invalid');
    assert.strictEqual(medPeek[1], true, 'BUG: cached peek() still says valid');
    assertBnEq(medPeek[0], price, 'cached peek() still returns the stale price');
    assertBnEq(medRead, price, 'read() still succeeds with the stale price');

    await medianizer.poke({ from: anyone });
    const afterPoke = await medianizer.peek();
    assert.strictEqual(afterPoke[1], false, 'poke() finally refreshes the cached flag to false');
  });

  it('lets PriceFeed.poke() update a feed without refreshing the medianizer cache', async () => {
    const { medianizer, feed, price: oldPrice } = await deployLiveOracle('10000', 3600);

    const newPrice = web3.utils.toWei('12345', 'ether');
    const newExpiry = (await latestTimestamp()) + 3600;

    // PriceFeed.poke() is an authorized feed-owner maintenance function, but unlike post(),
    // it does not call med.poke(). The underlying feed changes; the public medianizer API does not.
    await feed.poke(newPrice, newExpiry, { from: owner });

    const feedPeek = await feed.peek();
    const compute = await medianizer.compute();
    const medPeek = await medianizer.peek();

    console.log('feed.poke case: feed=', feedPeek[0].toString(), 'compute=', compute[0].toString(), 'cached=', medPeek[0].toString());

    assert.strictEqual(feedPeek[1], true, 'updated feed is valid');
    assert.strictEqual(compute[1], true, 'fresh compute sees the new valid feed value');
    assertBnEq(feedPeek[0], newPrice, 'feed.peek() has the new price');
    assertBnEq(compute[0], newPrice, 'compute() has the new price');
    assert.strictEqual(medPeek[1], true, 'cached medianizer flag still says valid');
    assertBnEq(medPeek[0], oldPrice, 'BUG: cached medianizer value is still the old price');
  });

  it('lets PriceFeed.void() invalidate a feed without refreshing the medianizer cache', async () => {
    const { medianizer, feed, price } = await deployLiveOracle('7777', 3600);

    // PriceFeed.void() kills the feed by setting zzz=0, but it does not poke the medianizer.
    await feed.void({ from: owner });

    const feedPeek = await feed.peek();
    const compute = await medianizer.compute();
    const medPeek = await medianizer.peek();
    const medRead = await medianizer.read();

    console.log('feed.void case: feed.peek.has=', feedPeek[1], 'compute.has=', compute[1], 'medianizer.peek.has=', medPeek[1]);

    assert.strictEqual(feedPeek[1], false, 'feed has been voided');
    assert.strictEqual(compute[1], false, 'fresh compute sees no valid inputs');
    assert.strictEqual(medPeek[1], true, 'BUG: cached medianizer flag still says valid');
    assertBnEq(medPeek[0], price, 'cached medianizer price is still the pre-void price');
    assertBnEq(medRead, price, 'read() still succeeds after the feed was voided');
  });
});
```

Run it with:

```bash
# from the Amphiraos-Oracle repository root
# Node 16 is recommended for this old Truffle/Solidity toolchain.
npm install

# If the repository config tries to load optional deploy providers, use any
# equivalent Truffle config that points at ./contracts and ./build/contracts.
npx truffle test issue/poc/ISSUE-2-CachedValidity-truffle-test.js --migrate-none
```

Observed output:

```text
Using network 'development'.


Compiling your contracts...
===========================
> Compiling ./contracts/MocMedianizer.sol
> Compiling ./contracts/medianizer/medianizer.sol
> Artifacts written to temporary Truffle test directory
> Compiled successfully using:
   - solc: 0.4.24+commit.e67f0147.Emscripten.clang
> Migration skipped because --migrate-none option was passed.


  Contract: cached medianizer validity
expiry case: feed.peek.has= false compute.has= false medianizer.peek.has= true
expiry case: medianizer.read() still returns 0x00000000000000000000000000000000000000000000021e19e0c9bab2400000
    ✔ keeps peek()/read() valid after the only feed expires (792ms)
feed.poke case: feed= 0x00000000000000000000000000000000000000000000029d394a5d6305440000 compute= 0x00000000000000000000000000000000000000000000029d394a5d6305440000 cached= 0x00000000000000000000000000000000000000000000021e19e0c9bab2400000
    ✔ lets PriceFeed.poke() update a feed without refreshing the medianizer cache (221ms)
feed.void case: feed.peek.has= false compute.has= false medianizer.peek.has= true
    ✔ lets PriceFeed.void() invalidate a feed without refreshing the medianizer cache (191ms)


  3 passing (1s)
```

### PoC file 2 — local forked-mainnet check

Start a local fork. This does not send any production transaction:

```bash
anvil --host 127.0.0.1 --port 8549 \
  --chain-id 30 \
  --fork-url https://public-node.rsk.co \
  --fork-block-number 9068970
```

Save the following as `issue/poc/ISSUE-2-fork-mainnet-cached-validity.js`:

```javascript
const fs = require('fs');
const path = require('path');
const Web3 = require('web3');

const ROOT = process.cwd();
const RPC = process.env.RPC || 'http://127.0.0.1:8549';
const web3 = new Web3(RPC);
const medianizerAbi = JSON.parse(fs.readFileSync(path.join(ROOT, 'build/contracts/MoCMedianizer.json'))).abi;

const medianizers = [
  ['BTC/USD', 'mocMainnet', '0x7B19bb8e6c5188eC483b784d6fB5d807a77b21bF'],
  ['ETH/BTC', 'ethMainnet', '0x68862C30d45605EAd8D01eF1632F7BFB18FAB587'],
  ['BTC/USDT', 'tetherMainnet', '0x5741d55C96176eEca86316b5840Cb208784d5188'],
  ['RIF/USD', 'rdocMainnet', '0x504EfCadFB020d6bBaeC8a5c5BB21453719d0E00'],
];

function rpc(method, params = []) {
  return new Promise((resolve, reject) => {
    web3.currentProvider.send(
      { jsonrpc: '2.0', id: Date.now(), method, params },
      (err, response) => {
        if (err) return reject(err);
        if (response && response.error) return reject(new Error(response.error.message || JSON.stringify(response.error)));
        resolve(response ? response.result : undefined);
      }
    );
  });
}

async function withSnapshot(fn) {
  const id = await rpc('evm_snapshot');
  try {
    return await fn();
  } finally {
    await rpc('evm_revert', [id]);
  }
}

function asDecimal(wad) {
  return Number(web3.utils.toBN(wad).toString()) / 1e18;
}

async function main() {
  const chainId = await web3.eth.getChainId();
  const block = await web3.eth.getBlock('latest');

  console.log('RSK fork:', RPC);
  console.log('chainId:', chainId, 'block:', block.number, 'timestamp:', block.timestamp);
  console.log('');

  for (const [pair, configName, address] of medianizers) {
    const med = new web3.eth.Contract(medianizerAbi, address);
    const min = await med.methods.min().call();
    const peek = await med.methods.peek().call();
    const compute = await med.methods.compute().call({ gas: 30000000 });
    const staleNow = peek[1] === true && compute[1] === false;

    console.log(`${pair.padEnd(8)} ${configName.padEnd(14)} min=${min} peek.has=${peek[1]} compute.has=${compute[1]} read=${asDecimal(peek[0])}` +
      (staleNow ? '  <-- STALE SERVED AS VALID NOW' : ''));

    if (!staleNow) {
      await withSnapshot(async () => {
        await rpc('evm_increaseTime', [3600]);
        await rpc('evm_mine');
        const laterPeek = await med.methods.peek().call();
        const laterCompute = await med.methods.compute().call({ gas: 30000000 });
        console.log(`  after +1h/no poke: peek.has=${laterPeek[1]} compute.has=${laterCompute[1]}` +
          (laterPeek[1] === true && laterCompute[1] === false ? '  <-- BECOMES STALE SERVED AS VALID' : ''));
      });
    }
  }
}

main().catch(err => {
  console.error(err.stack || err.message || err);
  process.exit(1);
});
```

Run it with:

```bash
# from the Amphiraos-Oracle repository root
# compile first if build/contracts/MoCMedianizer.json is not present
npm install
npx truffle compile --all
RPC=http://127.0.0.1:8549 node issue/poc/ISSUE-2-fork-mainnet-cached-validity.js
```

Observed forked-mainnet output:

```text
RSK fork: http://127.0.0.1:8549
chainId: 30 block: 9068970 timestamp: 1784463665

BTC/USD  mocMainnet     min=1 peek.has=true compute.has=false read=75121.025  <-- STALE SERVED AS VALID NOW
ETH/BTC  ethMainnet     min=1 peek.has=true compute.has=false read=0.060009  <-- STALE SERVED AS VALID NOW
BTC/USDT tetherMainnet  min=1 peek.has=true compute.has=false read=1.0002491458249416  <-- STALE SERVED AS VALID NOW
RIF/USD  rdocMainnet    min=1 peek.has=true compute.has=true read=0.1322964582208
  after +1h/no poke: peek.has=true compute.has=false  <-- BECOMES STALE SERVED AS VALID
```

This fork output is the key production-state check: three of the four deployed medianizers were already
returning `peek.has=true` while a fresh `compute()` returned `false`, and the live RIF/USD medianizer
entered the same state after time advanced without a medianizer `poke()`.

### Notes and limits

- All state-changing testing was done on a local test chain or a local mainnet fork.
- I am not submitting this as direct theft of funds. The correct scoped impact is High Smart Contract Impact.
- The governance-triggered variants (`setMin`/`unset`) are useful to show the same cache bug, but the expiry
  path alone is enough and does not require admin permissions.
- Upstream issue #9 is related to feed TTL, but it is not the same bug. This report is about the medianizer-level
  cached `has` flag returned by the public integration API.
