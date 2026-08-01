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
