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
