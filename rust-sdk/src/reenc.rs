//! The batch re-encryption scalar chain (guest `reenc_chain_start` /
//! `sha256_to_scalar`, Go `elgamal.NewReencChain`):
//!
//! ```text
//! H(b)  = int_be(sha256(b)) mod p
//! r_0   = H("davinci-reenc-v1" || seed_BE32 || BE32(old_root_int))
//! r_t+1 = H(BE32(r_t))
//! ```
//!
//! Every active field of every entry consumes one scalar, batch entries first
//! (ballot order), then refreshes (refresh-chain order). Padded fields consume
//! nothing.

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::ballot::Ballot;
use crate::crypto::babyjubjub::Point;
use crate::crypto::elgamal::{random_scalar, reencrypt};
use crate::crypto::field::{fr_from_be_mod_order, fr_to_be, fr_to_u256, u256_to_be, Fr, U256};
use crate::limits::NUM_FIELDS;

const TAG: &[u8; 16] = b"davinci-reenc-v1";

/// Secret per-batch chain. Never log, persist or reuse the seed.
pub struct ReencChain {
    next: Fr,
}

impl ReencChain {
    /// `seed` is the 32 bytes sent as `reencryption.seed` (hashed raw, never
    /// reduced); `old_root` is the raw arbo root before the batch.
    pub fn new(seed: &[u8; 32], old_root: &[u8; 32]) -> Self {
        let mut root_be = *old_root;
        root_be.reverse(); // BE32 of the root's little-endian integer
        let mut h = Sha256::new();
        h.update(TAG);
        h.update(seed);
        h.update(root_be);
        ReencChain {
            next: fr_from_be_mod_order(&h.finalize()),
        }
    }

    /// Current scalar; advances the chain.
    pub fn next_scalar(&mut self) -> U256 {
        let r = self.next;
        self.next = fr_from_be_mod_order(&Sha256::digest(fr_to_be(&r)));
        fr_to_u256(&r)
    }
}

impl std::fmt::Debug for ReencChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReencChain(..)")
    }
}

/// Fresh batch seed, uniform below the subgroup order like the Go sequencer's.
pub fn random_seed<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    u256_to_be(&random_scalar(rng))
}

/// `b + Enc(0; r_t)` on fields `< nf`, one chain scalar each; padded fields
/// are copied (the guest requires them to be the identity).
pub fn reencrypt_ballot(b: &Ballot, pk: &Point, nf: u8, chain: &mut ReencChain) -> Ballot {
    let mut out = *b;
    for ct in out.0.iter_mut().take((nf as usize).min(NUM_FIELDS)) {
        *ct = reencrypt(ct, pk, &chain.next_scalar());
    }
    out
}
