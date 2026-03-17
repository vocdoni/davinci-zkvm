//! Shared davinci-stark proof and public-value types.
//!
//! These types define the canonical ballot-proof statement that replaces the
//! STARK public values and wire encoding shared by the service, SDK, and tests.

use anyhow::{bail, Result};
pub const STARK_INPUTS_HASH_LIMBS: usize = 4;
pub const STARK_ADDRESS_LIMBS: usize = 4;
pub const STARK_INPUTS_PREIMAGE_LIMBS: usize = 114;
pub const STARK_PUBLIC_VALUE_COUNT: usize =
    STARK_INPUTS_HASH_LIMBS + STARK_ADDRESS_LIMBS + 1 + STARK_INPUTS_PREIMAGE_LIMBS;
pub const STARK_PUBLIC_VALUE_BYTES: usize = STARK_PUBLIC_VALUE_COUNT * 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkPublicValues {
    pub inputs_hash: [u64; STARK_INPUTS_HASH_LIMBS],
    pub address: [u64; STARK_ADDRESS_LIMBS],
    pub vote_id: u64,
    pub inputs_preimage: [u64; STARK_INPUTS_PREIMAGE_LIMBS],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StarkProofBundle {
    pub proof_bytes: Vec<u8>,
    pub public_values: StarkPublicValues,
}

impl StarkPublicValues {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() != STARK_PUBLIC_VALUE_BYTES {
            bail!(
                "invalid stark public-value length: got {}, want {}",
                raw.len(),
                STARK_PUBLIC_VALUE_BYTES
            );
        }
        let mut inputs_hash = [0u64; STARK_INPUTS_HASH_LIMBS];
        let mut address = [0u64; STARK_ADDRESS_LIMBS];
        let mut inputs_preimage = [0u64; STARK_INPUTS_PREIMAGE_LIMBS];
        for (i, limb) in inputs_hash.iter_mut().enumerate() {
            *limb = u64::from_le_bytes(raw[i * 8..(i + 1) * 8].try_into().unwrap());
        }
        for (i, limb) in address.iter_mut().enumerate() {
            let offset = (STARK_INPUTS_HASH_LIMBS + i) * 8;
            *limb = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
        }
        let vote_id_offset = (STARK_INPUTS_HASH_LIMBS + STARK_ADDRESS_LIMBS) * 8;
        let vote_id =
            u64::from_le_bytes(raw[vote_id_offset..vote_id_offset + 8].try_into().unwrap());
        let base = vote_id_offset + 8;
        for (i, limb) in inputs_preimage.iter_mut().enumerate() {
            let offset = base + i * 8;
            *limb = u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap());
        }
        Ok(Self {
            inputs_hash,
            address,
            vote_id,
            inputs_preimage,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0u8; STARK_PUBLIC_VALUE_BYTES];
        for (i, limb) in self.inputs_hash.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
        }
        for (i, limb) in self.address.iter().enumerate() {
            let offset = (STARK_INPUTS_HASH_LIMBS + i) * 8;
            out[offset..offset + 8].copy_from_slice(&limb.to_le_bytes());
        }
        let vote_id_offset = (STARK_INPUTS_HASH_LIMBS + STARK_ADDRESS_LIMBS) * 8;
        out[vote_id_offset..vote_id_offset + 8].copy_from_slice(&self.vote_id.to_le_bytes());
        let base = vote_id_offset + 8;
        for (i, limb) in self.inputs_preimage.iter().enumerate() {
            let offset = base + i * 8;
            out[offset..offset + 8].copy_from_slice(&limb.to_le_bytes());
        }
        out
    }

    pub fn as_u64_vec(&self) -> Vec<u64> {
        let mut out = Vec::with_capacity(STARK_PUBLIC_VALUE_COUNT);
        out.extend(self.inputs_hash);
        out.extend(self.address);
        out.push(self.vote_id);
        out.extend(self.inputs_preimage);
        out
    }
}

impl StarkProofBundle {
    pub fn decode_wire(raw: &[u8]) -> Result<Self> {
        if raw.len() < 4 {
            bail!("stark proof blob too short");
        }
        let proof_len = u32::from_le_bytes(raw[..4].try_into().unwrap()) as usize;
        if raw.len() != 4 + proof_len + STARK_PUBLIC_VALUE_BYTES {
            bail!(
                "invalid stark proof blob length: got {}, want {}",
                raw.len(),
                4 + proof_len + STARK_PUBLIC_VALUE_BYTES
            );
        }
        let proof_bytes = raw[4..4 + proof_len].to_vec();
        let public_values = StarkPublicValues::decode(&raw[4 + proof_len..])?;
        Ok(Self {
            proof_bytes,
            public_values,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stark_public_values_round_trip() {
        let mut pv = StarkPublicValues {
            inputs_hash: [1, 2, 3, 4],
            address: [5, 6, 7, 8],
            vote_id: 9,
            inputs_preimage: [0; STARK_INPUTS_PREIMAGE_LIMBS],
        };
        for (i, limb) in pv.inputs_preimage.iter_mut().enumerate() {
            *limb = 100 + i as u64;
        }
        let enc = pv.encode();
        let dec = StarkPublicValues::decode(&enc).unwrap();
        assert_eq!(pv, dec);
        assert_eq!(dec.as_u64_vec().len(), STARK_PUBLIC_VALUE_COUNT);
    }

    #[test]
    fn stark_proof_bundle_round_trip() {
        let pv = StarkPublicValues {
            inputs_hash: [11, 12, 13, 14],
            address: [15, 16, 17, 18],
            vote_id: 19,
            inputs_preimage: [20; STARK_INPUTS_PREIMAGE_LIMBS],
        };
        let proof_bytes = vec![1, 2, 3, 4, 5];
        let mut blob = Vec::new();
        blob.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        blob.extend_from_slice(&proof_bytes);
        blob.extend_from_slice(&pv.encode());
        let decoded = StarkProofBundle::decode_wire(&blob).unwrap();
        assert_eq!(decoded.proof_bytes, proof_bytes);
        assert_eq!(decoded.public_values, pv);
    }
}
