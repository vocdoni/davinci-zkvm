//! Primitive type aliases and constants shared across the circuit.
//!
//! # Fail-mask bit assignments (output[1])
//!
//! | Bit | Name                    | Set by         | Meaning                                    |
//! |-----|-------------------------|----------------|--------------------------------------------|
//! |   2 | `FAIL_STARK_PROOF`      | davinci_stark.rs | Ballot proof verification failed         |
//! |   3 | `FAIL_ECDSA`            | ecdsa.rs       | ECDSA signature or address binding failed  |
//! |  10 | `FAIL_SMT_VOTEID`       | smt.rs         | VoteID insertion chain invalid             |
//! |  11 | `FAIL_SMT_BALLOT`       | smt.rs         | Ballot insertion chain invalid             |
//! |  12 | `FAIL_SMT_RESULTS`      | smt.rs         | ResultsAdd/Sub transition invalid          |
//! |  13 | `FAIL_SMT_PROCESS`      | smt.rs         | Process config proof invalid or missing    |
//! |  14 | `FAIL_CONSISTENCY`      | consistency.rs | VoteID namespace / proof binding mismatch  |
//! |  15 | `FAIL_BALLOT_NS`        | consistency.rs | Ballot namespace / address binding mismatch|
//! |  16 | `FAIL_CENSUS`           | census.rs      | Census membership proof failed             |
//! |  17 | `FAIL_REENC`            | ecgfp5_verify.rs | Re-encryption verification failed       |
//! |  18 | `FAIL_KZG`              | kzg.rs         | KZG barycentric evaluation mismatch        |
//! |  19 | `FAIL_MISSING_BLOCK`    | various        | Mandatory block absent from input          |
//! |  20 | `FAIL_RESULT_ACCUM`     | results.rs     | Result accumulator ballot sum mismatch     |
//! |  21 | `FAIL_LEAF_HASH`        | results.rs     | Ballot SMT leaf hash mismatch              |
//! |  22 | `FAIL_BINDING`          | main.rs        | Cross-block binding mismatch               |
//! |  23 | `FAIL_CSP`              | csp.rs         | CSP ECDSA signature or address check failed|
//! |  31 | `FAIL_PARSE`            | io.rs          | Binary format / parse error                |

/// BN254 scalar field element in raw (non-Montgomery) 256-bit little-endian limbs.
pub type FrRaw = [u64; 4];

/// Magic bytes `"DSTARKB!"` in little-endian ASCII => davinci-stark ballot block.
pub const STARK_MAGIC: u64 = u64::from_le_bytes(*b"DSTARKB!");
pub const STATE_G5_MAGIC: u64 = u64::from_le_bytes(*b"STAG5TX!");
pub const REENC_G5_MAGIC: u64 = u64::from_le_bytes(*b"REG5BLK!");

pub const ZERO_FR: FrRaw = [0, 0, 0, 0];

pub const DEFAULT_MAX_BATCH_SIZE: usize = 128;

const fn parse_max_batch_size_ascii(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    if bytes.is_empty() {
        return None;
    }
    let mut value = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            return None;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as usize);
        i += 1;
    }
    if value >= 2 && value.is_power_of_two() {
        Some(value)
    } else {
        None
    }
}

const fn configured_max_batch_size(raw: Option<&str>) -> usize {
    match raw {
        Some(s) => match parse_max_batch_size_ascii(s) {
            Some(v) => v,
            None => DEFAULT_MAX_BATCH_SIZE,
        },
        None => DEFAULT_MAX_BATCH_SIZE,
    }
}

/// Maximum number of ballot proofs per batch.
pub const MAX_BATCH_SIZE: usize = configured_max_batch_size(option_env!("DAVINCI_MAX_BATCH_SIZE"));

pub const FAIL_PARSE: u32 = 1 << 31;
pub const FAIL_STARK_PROOF: u32 = 1 << 2;
pub const FAIL_ECDSA: u32 = 1 << 3;
pub const FAIL_SMT_VOTEID: u32 = 1 << 10;
pub const FAIL_SMT_BALLOT: u32 = 1 << 11;
pub const FAIL_SMT_RESULTS: u32 = 1 << 12;
pub const FAIL_SMT_PROCESS: u32 = 1 << 13;
pub const FAIL_CONSISTENCY: u32 = 1 << 14;
pub const FAIL_BALLOT_NS: u32 = 1 << 15;
pub const FAIL_CENSUS: u32 = 1 << 16;
pub const FAIL_REENC: u32 = 1 << 17;
pub const FAIL_KZG: u32 = 1 << 18;
pub const FAIL_MISSING_BLOCK: u32 = 1 << 19;
pub const FAIL_RESULT_ACCUM: u32 = 1 << 20;
pub const FAIL_LEAF_HASH: u32 = 1 << 21;
pub const FAIL_BINDING: u32 = 1 << 22;
pub const FAIL_CSP: u32 = 1 << 23;

/// Canonical davinci-stark public statement carried by each ballot proof.
#[derive(Clone, Copy)]
pub struct StarkPublicValues {
    pub inputs_hash: [u64; 4],
    pub address: FrRaw,
    pub vote_id: u64,
    pub inputs_preimage: [u64; 114],
}

/// One davinci-stark proof and its decoded public statement.
#[derive(Clone)]
pub struct StarkProofRaw {
    pub proof_bytes: Vec<u8>,
    pub public_values: StarkPublicValues,
}

/// One secp256k1 ECDSA entry from the signature block.
#[derive(Clone)]
pub struct EcdsaEntry {
    pub r: FrRaw,
    pub s: FrRaw,
    pub px: FrRaw,
    pub py: FrRaw,
}

#[derive(Clone)]
pub struct SmtTransition {
    pub old_root: FrRaw,
    pub new_root: FrRaw,
    pub old_key: FrRaw,
    pub old_value: FrRaw,
    pub is_old0: bool,
    pub new_key: FrRaw,
    pub new_value: FrRaw,
    pub fnc0: bool,
    pub fnc1: bool,
    pub siblings: Vec<FrRaw>,
}

/// Magic bytes `"CENSUS!!"` => identifies the optional census proof block.
pub const CENSUS_MAGIC: u64 = u64::from_le_bytes(*b"CENSUS!!");
/// Magic bytes `"KZGBLK!!"` => identifies the optional KZG barycentric evaluation block.
pub const KZG_MAGIC: u64 = u64::from_le_bytes(*b"KZGBLK!!");
/// Magic bytes `"CSPBLK!!"` => identifies the CSP ECDSA census block.
pub const CSP_MAGIC: u64 = u64::from_le_bytes(*b"CSPBLK!!");
/// Census origin value for CSP ECDSA mode (process config key 0x06 == 4).
pub const CENSUS_ORIGIN_CSP: u64 = 4;

pub struct KZGBlock {
    pub process_id: FrRaw,
    pub root_hash_before: FrRaw,
    pub commitment: [u8; 48],
    pub y_claimed: [u8; 32],
    pub blob: Vec<u8>,
}

#[derive(Clone)]
pub struct CensusProofEntry {
    pub root: FrRaw,
    pub leaf: FrRaw,
    pub index: u64,
    pub siblings: Vec<FrRaw>,
}

#[derive(Clone)]
pub struct CspEntry {
    pub r: FrRaw,
    pub s: FrRaw,
    pub voter_address: FrRaw,
    pub weight: FrRaw,
    pub index: u64,
}

pub struct CspBlock {
    pub csp_pub_key_x: FrRaw,
    pub csp_pub_key_y: FrRaw,
    pub entries: Vec<CspEntry>,
}

/// Canonical ecgfp5 point encoding (40 bytes = 5 little-endian u64 limbs).
pub type Ecgfp5PointRaw = [u64; 5];

/// One ecgfp5 ElGamal ciphertext (C1, C2).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Ecgfp5Ciphertext {
    pub c1: Ecgfp5PointRaw,
    pub c2: Ecgfp5PointRaw,
}

/// One ecgfp5 ballot with 8 ciphertexts.
pub type Ecgfp5Ballot = [Ecgfp5Ciphertext; 8];

#[derive(Clone)]
pub struct Ecgfp5ReencEntry {
    pub k: Ecgfp5PointRaw,
    pub original: Ecgfp5Ballot,
    pub reencrypted: Ecgfp5Ballot,
}

pub struct StateBlock {
    pub n_voters: usize,
    pub n_overwritten: usize,
    pub process_id: FrRaw,
    pub old_state_root: FrRaw,
    pub new_state_root: FrRaw,
    pub vote_id_chain: Vec<SmtTransition>,
    pub ballot_chain: Vec<SmtTransition>,
    pub results_add: Option<SmtTransition>,
    pub results_sub: Option<SmtTransition>,
    pub process_proofs: Vec<SmtTransition>,
    pub old_results_add_g5: Option<Ecgfp5Ballot>,
    pub old_results_sub_g5: Option<Ecgfp5Ballot>,
    pub voter_ballots_g5: Vec<Ecgfp5Ballot>,
    pub overwritten_ballots_g5: Vec<Ecgfp5Ballot>,
}

#[cfg(test)]
mod tests {
    use super::{configured_max_batch_size, parse_max_batch_size_ascii, DEFAULT_MAX_BATCH_SIZE};

    #[test]
    fn parse_max_batch_size_accepts_power_of_two() {
        assert_eq!(parse_max_batch_size_ascii("256"), Some(256));
    }

    #[test]
    fn parse_max_batch_size_rejects_non_power_of_two() {
        assert_eq!(parse_max_batch_size_ascii("96"), None);
    }

    #[test]
    fn configured_max_batch_size_falls_back_to_default() {
        assert_eq!(configured_max_batch_size(Some("invalid")), DEFAULT_MAX_BATCH_SIZE);
    }
}
