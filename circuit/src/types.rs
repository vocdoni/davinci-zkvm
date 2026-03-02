//! Primitive type aliases and constants shared across the circuit.
//!
//! # Fail-mask bit assignments (output\[1\])
//!
//! | Bit | Name                    | Set by         | Meaning                                    |
//! |-----|-------------------------|----------------|--------------------------------------------|
//! |   1 | `FAIL_CURVE`            | groth16.rs     | Proof point not on curve                   |
//! |   2 | `FAIL_PAIRING`          | groth16.rs     | Batch pairing check failed                 |
//! |   3 | `FAIL_ECDSA`            | ecdsa.rs       | ECDSA signature or address binding failed  |
//! |  10 | `FAIL_SMT_VOTEID`       | smt.rs         | VoteID insertion chain invalid             |
//! |  11 | `FAIL_SMT_BALLOT`       | smt.rs         | Ballot insertion chain invalid             |
//! |  12 | `FAIL_SMT_RESULTS`      | smt.rs         | ResultsAdd/Sub transition invalid          |
//! |  13 | `FAIL_SMT_PROCESS`      | smt.rs         | Process read-proof invalid                 |
//! |  14 | `FAIL_CONSISTENCY`      | consistency.rs | VoteID namespace / proof binding mismatch  |
//! |  15 | `FAIL_BALLOT_NS`        | consistency.rs | Ballot namespace / address binding mismatch|
//! |  16 | `FAIL_CENSUS`           | census.rs      | Census membership proof failed             |
//! |  17 | `FAIL_REENC`            | babyjubjub.rs  | Re-encryption verification failed          |
//! |  18 | `FAIL_KZG`              | kzg.rs         | KZG barycentric evaluation mismatch        |
//! |  19 | `FAIL_MISSING_BLOCK`    | various        | Mandatory block absent from input          |
//! |  20 | `FAIL_RESULT_ACCUM`     | results.rs     | Result accumulator ballot sum mismatch     |
//! |  21 | `FAIL_LEAF_HASH`        | results.rs     | Ballot SMT leaf hash mismatch              |
//! |  31 | `FAIL_PARSE`            | io.rs          | Binary format / parse error                |

/// BN254 G1 affine point: (x[4], y[4]) in 256-bit little-endian limbs.
pub type G1 = [u64; 8];

/// BN254 G2 affine point: (x[2][4], y[2][4]) in 256-bit little-endian limbs.
pub type G2 = [u64; 16];

/// BN254 GT element: 48 u64 limbs (12-extension field).
pub type GT = [u64; 48];

/// BN254 scalar field element in raw (non-Montgomery) 256-bit little-endian limbs.
pub type FrRaw = [u64; 4];

/// Magic bytes `"GROTH16B"` in little-endian ASCII — identifies the binary input format.
pub const MAGIC: u64 = 0x423631484f545247u64;

/// BN254 scalar field modulus r as [u64; 4] little-endian.
#[allow(dead_code)]
pub const BN254_FR_MODULUS: FrRaw = [
    4891460686036598785,
    2896914383306846353,
    13281191951274694749,
    3486998266802970665,
];

pub const ZERO_FR: FrRaw = [0, 0, 0, 0];
/// The value 1 in the BN254 scalar field (raw LE limbs).
#[allow(dead_code)]
pub const ONE_FR: FrRaw = [1, 0, 0, 0];

// ─── Fail-mask bit constants ────────────────────────────────────────────────
// See the module-level table for a complete description of each bit.
pub const FAIL_PARSE:       u32 = 1 << 31;
pub const FAIL_CURVE:       u32 = 1 << 1;
pub const FAIL_PAIRING:     u32 = 1 << 2;
pub const FAIL_ECDSA:       u32 = 1 << 3;
pub const FAIL_SMT_VOTEID:  u32 = 1 << 10;
pub const FAIL_SMT_BALLOT:  u32 = 1 << 11;
pub const FAIL_SMT_RESULTS: u32 = 1 << 12;
pub const FAIL_SMT_PROCESS: u32 = 1 << 13;
pub const FAIL_CONSISTENCY: u32 = 1 << 14;
pub const FAIL_BALLOT_NS:   u32 = 1 << 15;
pub const FAIL_CENSUS:      u32 = 1 << 16;
pub const FAIL_REENC:       u32 = 1 << 17;
/// Bit 18 — KZG barycentric evaluation mismatch.
pub const FAIL_KZG:         u32 = 1 << 18;
/// Bit 19 — A mandatory protocol block is missing from the input.
pub const FAIL_MISSING_BLOCK: u32 = 1 << 19;
/// Bit 20 — Result accumulator: homomorphic ballot sum does not match ResultsAdd/Sub.
pub const FAIL_RESULT_ACCUM: u32 = 1 << 20;
/// Bit 21 — Ballot leaf hash: SHA-256(serialized_ballot) ≠ SMT new_value.
pub const FAIL_LEAF_HASH: u32 = 1 << 21;

/// One Groth16 proof and its associated public inputs.
#[derive(Clone)]
pub struct ProofRaw {
    pub a: G1,
    pub b: G2,
    pub c: G1,
    pub public_inputs: Vec<FrRaw>,
}

/// One secp256k1 ECDSA entry from the optional signature block.
/// All fields are `[u64; 4]` little-endian scalars.
#[derive(Clone)]
pub struct EcdsaEntry {
    pub r: FrRaw,
    pub s: FrRaw,
    pub px: FrRaw,
    pub py: FrRaw,
}

/// One Arbo-compatible SMT state-transition proof.
///
/// All `FrRaw` fields use LE word order (same convention as the rest of the circuit).
/// The SMT verifier converts them to big-endian bytes for hashing, matching Arbo's
/// `HashFunctionSha256` byte layout.
#[derive(Clone)]
pub struct SmtTransition {
    pub old_root: FrRaw,
    pub new_root: FrRaw,
    pub old_key: FrRaw,
    pub old_value: FrRaw,
    /// `true` when the old leaf slot was empty (pure insert into an unoccupied position).
    pub is_old0: bool,
    pub new_key: FrRaw,
    pub new_value: FrRaw,
    /// `fnc0=true` → insert (or delete if also fnc1=true).
    pub fnc0: bool,
    /// `fnc1=true` → update (or delete if also fnc0=true).
    pub fnc1: bool,
    /// Merkle siblings, root→leaf order, padded to `n_levels` with zeros.
    pub siblings: Vec<FrRaw>,
}

/// Magic bytes `"STATETX!"` — identifies the full state-transition block.
pub const STATE_MAGIC: u64 = u64::from_le_bytes(*b"STATETX!");

/// Magic bytes `"CENSUS!!"` — identifies the optional census proof block.
pub const CENSUS_MAGIC: u64 = u64::from_le_bytes(*b"CENSUS!!");

/// Magic bytes `"REENCBLK"` — identifies the optional re-encryption verification block.
pub const REENC_MAGIC: u64 = u64::from_le_bytes(*b"REENCBLK");

/// Magic bytes `"KZGBLK!!"` — identifies the optional KZG barycentric evaluation block.
pub const KZG_MAGIC: u64 = u64::from_le_bytes(*b"KZGBLK!!");

/// KZG EIP-4844 blob barycentric evaluation block.
///
/// Contains all data needed to verify Y = P(Z) where P is the polynomial interpolating
/// the blob, and Z is derived from the process context via SHA-256.
pub struct KZGBlock {
    /// Process identifier (BN254 Fr, 4×u64 LE). Used to derive the evaluation point Z.
    pub process_id: FrRaw,
    /// Arbo SHA-256 state root before the batch (BN254 Fr, 4×u64 LE). Also used for Z.
    pub root_hash_before: FrRaw,
    /// Compressed BLS12-381 G1 KZG commitment (48 bytes, big-endian).
    pub commitment: [u8; 48],
    /// Claimed evaluation Y at point Z (32 bytes, big-endian BLS12-381 Fr).
    pub y_claimed: [u8; 32],
    /// Blob data: 4096 cells of 32 big-endian bytes each (131072 bytes total).
    pub blob: Vec<u8>,
}

/// One ElGamal ciphertext: (C1.x, C1.y, C2.x, C2.y) in BN254 Fr.
#[derive(Clone, Default)]
pub struct BjjCiphertext {
    pub c1x: FrRaw,
    pub c1y: FrRaw,
    pub c2x: FrRaw,
    pub c2y: FrRaw,
}

/// Re-encryption entry for one voter: seed k, original ballot, re-encrypted ballot.
#[derive(Clone)]
pub struct ReencEntry {
    /// The re-encryption seed k (before Poseidon hash).
    pub k: FrRaw,
    /// Original 8 ciphertexts from the voter's ballot proof.
    pub original: [BjjCiphertext; 8],
    /// Re-encrypted 8 ciphertexts stored in the state tree.
    pub reencrypted: [BjjCiphertext; 8],
}

/// One lean-IMT Poseidon membership proof for a census voter.
#[derive(Clone)]
pub struct CensusProofEntry {
    /// Tree root at the time of the proof.
    pub root: FrRaw,
    /// Leaf value: `PackAddressWeight(address, weight)` = `(address << 88) | weight`.
    pub leaf: FrRaw,
    /// Packed path bits (bit `i` = `(index >> i) & 1`; 1 = node is right child).
    pub index: u64,
    /// Merkle siblings (variable length; absent levels are omitted by lean-IMT).
    pub siblings: Vec<FrRaw>,
}

/// A ballot is 8 ElGamal ciphertexts × 4 BN254 Fr coordinates = 32 field elements.
/// Layout: [C1.x, C1.y, C2.x, C2.y] for each of the 8 ciphertexts, sequentially.
/// This matches `elgamal.Ballot.BigInts()` in davinci-node.
pub type BallotData = [FrRaw; 32];

/// Full DAVINCI state-transition data, parsed from the STATETX binary block.
/// Present when the prover includes a `state` field in the ProveRequest.
pub struct StateBlock {
    /// Number of real (non-dummy) votes in this batch.
    pub n_voters: usize,
    /// Number of votes that replaced an existing ballot.
    pub n_overwritten: usize,
    /// Process identifier (arbo state tree key 0x0).
    pub process_id: FrRaw,
    /// Arbo SHA-256 state root before all transitions.
    pub old_state_root: FrRaw,
    /// Arbo SHA-256 state root after all transitions.
    pub new_state_root: FrRaw,
    /// VoteID SMT insertion chain (one transition per real vote).
    pub vote_id_chain: Vec<SmtTransition>,
    /// Ballot SMT insertion/update chain (one transition per real vote).
    pub ballot_chain: Vec<SmtTransition>,
    /// ResultsAdd SMT transition (one update per batch; None if all dummy).
    pub results_add: Option<SmtTransition>,
    /// ResultsSub SMT transition (present only when overwritten votes > 0).
    pub results_sub: Option<SmtTransition>,
    /// Process config read-proofs (exactly 4: processID, ballotMode, encKey, censusOrigin).
    pub process_proofs: Vec<SmtTransition>,
    /// Shared n_levels for vote_id_chain and ballot_chain.
    pub n_levels: usize,

    // ── Result accumulator ballot data ────────────────────────────────────────
    /// Previous ResultsAdd leaf value (32 Fr elements). ZERO_FR ballot when absent.
    pub old_results_add: BallotData,
    /// Previous ResultsSub leaf value (32 Fr elements). ZERO_FR ballot when absent.
    pub old_results_sub: BallotData,
    /// Per-voter re-encrypted ballots (32 Fr elements each), in same order as ballot_chain.
    /// Used for homomorphic sum verification: NewResultsAdd = OldResultsAdd + Σ(all ballots).
    pub voter_ballots: Vec<BallotData>,
    /// Per-overwrite old ballot data (32 Fr elements each). Only present for UPDATE entries.
    /// Used for homomorphic sum: NewResultsSub = OldResultsSub + Σ(overwritten ballots).
    pub overwritten_ballots: Vec<BallotData>,
}
