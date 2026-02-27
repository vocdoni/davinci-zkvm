//! Primitive type aliases and constants shared across the circuit.

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

/// Magic bytes `"SMTBLK!!"` — identifies the optional SMT block appended after ECDSA data.
pub const SMT_MAGIC: u64 = u64::from_le_bytes(*b"SMTBLK!!");

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
