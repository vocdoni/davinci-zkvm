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
