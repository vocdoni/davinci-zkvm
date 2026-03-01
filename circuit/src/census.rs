//! Census lean-IMT Poseidon proof verifier.
//!
//! Verifies a lean-IMT membership proof using the iden3 Poseidon hash over BN254.
//!
//! Leaf encoding: `PackAddressWeight(address, weight)` = `(address << 88) | weight`
//! Tree hash:     `poseidon2(left, right)` (iden3 Poseidon, 2 inputs, t=3)
//! Proof format:  `(root, leaf, index: u64, siblings: &[FrRaw])`
//!
//! Index bit `i` (LSB-first): if bit=1, node is right child (sibling on left).

use crate::poseidon::poseidon2;
use crate::types::FrRaw;

/// Verify a lean-IMT Poseidon membership proof.
///
/// Compatible with `leanimt.VerifyProofWith` from lean-imt-go with `PoseidonHasher`.
///
/// - `root`:     expected tree root
/// - `leaf`:     `PackAddressWeight(address, weight)` as BN254 Fr LE
/// - `index`:    packed path bits (bit i = `(index >> i) & 1`)
/// - `siblings`: merkle path (only non-empty levels included)
pub fn verify_census_proof(root: &FrRaw, leaf: &FrRaw, index: u64, siblings: &[FrRaw]) -> bool {
    let mut node = *leaf;

    for (i, sibling) in siblings.iter().enumerate() {
        let bit = (index >> i) & 1;
        node = if bit == 1 {
            // current node is right child: hash(sibling, node)
            poseidon2(sibling, &node)
        } else {
            // current node is left child: hash(node, sibling)
            poseidon2(&node, sibling)
        };
    }

    node == *root
}

/// Verify census proofs for all voters in the parsed input.
///
/// Returns `true` when all proofs are valid (or when no census proofs are present).
/// Sets the corresponding bit in `fail_mask` on failure.
pub fn verify_batch(parsed: &crate::io::ParsedInput, fail_mask: &mut u32) -> bool {
    if parsed.census_proofs.is_empty() {
        return true;
    }

    for (i, cp) in parsed.census_proofs.iter().enumerate() {
        let ok = verify_census_proof(&cp.root, &cp.leaf, cp.index, &cp.siblings);
        if !ok {
            *fail_mask |= 1 << 12; // CENSUS_FAIL bit
            return false;
        }
    }
    true
}
