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
use crate::types::{FrRaw, FAIL_CENSUS};

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
/// Sets `FAIL_CENSUS` in `fail_mask` on failure.
///
/// Security invariants enforced:
/// 1. All proofs use the **same census root** — prevents mixing proofs from different snapshots.
/// 2. No duplicate leaves — prevents the same voter from voting twice in one batch.
/// 3. Each proof's Merkle path is valid against the declared root.
pub fn verify_batch(parsed: &crate::io::ParsedInput, fail_mask: &mut u32) -> bool {
    if parsed.census_proofs.is_empty() {
        *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
        return false;
    }

    // ── Invariant 1: all proofs must reference the same census root ───────────
    let expected_root = &parsed.census_proofs[0].root;
    for cp in parsed.census_proofs.iter().skip(1) {
        if &cp.root != expected_root {
            *fail_mask |= FAIL_CENSUS;
            return false;
        }
    }

    // ── Invariant 2: no duplicate leaves (same voter counted twice) ───────────
    let n = parsed.census_proofs.len();
    for i in 0..n {
        for j in (i + 1)..n {
            if parsed.census_proofs[i].leaf == parsed.census_proofs[j].leaf {
                *fail_mask |= FAIL_CENSUS;
                return false;
            }
        }
    }

    // ── Invariant 3: each proof is valid ─────────────────────────────────────
    for cp in &parsed.census_proofs {
        if !verify_census_proof(&cp.root, &cp.leaf, cp.index, &cp.siblings) {
            *fail_mask |= FAIL_CENSUS;
            return false;
        }
    }
    true
}
