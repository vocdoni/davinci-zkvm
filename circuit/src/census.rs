//! Census Keccak lean-IMT proof verifier.
//!
//! Leaf encoding: `PackAddressWeight(address, weight)` = `(address << 88) | weight`,
//!                below 2^248 (check 3A.6)
//! Tree hash:     `keccak256(be32(left) || be32(right))` (Solidity
//!                `keccak256(abi.encode(left, right))`); a lone right-most
//!                node moves up unhashed
//! Proof format:  `(root, leaf, index: u64, siblings: &[FrRaw])`, every value a
//!                256-bit integer in LE limbs, never reduced mod r
//!
//! Index bit `i` (LSB-first): if bit=1, node is right child (sibling on left).
//!
//! No leaf/node domain tag: an internal node presented as a leaf at a shorter
//! path is rejected by the 2^248 bound unless its top byte is zero, and then
//! its address bits are a Keccak output whose key nobody holds.

use crate::hash::keccak_node;
use crate::types::{FrRaw, FAIL_CENSUS};

/// Longest compact lean-IMT path accepted (rust-sdk `MAX_CENSUS_DEPTH`).
const MAX_CENSUS_DEPTH: usize = 61;

/// Verify a Keccak lean-IMT membership proof.
/// Compatible with lean-imt-go `VerifyProof` with go-sdk `KeccakHasher`.
/// - `root`:     expected tree root
/// - `leaf`:     `PackAddressWeight(address, weight)`
/// - `index`:    packed path bits (bit i = `(index >> i) & 1`)
/// - `siblings`: merkle path (only non-empty levels included), at most 61
pub fn verify_census_proof(root: &FrRaw, leaf: &FrRaw, index: u64, siblings: &[FrRaw]) -> bool {
    // Canonical shape: bounded depth, and no path bit the walk never reads.
    let n = siblings.len();
    if n > MAX_CENSUS_DEPTH || index >> n != 0 {
        return false;
    }
    let mut node = *leaf;

    for (i, sibling) in siblings.iter().enumerate() {
        let bit = (index >> i) & 1;
        node = if bit == 1 {
            // current node is right child: hash(sibling, node)
            keccak_node(sibling, &node)
        } else {
            // current node is left child: hash(node, sibling)
            keccak_node(&node, sibling)
        };
    }

    node == *root
}

/// Verify census proofs for all voters in the parsed input.
/// Returns `true` when all proofs are valid (or when no census proofs are present).
/// Sets `FAIL_CENSUS` in `fail_mask` on failure.
/// Security invariants enforced:
/// 1. All proofs use the **same census root** => prevents mixing proofs from different snapshots.
/// 2. No duplicate leaves => prevents the same voter from voting twice in one batch.
/// 3. Each proof's Merkle path is valid against the declared root, with at
///    most 61 siblings and no path bit above the sibling count.
/// 4. Every leaf is below 2^248 (check 3A.6): the bound separates leaves from
///    internal nodes, which are full 256-bit Keccak outputs.
pub fn verify_batch(parsed: &crate::io::ParsedInput, fail_mask: &mut u32) -> bool {
    if parsed.census_proofs.is_empty() {
        *fail_mask |= crate::types::FAIL_MISSING_BLOCK;
        return false;
    }

    // Invariant 4: leaves below 2^248 (top byte zero).
    for cp in &parsed.census_proofs {
        if cp.leaf[3] >> 56 != 0 {
            *fail_mask |= FAIL_CENSUS;
            return false;
        }
    }

    // Invariant 1: all proofs must reference the same census root
    let expected_root = &parsed.census_proofs[0].root;
    for cp in parsed.census_proofs.iter().skip(1) {
        if &cp.root != expected_root {
            *fail_mask |= FAIL_CENSUS;
            return false;
        }
    }

    // Invariant 2: no duplicate leaves (same voter counted twice)
    let n = parsed.census_proofs.len();
    for i in 0..n {
        for j in (i + 1)..n {
            if parsed.census_proofs[i].leaf == parsed.census_proofs[j].leaf {
                *fail_mask |= FAIL_CENSUS;
                return false;
            }
        }
    }

    // Invariant 3: each proof is valid
    for cp in &parsed.census_proofs {
        if !verify_census_proof(&cp.root, &cp.leaf, cp.index, &cp.siblings) {
            *fail_mask |= FAIL_CENSUS;
            return false;
        }
    }
    true
}
