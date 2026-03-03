//! Binary input parsing for the davinci-zkvm circuit.
//!
//! # Binary format
//!
//! All integers are little-endian; field/curve elements are stored as `[u64; N]`.
//!
//! ```text
//! Header : magic(u64) log_n(u64) nproofs(u64) n_public(u64)
//! VK     : alpha_g1(G1) beta_g2(G2) gamma_g2(G2) delta_g2(G2)
//!          gamma_abc_len(u64) gamma_abc[..](G1 each)
//! Proofs : nproofs(u64) [a(G1) b(G2) c(G1) pubs[..](FrRaw each)] × nproofs
//! Hints  : scaled_a[..](G1 each) neg_alpha_rsum(G1) neg_g_ic(G1) neg_acc_c(G1)
//! ECDSA  : [r s px py](FrRaw each) × nproofs  (mandatory)
//! STATETX: STATE_MAGIC(u64) followed by full state-transition data
//! CENSUS : CENSUS_MAGIC(u64) followed by lean-IMT proofs
//! REENC  : REENC_MAGIC(u64) followed by re-encryption data
//! KZGBLK : KZG_MAGIC(u64) followed by KZG evaluation data
//! ```

use crate::bn254::{g1_identity, g2_identity};
use crate::types::*;

/// Read `N` little-endian `u64` words from `input` at `*offset`, advancing `*offset`.
/// Returns `None` => without moving `*offset` => if insufficient bytes remain.
pub fn read_words_le<const N: usize>(input: &[u8], offset: &mut usize) -> Option<[u64; N]> {
    let bytes = N * 8;
    if *offset + bytes > input.len() {
        return None;
    }
    let mut out = [0u64; N];
    for i in 0..N {
        let start = *offset + i * 8;
        out[i] = u64::from_le_bytes(input[start..start + 8].try_into().unwrap());
    }
    *offset += bytes;
    Some(out)
}

/// All data parsed from a single ZisK binary input blob.
pub struct ParsedInput {
    pub log_n: usize,
    pub nproofs: usize,
    pub n_public: usize,
    pub vk_alpha_g1: G1,
    pub vk_beta_g2: G2,
    pub vk_gamma_g2: G2,
    pub vk_delta_g2: G2,
    pub vk_gamma_abc: Vec<G1>,
    pub proofs: Vec<ProofRaw>,
    pub scaled_a: Vec<G1>,
    pub neg_alpha_rsum: G1,
    pub neg_g_ic: G1,
    pub neg_acc_c: G1,
    /// ECDSA entries; one per proof (mandatory).
    pub ecdsa: Vec<EcdsaEntry>,
    /// Full state-transition data (STATETX! magic). None if absent.
    pub state: Option<StateBlock>,
    /// Census lean-IMT Poseidon proofs (CENSUS!! magic). Empty if absent.
    pub census_proofs: Vec<CensusProofEntry>,
    /// CSP ECDSA census block (CSPBLK!! magic). None if absent.
    pub csp_block: Option<CspBlock>,
    /// Re-encryption verification entries (REENCBLK magic). Empty if absent.
    pub reenc_pub_key: Option<(FrRaw, FrRaw)>,
    pub reenc_entries: Vec<ReencEntry>,
    /// KZG barycentric evaluation block (KZGBLK!! magic). None if absent.
    pub kzg: Option<KZGBlock>,
    /// Number of bytes consumed (equals `input.len()` on success).
    pub bytes_consumed: usize,
}

/// Parse the binary input blob, setting bits in `fail_mask` on any error.
/// This function is **infallible** => it always returns a `ParsedInput`, using
/// identity/zero fallbacks for unreadable fields.  Callers must check `fail_mask`
/// (particularly bit 31 = parse error) before trusting the returned data.
/// # Fail-mask bits
/// - Bit 31 => format/parse error (magic mismatch, truncated data, counter mismatch)
pub fn parse_input(input: &[u8], fail_mask: &mut u32) -> ParsedInput {
    // Convenience macros to read fields and record failures without early-return.
    macro_rules! read1 {
        ($off:expr, $default:expr) => {
            read_words_le::<1>(input, $off)
                .map(|x| x[0])
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; $default })
        };
    }
    macro_rules! read_g1 { ($off:expr) => {
        read_words_le::<8>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; g1_identity() })
    };}
    macro_rules! read_g2 { ($off:expr) => {
        read_words_le::<16>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; g2_identity() })
    };}
    macro_rules! read_fr { ($off:expr) => {
        read_words_le::<4>(input, $off).unwrap_or_else(|| { *fail_mask |= 1 << 31; ZERO_FR })
    };}

    let mut off = 0usize;

    // --- Header ---
    let magic    = read1!(&mut off, 0);
    let log_n    = read1!(&mut off, 0) as usize;
    let nproofs  = read1!(&mut off, 0) as usize;
    let n_public = read1!(&mut off, 0) as usize;

    if magic != MAGIC              { *fail_mask |= 1 << 31; }
    if nproofs == 0 || nproofs > 4096 { *fail_mask |= 1 << 31; }
    if n_public > 256              { *fail_mask |= 1 << 31; }

    // --- Verification key ---
    let vk_alpha_g1 = read_g1!(&mut off);
    let vk_beta_g2  = read_g2!(&mut off);
    let vk_gamma_g2 = read_g2!(&mut off);
    let vk_delta_g2 = read_g2!(&mut off);

    let gamma_abc_len = read1!(&mut off, 0) as usize;
    if gamma_abc_len != n_public + 1 { *fail_mask |= 1 << 31; }

    let mut vk_gamma_abc = Vec::with_capacity(gamma_abc_len);
    for _ in 0..gamma_abc_len {
        vk_gamma_abc.push(read_g1!(&mut off));
    }

    // --- Proofs ---
    let nproofs_check = read1!(&mut off, 0) as usize;
    if nproofs_check != nproofs { *fail_mask |= 1 << 31; }

    let mut proofs = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        let a = read_g1!(&mut off);
        let b = read_g2!(&mut off);
        let c = read_g1!(&mut off);
        let mut public_inputs = Vec::with_capacity(n_public);
        for _ in 0..n_public {
            public_inputs.push(read_fr!(&mut off));
        }
        proofs.push(ProofRaw { a, b, c, public_inputs });
    }

    // --- Precomputed hints (validated by the pairing equation) ---
    let mut scaled_a = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        scaled_a.push(read_g1!(&mut off));
    }
    let neg_alpha_rsum = read_g1!(&mut off);
    let neg_g_ic       = read_g1!(&mut off);
    let neg_acc_c      = read_g1!(&mut off);

    // --- ECDSA block (mandatory) ---
    // Must be present: exactly nproofs × (r + s + px + py) × 32 bytes follow.
    let ecdsa_block_size = nproofs * 4 * 32;
    if *fail_mask == 0 && off + ecdsa_block_size > input.len() {
        *fail_mask |= 1 << 31;
    }

    let mut ecdsa = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        let r  = read_fr!(&mut off);
        let s  = read_fr!(&mut off);
        let px = read_fr!(&mut off);
        let py = read_fr!(&mut off);
        ecdsa.push(EcdsaEntry { r, s, px, py });
    }

    // --- State-transition block (STATETX!) ---
    let mut state: Option<StateBlock> = None;
    let mut census_proofs: Vec<CensusProofEntry> = Vec::new();
    let mut csp_block: Option<CspBlock> = None;
    let mut reenc_pub_key: Option<(FrRaw, FrRaw)> = None;
    let mut reenc_entries: Vec<ReencEntry> = Vec::new();
    let mut kzg: Option<KZGBlock> = None;

    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == STATE_MAGIC {
            off += 8;
            state = Some(parse_state_block(input, &mut off, fail_mask));
        }
    }

    // --- Census block (optional, after state block) ---
    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == CENSUS_MAGIC {
            off += 8;
            let n_proofs = read1!(&mut off, 0) as usize;
            if n_proofs > 4096 { *fail_mask |= 1 << 31; }
            census_proofs.reserve(n_proofs);
            for _ in 0..n_proofs {
                let root = read_fr!(&mut off);
                let leaf = read_fr!(&mut off);
                let index = read1!(&mut off, 0);
                let n_siblings = read1!(&mut off, 0) as usize;
                if n_siblings > 64 { *fail_mask |= 1 << 31; }
                let mut siblings = Vec::with_capacity(n_siblings);
                for _ in 0..n_siblings {
                    siblings.push(read_fr!(&mut off));
                }
                census_proofs.push(CensusProofEntry { root, leaf, index, siblings });
            }
        }
    }

    // --- CSP block (optional, after census block) ---
    // Format: CSPBLK!!(u64) | n_entries(u64) | csp_pub_key_x(FrRaw) | csp_pub_key_y(FrRaw)
    //         Per entry: r(FrRaw) s(FrRaw) voter_address(FrRaw) weight(FrRaw) index(u64)
    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == CSP_MAGIC {
            off += 8;
            let n_entries = read1!(&mut off, 0) as usize;
            if n_entries > 4096 { *fail_mask |= 1 << 31; }
            let csp_pub_key_x = read_fr!(&mut off);
            let csp_pub_key_y = read_fr!(&mut off);
            let mut entries = Vec::with_capacity(n_entries);
            for _ in 0..n_entries {
                let r = read_fr!(&mut off);
                let s = read_fr!(&mut off);
                let voter_address = read_fr!(&mut off);
                let weight = read_fr!(&mut off);
                let index = read1!(&mut off, 0);
                entries.push(CspEntry { r, s, voter_address, weight, index });
            }
            csp_block = Some(CspBlock { csp_pub_key_x, csp_pub_key_y, entries });
        }
    }

    // --- Re-encryption block (optional, after census block) ---
    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == REENC_MAGIC {
            off += 8;
            let n_voters = read1!(&mut off, 0) as usize;
            let pub_key_x = read_fr!(&mut off);
            let pub_key_y = read_fr!(&mut off);
            reenc_pub_key = Some((pub_key_x, pub_key_y));
            reenc_entries.reserve(n_voters);
            for _ in 0..n_voters {
                let k = read_fr!(&mut off);
                let mut original: [BjjCiphertext; 8] = Default::default();
                let mut reencrypted: [BjjCiphertext; 8] = Default::default();
                for j in 0..8 {
                    original[j] = BjjCiphertext {
                        c1x: read_fr!(&mut off),
                        c1y: read_fr!(&mut off),
                        c2x: read_fr!(&mut off),
                        c2y: read_fr!(&mut off),
                    };
                }
                for j in 0..8 {
                    reencrypted[j] = BjjCiphertext {
                        c1x: read_fr!(&mut off),
                        c1y: read_fr!(&mut off),
                        c2x: read_fr!(&mut off),
                        c2y: read_fr!(&mut off),
                    };
                }
                reenc_entries.push(ReencEntry { k, original, reencrypted });
            }
        }
    }

    // --- KZG block (optional, after re-encryption block) ---
    // Format: KZGBLK!! (u64) | processID (FrRaw) | rootHashBefore (FrRaw) |
    //         commitment (48 bytes) | y_claimed (32 bytes) | blob (131072 bytes)
    const BLOB_BYTES: usize = 4096 * 32;
    const KZG_BLOCK_SIZE: usize = 8 + 32 + 32 + 48 + 32 + BLOB_BYTES;
    if off + KZG_BLOCK_SIZE <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == KZG_MAGIC {
            off += 8;
            let process_id    = read_fr!(&mut off);
            let root_hash_before = read_fr!(&mut off);

            // commitment: 48 raw bytes
            let commitment: [u8; 48] = input[off..off + 48].try_into().unwrap();
            off += 48;

            // y_claimed: 32 raw bytes
            let y_claimed: [u8; 32] = input[off..off + 32].try_into().unwrap();
            off += 32;

            // blob: 4096 × 32 = 131072 raw bytes
            let blob = input[off..off + BLOB_BYTES].to_vec();
            off += BLOB_BYTES;

            kzg = Some(KZGBlock { process_id, root_hash_before, commitment, y_claimed, blob });
        }
    }

    if off != input.len() {
        *fail_mask |= 1 << 31;
    }

    ParsedInput {
        log_n, nproofs, n_public,
        vk_alpha_g1, vk_beta_g2, vk_gamma_g2, vk_delta_g2, vk_gamma_abc,
        proofs, scaled_a, neg_alpha_rsum, neg_g_ic, neg_acc_c,
        ecdsa, state, census_proofs, csp_block,
        reenc_pub_key, reenc_entries, kzg,
        bytes_consumed: off,
    }
}

/// Parse an SMT transition (n_levels siblings) from `input` at `*off`.
fn parse_smt_transition(input: &[u8], off: &mut usize, n_levels: usize, fail_mask: &mut u32) -> SmtTransition {
    macro_rules! read1 {
        ($default:expr) => {
            read_words_le::<1>(input, off)
                .map(|x| x[0])
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; $default })
        };
    }
    macro_rules! read_fr {
        () => {
            read_words_le::<4>(input, off)
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; ZERO_FR })
        };
    }
    let old_root  = read_fr!();
    let new_root  = read_fr!();
    let old_key   = read_fr!();
    let old_value = read_fr!();
    let is_old0   = read1!(0) != 0;
    let new_key   = read_fr!();
    let new_value = read_fr!();
    let fnc0      = read1!(0) != 0;
    let fnc1      = read1!(0) != 0;
    let mut siblings = Vec::with_capacity(n_levels);
    for _ in 0..n_levels {
        siblings.push(read_fr!());
    }
    SmtTransition { old_root, new_root, old_key, old_value, is_old0, new_key, new_value, fnc0, fnc1, siblings }
}

/// Parse the STATETX block (magic already consumed) into a `StateBlock`.
fn parse_state_block(input: &[u8], off: &mut usize, fail_mask: &mut u32) -> StateBlock {
    macro_rules! read1 {
        ($default:expr) => {
            read_words_le::<1>(input, off)
                .map(|x| x[0])
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; $default })
        };
    }
    macro_rules! read_fr {
        () => {
            read_words_le::<4>(input, off)
                .unwrap_or_else(|| { *fail_mask |= 1 << 31; ZERO_FR })
        };
    }

    let n_voters      = read1!(0) as usize;
    let n_overwritten = read1!(0) as usize;
    let process_id    = read_fr!();
    let old_state_root = read_fr!();
    let new_state_root = read_fr!();

    // VoteID chain
    let vote_id_n      = read1!(0) as usize;
    let n_levels       = read1!(0) as usize;
    if n_levels > 256 { *fail_mask |= 1 << 31; }
    let mut vote_id_chain = Vec::with_capacity(vote_id_n);
    for _ in 0..vote_id_n {
        vote_id_chain.push(parse_smt_transition(input, off, n_levels, fail_mask));
    }

    // Ballot chain
    let ballot_n       = read1!(0) as usize;
    let ballot_n_levels = read1!(0) as usize;
    if ballot_n_levels > 256 { *fail_mask |= 1 << 31; }
    let mut ballot_chain = Vec::with_capacity(ballot_n);
    for _ in 0..ballot_n {
        ballot_chain.push(parse_smt_transition(input, off, ballot_n_levels, fail_mask));
    }

    // ResultsAdd (0 or 1)
    let has_results_add  = read1!(0) != 0;
    let results_n_levels = read1!(0) as usize;
    if results_n_levels > 256 { *fail_mask |= 1 << 31; }
    let results_add = if has_results_add {
        Some(parse_smt_transition(input, off, results_n_levels, fail_mask))
    } else {
        None
    };

    // ResultsSub (0 or 1, same n_levels)
    let has_results_sub = read1!(0) != 0;
    let results_sub = if has_results_sub {
        Some(parse_smt_transition(input, off, results_n_levels, fail_mask))
    } else {
        None
    };

    // Process read-proofs: n (0 or 4), then n_levels + entries only when n>0.
    let process_n = read1!(0) as usize;
    if process_n != 0 && process_n != 4 { *fail_mask |= 1 << 31; }
    let mut process_proofs = Vec::with_capacity(process_n);
    if process_n > 0 {
        let process_n_levels = read1!(0) as usize;
        if process_n_levels > 256 { *fail_mask |= 1 << 31; }
        for _ in 0..process_n {
            process_proofs.push(parse_smt_transition(input, off, process_n_levels, fail_mask));
        }
    }

    // Result accumulator ballot data
    // has_ballot_data: 0 = absent (zeros), 1 = present
    let has_ballot_data = read1!(0) != 0;
    let zero_ballot: [FrRaw; 32] = [ZERO_FR; 32];
    let (old_results_add, old_results_sub, voter_ballots, overwritten_ballots) = if has_ballot_data {
        let mut old_ra = [ZERO_FR; 32];
        for i in 0..32 { old_ra[i] = read_fr!(); }
        let mut old_rs = [ZERO_FR; 32];
        for i in 0..32 { old_rs[i] = read_fr!(); }

        let n_vb = read1!(0) as usize;
        if n_vb > 4096 { *fail_mask |= 1 << 31; }
        let mut vb = Vec::with_capacity(n_vb);
        for _ in 0..n_vb {
            let mut b = [ZERO_FR; 32];
            for i in 0..32 { b[i] = read_fr!(); }
            vb.push(b);
        }

        let n_ob = read1!(0) as usize;
        if n_ob > 4096 { *fail_mask |= 1 << 31; }
        let mut ob = Vec::with_capacity(n_ob);
        for _ in 0..n_ob {
            let mut b = [ZERO_FR; 32];
            for i in 0..32 { b[i] = read_fr!(); }
            ob.push(b);
        }
        (old_ra, old_rs, vb, ob)
    } else {
        (zero_ballot, zero_ballot, Vec::new(), Vec::new())
    };

    StateBlock {
        n_voters, n_overwritten,
        process_id, old_state_root, new_state_root,
        vote_id_chain, ballot_chain,
        results_add, results_sub,
        process_proofs,
        n_levels,
        old_results_add, old_results_sub,
        voter_ballots, overwritten_ballots,
    }
}
