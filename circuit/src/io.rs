//! Binary input parsing for the davinci-zkvm circuit.
//!
//! All integers are little-endian; field elements are stored as `[u64; N]`.
//!
//! ```text
//! Header : magic(u64) log_n(u64) nproofs(u64) n_public(u64)
//! DSTARKB!: [proof_len(u64) proof_bytes[..] public_values[123 × u64]] × nproofs
//! ECDSA   : [r s px py](FrRaw each) × nproofs  (mandatory)
//! STAG5TX!: full ecgfp5-native state-transition data (optional)
//! CENSUS  : lean-IMT proofs (optional)
//! CSPBLK  : CSP ECDSA census block (optional)
//! REG5BLK!: ecgfp5-native re-encryption data (optional)
//! KZGBLK  : KZG evaluation data (optional)
//! ```

use crate::types::*;

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

pub struct ParsedInput {
    pub log_n: usize,
    pub nproofs: usize,
    pub n_public: usize,
    pub stark_proofs: Vec<StarkProofRaw>,
    pub ecdsa: Vec<EcdsaEntry>,
    pub state: Option<StateBlock>,
    pub census_proofs: Vec<CensusProofEntry>,
    pub csp_block: Option<CspBlock>,
    pub reenc_g5_pub_key: Option<Ecgfp5PointRaw>,
    pub reenc_g5_entries: Vec<Ecgfp5ReencEntry>,
    pub kzg: Option<KZGBlock>,
}

impl ParsedInput {
    pub fn voter_address(&self, index: usize) -> Option<FrRaw> {
        self.stark_proofs
            .get(index)
            .map(|p| p.public_values.address)
    }

    pub fn voter_vote_id(&self, index: usize) -> Option<u64> {
        self.stark_proofs
            .get(index)
            .map(|p| p.public_values.vote_id)
    }
}

pub fn parse_input(input: &[u8], fail_mask: &mut u32) -> ParsedInput {
    macro_rules! read1 {
        ($off:expr, $default:expr) => {
            read_words_le::<1>(input, $off)
                .map(|x| x[0])
                .unwrap_or_else(|| {
                    *fail_mask |= FAIL_PARSE;
                    $default
                })
        };
    }
    macro_rules! read_fr {
        ($off:expr) => {
            read_words_le::<4>(input, $off).unwrap_or_else(|| {
                *fail_mask |= FAIL_PARSE;
                ZERO_FR
            })
        };
    }

    let mut off = 0usize;
    let magic = read1!(&mut off, 0);
    let log_n = read1!(&mut off, 0) as usize;
    let nproofs = read1!(&mut off, 0) as usize;
    let n_public = read1!(&mut off, 0) as usize;

    if magic != STARK_MAGIC {
        *fail_mask |= FAIL_PARSE;
    }
    if nproofs == 0 || nproofs > MAX_BATCH_SIZE {
        *fail_mask |= FAIL_PARSE;
    }
    if n_public != 123 {
        *fail_mask |= FAIL_PARSE;
    }

    let mut stark_proofs = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        let proof_len = read1!(&mut off, 0) as usize;
        if off + proof_len > input.len() {
            *fail_mask |= FAIL_PARSE;
        }
        let proof_bytes = if off + proof_len <= input.len() {
            let bytes = input[off..off + proof_len].to_vec();
            off += proof_len;
            let rem = off % 8;
            if rem != 0 {
                off += 8 - rem;
            }
            bytes
        } else {
            Vec::new()
        };
        let mut inputs_hash = [0u64; 4];
        let mut address = ZERO_FR;
        let vote_id;
        let mut inputs_preimage = [0u64; 114];
        for limb in &mut inputs_hash {
            *limb = read1!(&mut off, 0);
        }
        for limb in &mut address {
            *limb = read1!(&mut off, 0);
        }
        vote_id = read1!(&mut off, 0);
        for limb in &mut inputs_preimage {
            *limb = read1!(&mut off, 0);
        }
        stark_proofs.push(StarkProofRaw {
            proof_bytes,
            public_values: StarkPublicValues {
                inputs_hash,
                address,
                vote_id,
                inputs_preimage,
            },
        });
    }

    let ecdsa_block_size = nproofs * 4 * 32;
    if *fail_mask == 0 && off + ecdsa_block_size > input.len() {
        *fail_mask |= FAIL_PARSE;
    }
    let mut ecdsa = Vec::with_capacity(nproofs);
    for _ in 0..nproofs {
        ecdsa.push(EcdsaEntry {
            r: read_fr!(&mut off),
            s: read_fr!(&mut off),
            px: read_fr!(&mut off),
            py: read_fr!(&mut off),
        });
    }

    let mut state = None;
    let mut census_proofs = Vec::new();
    let mut csp_block = None;
    let mut reenc_g5_pub_key = None;
    let mut reenc_g5_entries = Vec::new();
    let mut kzg = None;

    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == STATE_G5_MAGIC {
            off += 8;
            state = Some(parse_state_block(input, &mut off, fail_mask));
        }
    }

    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == CENSUS_MAGIC {
            off += 8;
            let n_proofs = read1!(&mut off, 0) as usize;
            if n_proofs > 4096 {
                *fail_mask |= FAIL_PARSE;
            }
            census_proofs.reserve(n_proofs);
            for _ in 0..n_proofs {
                let root = read_fr!(&mut off);
                let leaf = read_fr!(&mut off);
                let index = read1!(&mut off, 0);
                let n_siblings = read1!(&mut off, 0) as usize;
                if n_siblings > 64 {
                    *fail_mask |= FAIL_PARSE;
                }
                let mut siblings = Vec::with_capacity(n_siblings);
                for _ in 0..n_siblings {
                    siblings.push(read_fr!(&mut off));
                }
                census_proofs.push(CensusProofEntry {
                    root,
                    leaf,
                    index,
                    siblings,
                });
            }
        }
    }

    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == CSP_MAGIC {
            off += 8;
            let n_entries = read1!(&mut off, 0) as usize;
            if n_entries > 4096 {
                *fail_mask |= FAIL_PARSE;
            }
            let csp_pub_key_x = read_fr!(&mut off);
            let csp_pub_key_y = read_fr!(&mut off);
            let mut entries = Vec::with_capacity(n_entries);
            for _ in 0..n_entries {
                entries.push(CspEntry {
                    r: read_fr!(&mut off),
                    s: read_fr!(&mut off),
                    voter_address: read_fr!(&mut off),
                    weight: read_fr!(&mut off),
                    index: read1!(&mut off, 0),
                });
            }
            csp_block = Some(CspBlock {
                csp_pub_key_x,
                csp_pub_key_y,
                entries,
            });
        }
    }

    if off + 8 <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == REENC_G5_MAGIC {
            off += 8;
            let n_voters = read1!(&mut off, 0) as usize;
            let pub_key = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                *fail_mask |= FAIL_PARSE;
                [0u64; 5]
            });
            reenc_g5_pub_key = Some(pub_key);
            reenc_g5_entries.reserve(n_voters);
            for _ in 0..n_voters {
                let k = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                    *fail_mask |= FAIL_PARSE;
                    [0u64; 5]
                });
                let mut original = [Ecgfp5Ciphertext::default(); 8];
                let mut reencrypted = [Ecgfp5Ciphertext::default(); 8];
                for ct in &mut original {
                    ct.c1 = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                        *fail_mask |= FAIL_PARSE;
                        [0u64; 5]
                    });
                    ct.c2 = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                        *fail_mask |= FAIL_PARSE;
                        [0u64; 5]
                    });
                }
                for ct in &mut reencrypted {
                    ct.c1 = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                        *fail_mask |= FAIL_PARSE;
                        [0u64; 5]
                    });
                    ct.c2 = read_words_le::<5>(input, &mut off).unwrap_or_else(|| {
                        *fail_mask |= FAIL_PARSE;
                        [0u64; 5]
                    });
                }
                reenc_g5_entries.push(Ecgfp5ReencEntry {
                    k,
                    original,
                    reencrypted,
                });
            }
        }
    }

    const BLOB_BYTES: usize = 4096 * 32;
    const KZG_BLOCK_SIZE: usize = 8 + 32 + 32 + 48 + 32 + BLOB_BYTES;
    if off + KZG_BLOCK_SIZE <= input.len() {
        let maybe_magic = u64::from_le_bytes(input[off..off + 8].try_into().unwrap());
        if maybe_magic == KZG_MAGIC {
            off += 8;
            let process_id = read_fr!(&mut off);
            let root_hash_before = read_fr!(&mut off);
            let commitment: [u8; 48] = input[off..off + 48].try_into().unwrap();
            off += 48;
            let y_claimed: [u8; 32] = input[off..off + 32].try_into().unwrap();
            off += 32;
            let blob = input[off..off + BLOB_BYTES].to_vec();
            off += BLOB_BYTES;
            kzg = Some(KZGBlock {
                process_id,
                root_hash_before,
                commitment,
                y_claimed,
                blob,
            });
        }
    }

    if off != input.len() {
        *fail_mask |= FAIL_PARSE;
    }

    ParsedInput {
        log_n,
        nproofs,
        n_public,
        stark_proofs,
        ecdsa,
        state,
        census_proofs,
        csp_block,
        reenc_g5_pub_key,
        reenc_g5_entries,
        kzg,
    }
}

fn parse_smt_transition(
    input: &[u8],
    off: &mut usize,
    n_levels: usize,
    fail_mask: &mut u32,
) -> SmtTransition {
    macro_rules! read1 {
        ($default:expr) => {
            read_words_le::<1>(input, off)
                .map(|x| x[0])
                .unwrap_or_else(|| {
                    *fail_mask |= FAIL_PARSE;
                    $default
                })
        };
    }
    macro_rules! read_fr {
        () => {
            read_words_le::<4>(input, off).unwrap_or_else(|| {
                *fail_mask |= FAIL_PARSE;
                ZERO_FR
            })
        };
    }
    let old_root = read_fr!();
    let new_root = read_fr!();
    let old_key = read_fr!();
    let old_value = read_fr!();
    let is_old0 = read1!(0) != 0;
    let new_key = read_fr!();
    let new_value = read_fr!();
    let fnc0 = read1!(0) != 0;
    let fnc1 = read1!(0) != 0;
    let mut siblings = Vec::with_capacity(n_levels);
    for _ in 0..n_levels {
        siblings.push(read_fr!());
    }
    SmtTransition {
        old_root,
        new_root,
        old_key,
        old_value,
        is_old0,
        new_key,
        new_value,
        fnc0,
        fnc1,
        siblings,
    }
}

fn parse_state_block(input: &[u8], off: &mut usize, fail_mask: &mut u32) -> StateBlock {
    macro_rules! read1 {
        ($default:expr) => {
            read_words_le::<1>(input, off)
                .map(|x| x[0])
                .unwrap_or_else(|| {
                    *fail_mask |= FAIL_PARSE;
                    $default
                })
        };
    }
    macro_rules! read_fr {
        () => {
            read_words_le::<4>(input, off).unwrap_or_else(|| {
                *fail_mask |= FAIL_PARSE;
                ZERO_FR
            })
        };
    }
    macro_rules! read_g5 {
        () => {
            read_words_le::<5>(input, off).unwrap_or_else(|| {
                *fail_mask |= FAIL_PARSE;
                [0u64; 5]
            })
        };
    }

    let n_voters = read1!(0) as usize;
    let n_overwritten = read1!(0) as usize;
    let process_id = read_fr!();
    let old_state_root = read_fr!();
    let new_state_root = read_fr!();

    let vote_id_n = read1!(0) as usize;
    let n_levels = read1!(0) as usize;
    if n_levels > 256 {
        *fail_mask |= FAIL_PARSE;
    }
    let mut vote_id_chain = Vec::with_capacity(vote_id_n);
    for _ in 0..vote_id_n {
        vote_id_chain.push(parse_smt_transition(input, off, n_levels, fail_mask));
    }

    let ballot_n = read1!(0) as usize;
    let ballot_n_levels = read1!(0) as usize;
    if ballot_n_levels > 256 {
        *fail_mask |= FAIL_PARSE;
    }
    let mut ballot_chain = Vec::with_capacity(ballot_n);
    for _ in 0..ballot_n {
        ballot_chain.push(parse_smt_transition(input, off, ballot_n_levels, fail_mask));
    }

    let has_results_add = read1!(0) != 0;
    let results_n_levels = read1!(0) as usize;
    if results_n_levels > 256 {
        *fail_mask |= FAIL_PARSE;
    }
    let results_add = if has_results_add {
        Some(parse_smt_transition(
            input,
            off,
            results_n_levels,
            fail_mask,
        ))
    } else {
        None
    };

    let has_results_sub = read1!(0) != 0;
    let results_sub = if has_results_sub {
        Some(parse_smt_transition(
            input,
            off,
            results_n_levels,
            fail_mask,
        ))
    } else {
        None
    };

    let process_n = read1!(0) as usize;
    if process_n != 0 && process_n != 4 {
        *fail_mask |= FAIL_PARSE;
    }
    let mut process_proofs = Vec::with_capacity(process_n);
    if process_n > 0 {
        let process_n_levels = read1!(0) as usize;
        if process_n_levels > 256 {
            *fail_mask |= FAIL_PARSE;
        }
        for _ in 0..process_n {
            process_proofs.push(parse_smt_transition(
                input,
                off,
                process_n_levels,
                fail_mask,
            ));
        }
    }

    let has_ballot_data = read1!(0) != 0;
    let (old_results_add_g5, old_results_sub_g5, voter_ballots_g5, overwritten_ballots_g5) =
        if has_ballot_data {
            let mut old_ra = [Ecgfp5Ciphertext::default(); 8];
            for ct in &mut old_ra {
                ct.c1 = read_g5!();
                ct.c2 = read_g5!();
            }
            let mut old_rs = [Ecgfp5Ciphertext::default(); 8];
            for ct in &mut old_rs {
                ct.c1 = read_g5!();
                ct.c2 = read_g5!();
            }
            let n_vb = read1!(0) as usize;
            if n_vb > 4096 {
                *fail_mask |= FAIL_PARSE;
            }
            let mut voter_ballots = Vec::with_capacity(n_vb);
            for _ in 0..n_vb {
                let mut ballot = [Ecgfp5Ciphertext::default(); 8];
                for ct in &mut ballot {
                    ct.c1 = read_g5!();
                    ct.c2 = read_g5!();
                }
                voter_ballots.push(ballot);
            }
            let n_ob = read1!(0) as usize;
            if n_ob > 4096 {
                *fail_mask |= FAIL_PARSE;
            }
            let mut overwritten_ballots = Vec::with_capacity(n_ob);
            for _ in 0..n_ob {
                let mut ballot = [Ecgfp5Ciphertext::default(); 8];
                for ct in &mut ballot {
                    ct.c1 = read_g5!();
                    ct.c2 = read_g5!();
                }
                overwritten_ballots.push(ballot);
            }
            (
                Some(old_ra),
                Some(old_rs),
                voter_ballots,
                overwritten_ballots,
            )
        } else {
            (None, None, Vec::new(), Vec::new())
        };

    StateBlock {
        n_voters,
        n_overwritten,
        process_id,
        old_state_root,
        new_state_root,
        vote_id_chain,
        ballot_chain,
        results_add,
        results_sub,
        process_proofs,
        old_results_add_g5,
        old_results_sub_g5,
        voter_ballots_g5,
        overwritten_ballots_g5,
    }
}
