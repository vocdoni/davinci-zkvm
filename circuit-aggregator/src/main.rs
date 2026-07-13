// DAVINCI chain aggregator guest.
//
// Folds vote-batch STARK proofs into a single recursive chain anchored at a
// genesis state derived from the immutable election config. Each fold step
// verifies the previous fold proof (if any) plus K batch proofs in-guest via
// `verify_zisk_proof_c`, checks state-root continuity, and commits a digest
// binding the whole chain. The final fold gets a PLONK wrap host-side.
//
// Input frames (each one a `read_input_slice` frame):
//   1. header: 12 u64 LE = [magic, mode, has_prev, n_batch, batch_vk[4], fold_vk[4]]
//   2. config: 200 bytes = process_id(32 LE) | ballot_mode(32 LE) | enc_x(32 LE)
//      | enc_y(32 LE) | census_origin(u64 LE) | census_root(32 LE) |
//      ballot_vk_hash(32 LE)
//   3. (if has_prev == 1) previous fold proof blob
//   4. fold: n_batch vote-batch proof blobs
//      finalize: one results frame (see RESULTS FRAME below)
//
// RESULTS FRAME (finalize mode, all LE):
//   ballot     32 x 32B   TE coords of the net Results accumulator (8 ciphertexts)
//   results     8 x u64   claimed plaintexts of ballot
//   cp proofs   8 x 160B  A1x A1y A2x A2y Z (32B each), one per ciphertext
//   n_levels    u64       SMT depth (siblings padded to this length)
//   siblings    n x 32B   inclusion siblings for the Results leaf (key 0x04)
//
// Proof blob layout (u64 LE words, `get_proof_bytes()` from ZisK v0.18.0):
//   [minimal][n_publics=68][program_vk(4)][publics(64)][proof][zisk_vk(4)]
// Each publics word holds one u32 of the inner guest's output registers.
//
// Output digest (53 u32, committed as LE bytes):
//   [0]      magic "DAG1"
//   [1]      mode (1 = fold, 2 = finalize)
//   [2]      step_count
//   [3]      total_voters
//   [4]      total_overwrites
//   [5..13]  config_commitment = sha256(config frame ‖ batch_vk ‖ fold_vk)
//   [13..21] state_root (last root_after)
//   [21..29] batch_vk
//   [29..37] fold_vk
//   [37..53] plaintext results (finalize only, zero otherwise): 16 u32 field
//            tallies, one per ballot field (each < 2^32)
//
// VK binding: batch_vk / fold_vk arrive as input and are committed in the
// digest. After PLONK verification the host checks publics.fold_vk ==
// proof.program_vk and publics.batch_vk == the known vote-batch vk; the
// digest chain then pins every intermediate step to the same vks.
// config_commitment additionally folds both vks into the genesis commitment,
// so one value binds the initial parameters AND the circuit release: a proof
// from one ELF release cannot be replayed under another's constants.

#![no_main]
ziskos::entrypoint!(main);

use circuit_primitives::chaum_pedersen::{verify_decryption, CpProof};
use circuit_primitives::hash::{hash_enc_key, sha256_once};
use circuit_primitives::results::ballot_leaf_hash;
use circuit_primitives::smt::{get_bit, le_to_fr, leaf_hash, node_hash, verify_transition};
use circuit_primitives::types::{FrRaw, SmtTransition, ZERO_FR};
use ziskos::io::{commit_slice, read_input_slice};

const AGG_MAGIC_IN: u64 = u64::from_le_bytes(*b"DAVAGGR!");
const AGG_MAGIC_OUT: u32 = u32::from_le_bytes(*b"DAG1");
const MODE_FOLD: u64 = 1;
const MODE_FINALIZE: u64 = 2;

// Universal ZisK vadcop-final verification key (rootC) for v0.18.0. Bound to
// the ZisK release, not to any guest program. Every inner proof's zisk_vk
// must match, otherwise it was produced by a different prover stack.
const ROOTC: [u64; 4] = [
    0xcf2a309856f107b1,
    0x43836ada112806da,
    0x71ae11567fa3f2d2,
    0x050baba5381c7b7d,
];

const CONFIG_LEN: usize = 200;
const DIGEST_WORDS: usize = 53;

// Proof blob word offsets.
const BLOB_VK_OFF: usize = 2; // program_vk at words [2..6]
const BLOB_PUBS_OFF: usize = 6; // publics at words [6..70]
const BLOB_PUBS_WORDS: usize = 64;

struct Config {
    process_id: FrRaw,
    ballot_mode: FrRaw,
    enc_x: FrRaw,
    enc_y: FrRaw,
    census_origin: u64,
    census_root: FrRaw,
    ballot_vk_hash: FrRaw,
}

fn parse_config(frame: &[u8]) -> Config {
    assert_eq!(frame.len(), CONFIG_LEN, "bad config frame length");
    let fr_at = |off: usize| le_to_fr(frame[off..off + 32].try_into().unwrap());
    Config {
        process_id: fr_at(0),
        ballot_mode: fr_at(32),
        enc_x: fr_at(64),
        enc_y: fr_at(96),
        census_origin: u64::from_le_bytes(frame[128..136].try_into().unwrap()),
        census_root: fr_at(136),
        ballot_vk_hash: fr_at(168),
    }
}

/// Election-identity commitment: sha256 over the config frame plus the two
/// circuit verification keys (each 4 u64 LE = 32 bytes). Binding the vks here
/// pins the initial parameters and the circuit release in a single value.
fn config_commitment(frame: &[u8], batch_vk: &[u64; 4], fold_vk: &[u64; 4]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(frame.len() + 64);
    buf.extend_from_slice(frame);
    for w in batch_vk.iter().chain(fold_vk.iter()) {
        buf.extend_from_slice(&w.to_le_bytes());
    }
    sha256_once(&buf)
}

/// Arbo root of a set of (key, value) leaves. Floating-leaf rule: a subtree
/// holding exactly one leaf hashes as the leaf itself, regardless of depth.
fn subtree_root(leaves: &[(FrRaw, FrRaw)], level: usize) -> FrRaw {
    match leaves.len() {
        0 => ZERO_FR,
        1 => leaf_hash(&leaves[0].0, &leaves[0].1),
        _ => {
            let mut left: Vec<(FrRaw, FrRaw)> = Vec::new();
            let mut right: Vec<(FrRaw, FrRaw)> = Vec::new();
            for l in leaves {
                if get_bit(&l.0, level) {
                    right.push(*l);
                } else {
                    left.push(*l);
                }
            }
            node_hash(&subtree_root(&left, level + 1), &subtree_root(&right, level + 1))
        }
    }
}

/// Genesis state root: the 6 reserved config leaves in an otherwise empty
/// arbo SHA-256 SMT. Mirrors davinci-node `state.Initialize()`.
fn genesis_root(cfg: &Config) -> FrRaw {
    let zero_results = ballot_leaf_hash(&circuit_primitives::results::zero_ballot());
    let leaves: [(FrRaw, FrRaw); 6] = [
        ([0x00, 0, 0, 0], cfg.process_id),                       // ProcessID
        ([0x02, 0, 0, 0], cfg.ballot_mode),                      // BallotMode
        ([0x03, 0, 0, 0], hash_enc_key(&cfg.enc_x, &cfg.enc_y)), // EncryptionKey
        ([0x04, 0, 0, 0], zero_results),                         // Results (net)
        ([0x06, 0, 0, 0], [cfg.census_origin, 0, 0, 0]),         // CensusOrigin
        ([0x07, 0, 0, 0], cfg.ballot_vk_hash),                   // BallotVKHash
    ];
    subtree_root(&leaves, 0)
}

/// FrRaw → 8 u32 (limb lo/hi), matching the batch circuit's
/// `write_fr_output` register encoding.
fn fr_to_u32x8(v: &FrRaw) -> [u32; 8] {
    let mut out = [0u32; 8];
    for i in 0..4 {
        out[i * 2] = (v[i] & 0xFFFF_FFFF) as u32;
        out[i * 2 + 1] = (v[i] >> 32) as u32;
    }
    out
}

fn u32x8_to_fr(v: &[u32; 8]) -> FrRaw {
    let mut out = ZERO_FR;
    for i in 0..4 {
        out[i] = (v[i * 2] as u64) | ((v[i * 2 + 1] as u64) << 32);
    }
    out
}

/// Finalize mode: parse and verify the results frame against the chain's
/// final `state_root` and the config's encryption key, filling
/// `results_u32` with the plaintext tally (16 x u32, one per field; each < 2^32).
/// The single net accumulator decrypts straight to the result; non-negativity
/// is inherent in the bounded discrete-log recovery, so no add−sub guard is
/// needed. Panics on any invalid proof.
fn verify_results(frame: &[u8], cfg: &Config, state_root: &[u32; 8], results_u32: &mut [u32; 16]) {
    const BALLOT_BYTES: usize = 64 * 32;
    const CP_BYTES: usize = 160;
    let fixed = BALLOT_BYTES + 128 + 16 * CP_BYTES + 8;
    assert!(frame.len() >= fixed, "results frame too short");
    let fr_at = |off: usize| le_to_fr(frame[off..off + 32].try_into().unwrap());
    let u64_at = |off: usize| u64::from_le_bytes(frame[off..off + 8].try_into().unwrap());

    let mut ballot = [ZERO_FR; 64];
    for i in 0..64 {
        ballot[i] = fr_at(i * 32);
    }
    let mut off = BALLOT_BYTES;
    let mut results = [0u64; 16];
    for i in 0..16 {
        results[i] = u64_at(off + i * 8);
    }
    off += 128;

    // Chaum-Pedersen decryption proofs: one per ciphertext.
    let enc_key = (cfg.enc_x, cfg.enc_y);
    for i in 0..16 {
        let p = off + i * CP_BYTES;
        let proof = CpProof {
            a1: (fr_at(p), fr_at(p + 32)),
            a2: (fr_at(p + 64), fr_at(p + 96)),
            z: fr_at(p + 128),
        };
        let c1 = (ballot[i * 4], ballot[i * 4 + 1]);
        let c2 = (ballot[i * 4 + 2], ballot[i * 4 + 3]);
        assert!(
            verify_decryption(&enc_key, &c1, &c2, results[i], &proof),
            "CP proof {} failed", i
        );
    }
    off += 16 * CP_BYTES;

    // SMT inclusion of the net Results leaf under the final state root.
    // An identity update (fnc=(0,1), old == new) through the processor
    // proves the leaf is present with exactly this value.
    let n_levels = u64_at(off) as usize;
    off += 8;
    assert_eq!(frame.len(), off + n_levels * 32, "bad results frame length");
    let root = u32x8_to_fr(state_root);
    let siblings: Vec<FrRaw> = (0..n_levels).map(|i| fr_at(off + i * 32)).collect();
    let leaf = ballot_leaf_hash(&ballot);
    let t = SmtTransition {
        old_root: root,
        new_root: root,
        old_key: [0x04, 0, 0, 0],
        old_value: leaf,
        is_old0: false,
        new_key: [0x04, 0, 0, 0],
        new_value: leaf,
        fnc0: false,
        fnc1: true,
        siblings,
    };
    assert!(verify_transition(&t), "results leaf 0x04 inclusion failed");

    for i in 0..16 {
        assert!(results[i] <= u32::MAX as u64, "result {} overflows u32 digest slot", i);
        results_u32[i] = results[i] as u32;
    }
}

fn bytes32_to_u32x8(b: &[u8; 32]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

/// Verify a proof blob in-guest and return (program_vk, publics as u32, zisk_vk).
fn verify_blob(blob: &[u8], what: &str) -> ([u64; 4], [u32; BLOB_PUBS_WORDS], [u64; 4]) {
    assert!(blob.len() % 8 == 0 && blob.len() / 8 > BLOB_PUBS_OFF + BLOB_PUBS_WORDS + 4,
        "{}: blob too short", what);
    let valid = unsafe { ziskos::zisklib::verify_zisk_proof_c(blob.as_ptr(), blob.len()) };
    assert!(valid, "{}: STARK verification failed", what);

    let word = |i: usize| u64::from_le_bytes(blob[i * 8..i * 8 + 8].try_into().unwrap());
    let n_words = blob.len() / 8;

    let mut program_vk = [0u64; 4];
    let mut zisk_vk = [0u64; 4];
    for i in 0..4 {
        program_vk[i] = word(BLOB_VK_OFF + i);
        zisk_vk[i] = word(n_words - 4 + i);
    }
    let mut publics = [0u32; BLOB_PUBS_WORDS];
    for i in 0..BLOB_PUBS_WORDS {
        let w = word(BLOB_PUBS_OFF + i);
        assert!(w <= u32::MAX as u64, "{}: publics word {} not a u32", what, i);
        publics[i] = w as u32;
    }
    (program_vk, publics, zisk_vk)
}

fn main() {
    let header = read_input_slice();
    assert_eq!(header.len(), 12 * 8, "bad header length");
    let hword = |i: usize| u64::from_le_bytes(header[i * 8..i * 8 + 8].try_into().unwrap());
    assert_eq!(hword(0), AGG_MAGIC_IN, "bad input magic");
    let mode = hword(1);
    let has_prev = hword(2);
    let n_batch = hword(3);
    let mut batch_vk = [0u64; 4];
    let mut fold_vk = [0u64; 4];
    for i in 0..4 {
        batch_vk[i] = hword(4 + i);
        fold_vk[i] = hword(8 + i);
    }

    assert!(mode == MODE_FOLD || mode == MODE_FINALIZE, "bad mode {}", mode);
    if mode == MODE_FINALIZE {
        assert_eq!(n_batch, 0, "finalize takes no batch proofs");
    }

    let config_frame = read_input_slice();
    let cfg = parse_config(&config_frame);
    let commitment = config_commitment(&config_frame, &batch_vk, &fold_vk);
    let commitment_u32 = bytes32_to_u32x8(&commitment);
    let census_root_u32 = fr_to_u32x8(&cfg.census_root);
    let batch_vk_u32 = fr_to_u32x8(&batch_vk);
    let fold_vk_u32 = fr_to_u32x8(&fold_vk);

    // Chain state: either carried from the previous fold proof or freshly
    // derived from the genesis config.
    let mut step_count: u32;
    let mut total_voters: u32;
    let mut total_overwrites: u32;
    let mut state_root: [u32; 8];

    if has_prev == 1 {
        let blob = read_input_slice();
        let (pvk, pubs, zvk) = verify_blob(&blob, "prev fold");
        assert_eq!(pvk, fold_vk, "prev fold: program_vk != fold_vk");
        assert_eq!(zvk, ROOTC, "prev fold: zisk_vk != rootC");
        assert_eq!(pubs[0], AGG_MAGIC_OUT, "prev fold: bad digest magic");
        assert_eq!(pubs[1], MODE_FOLD as u32, "prev fold: not a fold digest");
        assert_eq!(pubs[5..13], commitment_u32, "prev fold: config commitment mismatch");
        assert_eq!(pubs[21..29], batch_vk_u32, "prev fold: batch_vk mismatch");
        assert_eq!(pubs[29..37], fold_vk_u32, "prev fold: fold_vk mismatch");
        step_count = pubs[2];
        total_voters = pubs[3];
        total_overwrites = pubs[4];
        state_root = pubs[13..21].try_into().unwrap();
    } else {
        assert_eq!(has_prev, 0, "bad has_prev flag");
        step_count = 0;
        total_voters = 0;
        total_overwrites = 0;
        state_root = fr_to_u32x8(&genesis_root(&cfg));
    }

    // Fold the batch proofs, enforcing state-root continuity.
    for b in 0..n_batch {
        let blob = read_input_slice();
        let (pvk, pubs, zvk) = verify_blob(&blob, "batch");
        assert_eq!(pvk, batch_vk, "batch {}: program_vk != batch_vk", b);
        assert_eq!(zvk, ROOTC, "batch {}: zisk_vk != rootC", b);
        assert_eq!(pubs[0], 1, "batch {}: circuit reported failure (ok != 1)", b);
        assert_eq!(pubs[1], 0, "batch {}: nonzero fail_mask {:#x}", b, pubs[1]);
        assert_eq!(pubs[2..10], state_root, "batch {}: root_before != chain state_root", b);
        assert_eq!(pubs[20..28], census_root_u32, "batch {}: census_root mismatch", b);
        total_voters = total_voters.checked_add(pubs[18]).unwrap();
        total_overwrites = total_overwrites.checked_add(pubs[19]).unwrap();
        state_root = pubs[10..18].try_into().unwrap();
    }

    let mut results_u32 = [0u32; 16];
    if mode == MODE_FOLD {
        step_count = step_count.checked_add(1).unwrap();
    } else {
        verify_results(&read_input_slice(), &cfg, &state_root, &mut results_u32);
    }

    let mut digest = [0u32; DIGEST_WORDS];
    digest[0] = AGG_MAGIC_OUT;
    digest[1] = mode as u32;
    digest[2] = step_count;
    digest[3] = total_voters;
    digest[4] = total_overwrites;
    digest[5..13].copy_from_slice(&commitment_u32);
    digest[13..21].copy_from_slice(&state_root);
    digest[21..29].copy_from_slice(&batch_vk_u32);
    digest[29..37].copy_from_slice(&fold_vk_u32);
    digest[37..53].copy_from_slice(&results_u32);

    let mut out = [0u8; DIGEST_WORDS * 4];
    for (i, w) in digest.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    commit_slice(&out);
}
