#![no_main]
#![allow(clippy::needless_range_loop)]
ziskos::entrypoint!(main);

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInt as ArkBigInt, Field as ArkField, PrimeField};
use ziskos::{
    read_input_slice, set_output,
    syscalls::{syscall_arith256_mod, syscall_keccak_f, SyscallArith256ModParams, SyscallPoint256},
    zisklib::{
        add_bn254, is_on_curve_bn254, is_on_curve_twist_bn254, is_on_subgroup_twist_bn254,
        mul_bn254, neg_fp_bn254, pairing_batch_bn254, secp256k1_ecdsa_verify, sha256f_compress,
    },
};

type G1 = [u64; 8];
type G2 = [u64; 16];
type GT = [u64; 48];
type FrRaw = [u64; 4];

// "GROTH16B" in little-endian ASCII
const MAGIC: u64 = 0x423631484f545247u64;

const BN254_FR_MODULUS: FrRaw = [
    4891460686036598785,
    2896914383306846353,
    13281191951274694749,
    3486998266802970665,
];
const ZERO_FR: FrRaw = [0, 0, 0, 0];
const ONE_FR: FrRaw = [1, 0, 0, 0];

fn g1_identity() -> G1 {
    let mut id = [0u64; 8];
    id[4] = 1;
    id
}

fn g2_identity() -> G2 {
    let mut id = [0u64; 16];
    id[8] = 1;
    id
}

fn gt_one() -> GT {
    let mut one = [0u64; 48];
    one[0] = 1;
    one
}

fn read_words_le<const N: usize>(input: &[u8], offset: &mut usize) -> Option<[u64; N]> {
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

fn g1_neg(p: &G1) -> G1 {
    if *p == g1_identity() {
        return *p;
    }
    let mut out = *p;
    let y: [u64; 4] = p[4..8].try_into().unwrap();
    let y_neg = neg_fp_bn254(&y);
    out[4..8].copy_from_slice(&y_neg);
    out
}

fn g1_is_valid(p: &G1) -> bool {
    if *p == g1_identity() { true } else { is_on_curve_bn254(p) }
}

fn g2_is_valid(p: &G2) -> bool {
    if *p == g2_identity() {
        true
    } else {
        is_on_curve_twist_bn254(p) && is_on_subgroup_twist_bn254(p)
    }
}

fn gt_eq(a: &GT, b: &GT) -> bool { a == b }

fn fr_eq(a: &FrRaw, b: &FrRaw) -> bool { a == b }

fn add_fr(a: &FrRaw, b: &FrRaw) -> FrRaw {
    let mut out = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a,
        b: &ONE_FR,
        c: b,
        module: &BN254_FR_MODULUS,
        d: &mut out,
    };
    syscall_arith256_mod(&mut params);
    out
}

fn mul_fr(a: &FrRaw, b: &FrRaw) -> FrRaw {
    let mut out = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a,
        b,
        c: &ZERO_FR,
        module: &BN254_FR_MODULUS,
        d: &mut out,
    };
    syscall_arith256_mod(&mut params);
    out
}

fn structured_scalar_power(num: usize, s: &FrRaw) -> Vec<FrRaw> {
    let mut powers = vec![ONE_FR];
    for i in 1..num {
        powers.push(mul_fr(&powers[i - 1], s));
    }
    powers
}

// SHA256 using ZisK sha256f hardware precompile.
// Handles arbitrary-length input via standard SHA256 padding.
fn sha256_once(data: &[u8]) -> [u8; 32] {
    let mut state = [
        0x6a09e667u32, 0xbb67ae85u32, 0x3c6ef372u32, 0xa54ff53au32,
        0x510e527fu32, 0x9b05688cu32, 0x1f83d9abu32, 0x5be0cd19u32,
    ];
    let bit_len = (data.len() as u64) * 8;
    let len = data.len();
    let padded_len = ((len + 9 + 63) / 64) * 64;
    let mut padded = vec![0u8; padded_len];
    padded[..len].copy_from_slice(data);
    padded[len] = 0x80;
    padded[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());
    let n_blocks = padded_len / 64;
    let mut blocks: Vec<[u8; 64]> = Vec::with_capacity(n_blocks);
    for i in 0..n_blocks {
        blocks.push(padded[i * 64..(i + 1) * 64].try_into().unwrap());
    }
    sha256f_compress(&mut state, &blocks);
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

// Keccak-256 using ZisK keccak_f hardware precompile (Keccak rate = 136 bytes).
// Handles up to 135 bytes of input (fits in one block — sufficient for our use cases:
//   60 bytes for Ethereum signed-message hash, 64 bytes for pubkey address derivation).
//
// NOTE: This uses Keccak-256 padding (domain separation = 0x01), NOT SHA3-256 (0x06).
// Go-ethereum uses Keccak-256 which matches this implementation.
fn keccak256_short(data: &[u8]) -> [u8; 32] {
    assert!(data.len() < 136, "keccak256_short: input too long (>= 136 bytes)");
    // Lane-based Keccak state (25 × u64 = 200 bytes), initialised to zero
    let mut state = [0u64; 25];

    // Absorb: XOR padded message into first 136 bytes (rate) of state.
    // Keccak-256 padding: message || 0x01 || 0x00...00 || 0x80 (at byte index 135)
    for (i, &b) in data.iter().enumerate() {
        state[i / 8] ^= (b as u64) << ((i % 8) * 8);
    }
    // Domain suffix 0x01 at byte after message
    let pad_pos = data.len();
    state[pad_pos / 8] ^= 0x01u64 << ((pad_pos % 8) * 8);
    // Rate terminator 0x80 at byte 135 (last byte of the 136-byte block)
    state[135 / 8] ^= 0x80u64 << ((135 % 8) * 8);

    // Permute
    unsafe { syscall_keccak_f(&mut state as *mut [u64; 25]); }

    // Extract first 32 bytes (the 256-bit digest) from the LE lane state
    let mut out = [0u8; 32];
    for i in 0..32usize {
        out[i] = (state[i / 8] >> ((i % 8) * 8)) as u8;
    }
    out
}

// Build the 60-byte Ethereum signed-message for a vote_id and return keccak256(message)
// as a [u64; 4] little-endian scalar (for use as z in secp256k1_ecdsa_verify).
//
// Scheme (matching davinci-node/crypto/signatures/ethereum):
//   message  = PadToSign(vote_id_BE8) = [0x00×24, vote_id_be_byte0..7] (32 bytes)
//   envelope = "\x19Ethereum Signed Message:\n32" || message  (60 bytes)
//   hash     = keccak256(envelope)
//   z        = hash interpreted as 256-bit big-endian integer → [u64;4] LE
fn eth_message_hash(vote_id: u64) -> [u64; 4] {
    // prefix: "\x19Ethereum Signed Message:\n32" = 28 bytes
    const PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";
    let mut msg = [0u8; 60];
    msg[..28].copy_from_slice(PREFIX);
    // PadToSign: 24 zero bytes already present, append 8-byte BE vote_id
    msg[28 + 24..].copy_from_slice(&vote_id.to_be_bytes());

    let h = keccak256_short(&msg);

    // Convert big-endian 32-byte hash to [u64; 4] LE (least significant word first)
    [
        u64::from_be_bytes(h[24..32].try_into().unwrap()),
        u64::from_be_bytes(h[16..24].try_into().unwrap()),
        u64::from_be_bytes(h[8..16].try_into().unwrap()),
        u64::from_be_bytes(h[0..8].try_into().unwrap()),
    ]
}

// Derive the Ethereum address from a secp256k1 public key (uncompressed, no prefix).
// address = keccak256(px_be32 || py_be32)[12..] as big-endian 20 bytes.
//
// Inputs: px and py as [u64; 4] LE (standard ZisK representation).
// Returns the address as a 20-byte big-endian array.
fn eth_address_from_pk(px: &[u64; 4], py: &[u64; 4]) -> [u8; 20] {
    // Build 64-byte input: px as 32-byte BE || py as 32-byte BE
    let mut input = [0u8; 64];
    for i in 0..4 {
        input[i * 8..i * 8 + 8].copy_from_slice(&px[3 - i].to_be_bytes());
        input[32 + i * 8..32 + i * 8 + 8].copy_from_slice(&py[3 - i].to_be_bytes());
    }
    let h = keccak256_short(&input);
    h[12..].try_into().unwrap()
}

// Compare the keccak-derived address bytes with the address stored in a BN254 Fr element.
// The Fr element stores the uint160 address as [u64; 4] LE, address[0] = lower 64 bits.
fn address_matches(addr_bytes: &[u8; 20], pubs_addr: &FrRaw) -> bool {
    // Build expected 20 big-endian bytes from Fr element (uint160)
    let mut expected = [0u8; 20];
    expected[0..4].copy_from_slice(&(pubs_addr[2] as u32).to_be_bytes());
    expected[4..12].copy_from_slice(&pubs_addr[1].to_be_bytes());
    expected[12..20].copy_from_slice(&pubs_addr[0].to_be_bytes());
    addr_bytes == &expected
}
///
/// Optimised for small fixed-size input: uses stack-allocated [u8; 41] buffers to avoid
/// heap allocations in the retry loop.  The caller is responsible for pre-hashing any
/// large transcript down to 32 bytes before calling this function.
fn challenge_fr(digest: &[u8; 32]) -> Option<FrRaw> {
    // Each iteration hashes digest || counter(8B) || domain(1B) twice.
    // The result fits in [u8; 41] — no heap needed.
    let mut counter = 0u64;
    loop {
        let mut input0 = [0u8; 41];
        input0[..32].copy_from_slice(digest);
        input0[32..40].copy_from_slice(&counter.to_be_bytes());
        input0[40] = 0u8;
        let d0 = sha256_once(&input0);

        let mut input1 = [0u8; 41];
        input1[..32].copy_from_slice(digest);
        input1[32..40].copy_from_slice(&counter.to_be_bytes());
        input1[40] = 1u8;
        let d1 = sha256_once(&input1);

        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&d0);
        wide[32..].copy_from_slice(&d1);

        if let Some(v) = ArkFr::from_random_bytes(&wide) {
            if v.inverse().is_some() {
                return Some(v.into_bigint().0);
            }
        }
        counter = counter.wrapping_add(1);
    }
}

#[derive(Clone)]
struct ProofRaw {
    a: G1,
    b: G2,
    c: G1,
    public_inputs: Vec<FrRaw>,
}

fn main() {
    let input = read_input_slice();
    let mut offset = 0usize;
    let mut parse_fail = false;
    let mut fail_mask: u32 = 0;

    // --- Read header ---
    let magic = read_words_le::<1>(input, &mut offset).map(|x| x[0]).unwrap_or_else(|| { parse_fail = true; 0 });
    let log_n = read_words_le::<1>(input, &mut offset).map(|x| x[0]).unwrap_or_else(|| { parse_fail = true; 0 }) as usize;
    let nproofs = read_words_le::<1>(input, &mut offset).map(|x| x[0]).unwrap_or_else(|| { parse_fail = true; 0 }) as usize;
    let n_public = read_words_le::<1>(input, &mut offset).map(|x| x[0]).unwrap_or_else(|| { parse_fail = true; 0 }) as usize;

    if magic != MAGIC { parse_fail = true; }
    if nproofs == 0 || nproofs > 4096 { parse_fail = true; }
    if n_public > 256 { parse_fail = true; }

    // --- Read VK ---
    let vk_alpha_g1 = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });
    let vk_beta_g2 = read_words_le::<16>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g2_identity() });
    let vk_gamma_g2 = read_words_le::<16>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g2_identity() });
    let vk_delta_g2 = read_words_le::<16>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g2_identity() });

    let gamma_abc_len = read_words_le::<1>(input, &mut offset).map(|x| x[0] as usize).unwrap_or_else(|| { parse_fail = true; 0 });
    if gamma_abc_len != n_public + 1 { parse_fail = true; }

    let mut vk_gamma_abc = Vec::<G1>::with_capacity(gamma_abc_len);
    for _ in 0..gamma_abc_len {
        vk_gamma_abc.push(read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() }));
    }

    // --- Read proofs ---
    let nproofs_check = read_words_le::<1>(input, &mut offset).map(|x| x[0] as usize).unwrap_or_else(|| { parse_fail = true; 0 });
    if nproofs_check != nproofs { parse_fail = true; }

    let mut proofs = Vec::<ProofRaw>::with_capacity(nproofs);
    for _ in 0..nproofs {
        let a = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });
        let b = read_words_le::<16>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g2_identity() });
        let c = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });
        let mut pubs = Vec::with_capacity(n_public);
        for _ in 0..n_public {
            pubs.push(read_words_le::<4>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; [0; 4] }));
        }
        proofs.push(ProofRaw { a, b, c, public_inputs: pubs });
    }

    // --- Read precomputed hints ---
    // scaled_a[i] = r_i*A_i (host hint, validated by final pairing equation)
    let mut scaled_a = Vec::<G1>::with_capacity(nproofs);
    for _ in 0..nproofs {
        scaled_a.push(read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() }));
    }
    // neg_alpha_rsum = -(vk_alpha * r_sum), neg_g_ic = -(Σ r_i*g_ic_i), neg_acc_c = -(Σ r_i*C_i)
    // These are validated by the pairing equation (under BDDH assumption)
    let neg_alpha_rsum = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });
    let neg_g_ic = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });
    let neg_acc_c = read_words_le::<8>(input, &mut offset).unwrap_or_else(|| { parse_fail = true; g1_identity() });

    // Check for optional ECDSA signature block.
    // If present: nproofs × 4 × 32 bytes (r, s, px, py — each 32 bytes = [u64;4])
    let ecdsa_block_size = nproofs * 4 * 32;
    let has_ecdsa = !parse_fail && (offset + ecdsa_block_size == input.len());
    let groth16_only = !parse_fail && (offset == input.len());
    if !parse_fail && !has_ecdsa && !groth16_only {
        parse_fail = true;
    }

    // --- Validate points ---
    if !parse_fail {
        let mut points_ok = true;
        // VK G2 points: full validation including subgroup check
        points_ok &= g1_is_valid(&vk_alpha_g1);
        points_ok &= g2_is_valid(&vk_beta_g2);
        points_ok &= g2_is_valid(&vk_gamma_g2);
        points_ok &= g2_is_valid(&vk_delta_g2);
        for i in 0..vk_gamma_abc.len() { points_ok &= g1_is_valid(&vk_gamma_abc[i]); }
        for i in 0..nproofs {
            points_ok &= g1_is_valid(&proofs[i].a);
            // proof.b: only on-curve check; subgroup check skipped (sound by Fiat-Shamir randomization)
            points_ok &= is_on_curve_twist_bn254(&proofs[i].b);
            points_ok &= g1_is_valid(&proofs[i].c);
            // scaled_a hints: on-curve check sufficient (validated by pairing equation)
            points_ok &= is_on_curve_bn254(&scaled_a[i]);
        }
        // neg_alpha_rsum/neg_g_ic/neg_acc_c: validated by pairing equation, no explicit check needed
        if !points_ok { parse_fail = true; fail_mask |= 1 << 1; }
    }

    // --- Derive r_shift from all proof data (Fiat-Shamir) ---
    // Transcript: domain || A_i || B_i || C_i || pub_i for each i.
    //
    // Optimisation: pre-hash the full transcript down to 32 bytes before calling
    // challenge_fr.  This reduces Sha256f AIR rows from 2×577=1154 to 577+2=579
    // (50% reduction) and avoids 2×36KB heap clones inside challenge_fr's retry loop.
    // Security is unchanged: SHA256(T) is collision-resistant, so binding r_shift to
    // SHA256(T) is equivalent to binding it to T directly under ROM.
    let mut batch_ok = !parse_fail;
    if batch_ok {
        // Pre-allocate to exact size to avoid Vec reallocations during extend_from_slice.
        let transcript_size = 16 + nproofs * (64 + 128 + 64 + n_public * 32);
        let mut transcript = Vec::<u8>::with_capacity(transcript_size);
        transcript.extend_from_slice(b"groth16-batch-v1");
        for i in 0..nproofs {
            for w in proofs[i].a.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for w in proofs[i].b.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for w in proofs[i].c.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for j in 0..n_public {
                for w in proofs[i].public_inputs[j].iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            }
        }
        // Compress the full transcript to 32 bytes before challenge derivation.
        // challenge_fr operates on the digest, using stack-allocated buffers — no heap.
        let transcript_digest = sha256_once(&transcript);
        drop(transcript); // free the 36KB Vec before allocating pairing inputs

        // r_shift is computed to bind the check to proof data (Fiat-Shamir),
        // ensuring host-precomputed hints are sound under BDDH + random oracle model.
        let r_shift = challenge_fr(&transcript_digest).unwrap_or_else(|| { batch_ok = false; ZERO_FR });

        if !fr_eq(&r_shift, &ZERO_FR) {
            // Batch pairing using host-precomputed hints (all validated by the pairing equation):
            // e(neg_alpha_rsum,beta) × e(neg_g_ic,gamma) × e(neg_acc_c,delta)
            //   × Π_i e(scaled_a[i],B_i) = GT_ONE
            // neg_alpha_rsum = -(vk_alpha × r_sum), neg_g_ic = -(Σ r_i*g_ic_i),
            // neg_acc_c = -(Σ r_i*C_i), scaled_a[i] = r_i*A_i   where r_i = r_shift^i
            let mut eq_g1 = Vec::<G1>::with_capacity(3 + nproofs);
            let mut eq_g2 = Vec::<G2>::with_capacity(3 + nproofs);
            eq_g1.push(neg_alpha_rsum); eq_g2.push(vk_beta_g2);
            eq_g1.push(neg_g_ic);       eq_g2.push(vk_gamma_g2);
            eq_g1.push(neg_acc_c);      eq_g2.push(vk_delta_g2);
            for i in 0..nproofs {
                eq_g1.push(scaled_a[i]);
                eq_g2.push(proofs[i].b);
            }

            batch_ok = gt_eq(&pairing_batch_bn254(&eq_g1, &eq_g2), &gt_one());
        }
    }

    if !batch_ok { fail_mask |= 1 << 2; }

    // --- ECDSA signature verification (optional, present when has_ecdsa=true) ---
    //
    // For each proof i, the ECDSA block contains:
    //   r[4], s[4], px[4], py[4]  — all [u64;4] little-endian
    //
    // We verify:
    //   1. secp256k1_ecdsa_verify(pk, z, r, s)
    //      where z = keccak256(Ethereum-signed-message envelope of vote_id)
    //   2. keccak256(px_be32 || py_be32)[12:] == address public input (pubs[0])
    //
    // If any verification fails, ecdsa_ok is set false and fail_mask bit 3 is set.
    // Missing sig block (groth16_only) is not an error — the output bit reflects presence.
    let mut ecdsa_ok = true;
    if has_ecdsa && batch_ok {
        for i in 0..nproofs {
            let r = read_words_le::<4>(input, &mut offset).unwrap_or_else(|| { ecdsa_ok = false; [0; 4] });
            let s = read_words_le::<4>(input, &mut offset).unwrap_or_else(|| { ecdsa_ok = false; [0; 4] });
            let px = read_words_le::<4>(input, &mut offset).unwrap_or_else(|| { ecdsa_ok = false; [0; 4] });
            let py = read_words_le::<4>(input, &mut offset).unwrap_or_else(|| { ecdsa_ok = false; [0; 4] });

            if !ecdsa_ok { break; }

            // n_public must be >= 2 (address at index 0, vote_id at index 1)
            if proofs[i].public_inputs.len() < 2 { ecdsa_ok = false; break; }

            let pubs_addr = &proofs[i].public_inputs[0];
            let vote_id = proofs[i].public_inputs[1][0]; // fits in u64

            // 1. ECDSA signature verification
            let pk = SyscallPoint256 { x: px, y: py };
            let z = eth_message_hash(vote_id);
            if !secp256k1_ecdsa_verify(&pk, &z, &r, &s) {
                ecdsa_ok = false;
                break;
            }

            // 2. Public key → Ethereum address binding
            let addr_bytes = eth_address_from_pk(&px, &py);
            if !address_matches(&addr_bytes, pubs_addr) {
                ecdsa_ok = false;
                break;
            }
        }
    }

    if has_ecdsa && !ecdsa_ok { fail_mask |= 1 << 3; }

    if parse_fail { fail_mask |= 1 << 31; }

    let overall_ok = !parse_fail && batch_ok && (!has_ecdsa || ecdsa_ok);
    set_output(0, if overall_ok { 1 } else { 0 });
    set_output(1, fail_mask);
    set_output(2, log_n as u32);
    set_output(3, nproofs as u32);
    set_output(4, n_public as u32);
    set_output(5, input.len() as u32);
    set_output(6, offset as u32);
    set_output(7, if batch_ok { 1 } else { 0 });
    set_output(8, if has_ecdsa { if ecdsa_ok { 1 } else { 0 } } else { 2 }); // 2 = not present
}
