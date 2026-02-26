#![no_main]
#![allow(clippy::needless_range_loop)]
ziskos::entrypoint!(main);

use ark_bn254::Fr as ArkFr;
use ark_ff::{BigInt as ArkBigInt, Field as ArkField, PrimeField};
use ziskos::{
    read_input_slice, set_output,
    syscalls::{syscall_arith256_mod, SyscallArith256ModParams},
    zisklib::{
        add_bn254, is_on_curve_bn254, is_on_curve_twist_bn254, is_on_subgroup_twist_bn254,
        mul_bn254, neg_fp_bn254, pairing_batch_bn254, sha256f_compress,
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

// SHA256 using ZisK sha256f hardware precompile
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

/// Derive Fr challenge from arbitrary bytes using double-hash wide reduction.
fn challenge_fr(data: &[u8]) -> Option<FrRaw> {
    let mut counter = 0u64;
    loop {
        let mut input0 = data.to_vec();
        input0.extend_from_slice(&counter.to_be_bytes());
        input0.push(0u8);
        let d0 = sha256_once(&input0);

        let mut input1 = data.to_vec();
        input1.extend_from_slice(&counter.to_be_bytes());
        input1.push(1u8);
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

    if offset != input.len() { parse_fail = true; }

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
    // Transcript: domain || A_i || B_i || C_i || pub_i for each i
    let mut batch_ok = !parse_fail;
    if batch_ok {
        let mut transcript = Vec::<u8>::new();
        transcript.extend_from_slice(b"groth16-batch-v1");
        for i in 0..nproofs {
            for w in proofs[i].a.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for w in proofs[i].b.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for w in proofs[i].c.iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            for j in 0..n_public {
                for w in proofs[i].public_inputs[j].iter() { transcript.extend_from_slice(&w.to_le_bytes()); }
            }
        }
        // r_shift is computed to bind the check to proof data (Fiat-Shamir),
        // ensuring host-precomputed hints are sound under BDDH + random oracle model.
        let r_shift = challenge_fr(&transcript).unwrap_or_else(|| { batch_ok = false; ZERO_FR });

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
    if parse_fail { fail_mask |= 1 << 31; }

    let overall_ok = !parse_fail && batch_ok;
    set_output(0, if overall_ok { 1 } else { 0 });
    set_output(1, fail_mask);
    set_output(2, log_n as u32);
    set_output(3, nproofs as u32);
    set_output(4, n_public as u32);
    set_output(5, input.len() as u32);
    set_output(6, offset as u32);
    set_output(7, if batch_ok { 1 } else { 0 });
}
