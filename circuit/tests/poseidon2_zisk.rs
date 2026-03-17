use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_symmetric::Permutation;
use ziskos::syscalls::syscall_poseidon2;

fn zisk_syscall_poseidon2(mut input: [Goldilocks; 16]) -> [Goldilocks; 16] {
    let mut state = input.map(|x| x.as_canonical_u64());
    unsafe {
        syscall_poseidon2(&mut state as *mut [u64; 16]);
    }
    for (dst, src) in input.iter_mut().zip(state) {
        *dst = Goldilocks::from_u64(src);
    }
    input
}

#[test]
fn width16_poseidon2_matches_zisk_syscall_on_zero_state() {
    let perm = davinci_stark::config::Perm::new_from_rng_128(
        &mut davinci_stark::config::DeterministicRng(42),
    );
    let input = [Goldilocks::ZERO; 16];
    let expected = perm.permute(input);
    let actual = zisk_syscall_poseidon2(input);
    assert_eq!(actual, expected);
}

#[test]
fn width16_poseidon2_matches_zisk_syscall_on_deterministic_vector() {
    let perm = davinci_stark::config::Perm::new_from_rng_128(
        &mut davinci_stark::config::DeterministicRng(42),
    );
    let input = core::array::from_fn(|i| Goldilocks::from_u64((i as u64) * 17 + 3));
    let expected = perm.permute(input);
    let actual = zisk_syscall_poseidon2(input);
    assert_eq!(actual, expected);
}

#[test]
fn upstream_plonky3_width16_differs_from_zisk_syscall() {
    let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(
        &mut davinci_stark::config::DeterministicRng(42),
    );
    let input = [Goldilocks::ZERO; 16];
    let upstream = perm.permute(input);
    let zisk = zisk_syscall_poseidon2(input);
    assert_ne!(upstream, zisk);
}
