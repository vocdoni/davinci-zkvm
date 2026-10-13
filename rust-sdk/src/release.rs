//! Pinned release values, like go-sdk `chain/release.go`. The program vks
//! change with the guest source (`scripts/build-guests.sh` builds are path
//! independent); `ROOT_C_VADCOP_FINAL` changes with the ZisK snark setup.
//!
//! Refreezing:
//! - `BATCH_PROGRAM_VK` / `RESULTS_PROGRAM_VK`: run
//!   `cargo-zisk setup -e <elf> -k ~/.zisk/provingKey` on the tracked ELF with
//!   an empty `ZISK_CACHE_DIR` (a warm cache skips the print). It prints
//!   `Root hash: [w0, w1, w2, w3]`; the pin is those four u64 words as
//!   big-endian bytes, concatenated. Update go-sdk `CircuitRelease` in the
//!   same change.
//! - `ROOT_C_VADCOP_FINAL`: after a ZisK release or snark setup change, copy
//!   `root_c_vadcop_final` from any PLONK job's `snark.json`
//!   (`GET /jobs/{id}/snark`); every job kind serves the same value.
//! - `ZISK_VERIFIER_CODEHASH`: after a ZisK snark setup change, `forge build`
//!   in davinci-contracts and take the keccak256 of `ZiskVerifier`'s
//!   `deployedBytecode` (it has no immutables, so it equals `eth_getCode`).
//!
//! A host that accepts a snark should compare its `program_vk` and
//! `root_c_vadcop_final` against these pins rather than trust the values the
//! service returns.

/// Vote-batch ELF program vk (`circuit/elf/circuit.elf`), go-sdk
/// `CircuitRelease.BatchVK`. The `program_vk` of every per-batch PLONK.
pub const BATCH_PROGRAM_VK: [u8; 32] = [
    0xa0, 0xad, 0x5c, 0x4c, 0x7e, 0x39, 0xd4, 0xa7, 0x00, 0x79, 0x33, 0x15, 0x81, 0x81, 0x41, 0x8a,
    0x75, 0x2e, 0x6c, 0x15, 0x63, 0xa2, 0x11, 0xaf, 0x84, 0xc5, 0x79, 0x64, 0x0d, 0xb4, 0x35, 0xfa,
];

/// circuit-results ELF program vk (`circuit-results/elf/results.elf`), go-sdk
/// `CircuitRelease.ResultsVK`. Checked on a GPU `/results` job.
pub const RESULTS_PROGRAM_VK: [u8; 32] = [
    0xe6, 0x93, 0x58, 0x94, 0x53, 0xec, 0xae, 0xe6, 0x3e, 0xba, 0x69, 0x7c, 0x48, 0xd4, 0xc5, 0x32,
    0x1a, 0x71, 0x4b, 0xb1, 0x8c, 0x2d, 0x84, 0xa9, 0x74, 0x37, 0xb3, 0xf3, 0x68, 0x57, 0x8f, 0x68,
];

/// VADCOP-final root of the installed ZisK 1.3 snark setup, as served in
/// `root_c_vadcop_final` by every PLONK job (batch, finalize and results).
pub const ROOT_C_VADCOP_FINAL: [u8; 32] = [
    0x05, 0x00, 0x65, 0x17, 0xb6, 0xcc, 0xde, 0x5d, 0xa4, 0xd8, 0x90, 0x58, 0x7b, 0xa6, 0x28, 0x45,
    0xb5, 0xaf, 0x8a, 0x30, 0x7c, 0x00, 0xe8, 0x7d, 0x4b, 0x9d, 0x05, 0x09, 0x9b, 0x16, 0xdc, 0x80,
];

/// keccak256 of the runtime code of davinci-contracts' `ZiskVerifier`, built
/// with its foundry.toml (solc 0.8.28, via-ir).
pub const ZISK_VERIFIER_CODEHASH: [u8; 32] = [
    0x82, 0x38, 0x5a, 0x40, 0x5b, 0x73, 0x01, 0x34, 0x5d, 0x7e, 0x24, 0x60, 0x17, 0x84, 0x6c, 0xa3,
    0x22, 0x8a, 0xae, 0xa3, 0x49, 0xcb, 0x68, 0xb1, 0x16, 0xd7, 0x6e, 0x0e, 0x77, 0x05, 0x65, 0x66,
];

/// The davinci-circom ballot proof verification key the sequencer accepts
/// (davinci-circom `artifacts/ballot_proof_vkey.json`).
pub fn ballot_vk_json() -> &'static str {
    include_str!("../assets/ballot_proof_vkey.json")
}
