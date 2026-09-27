//! Pinned release values, like go-sdk `chain/release.go`. The program vks
//! change with every guest rebuild; `ROOT_C_VADCOP_FINAL` changes with the
//! ZisK snark setup.
//!
//! Refreezing:
//! - `BATCH_PROGRAM_VK` / `RESULTS_PROGRAM_VK`: run
//!   `cargo-zisk setup -e <elf> -k ~/.zisk/provingKey` on the tracked ELF. It
//!   prints `Root hash: [w0, w1, w2, w3]`; the pin is those four u64 words as
//!   big-endian bytes, concatenated. Update go-sdk `CircuitRelease` in the
//!   same change.
//! - `ROOT_C_VADCOP_FINAL`: after a ZisK release or snark setup change, copy
//!   `root_c_vadcop_final` from any PLONK job's `snark.json`
//!   (`GET /jobs/{id}/snark`); every job kind serves the same value.
//!
//! A host that accepts a snark should compare its `program_vk` and
//! `root_c_vadcop_final` against these pins rather than trust the values the
//! service returns.

/// Vote-batch ELF program vk (`circuit/elf/circuit.elf`), go-sdk
/// `CircuitRelease.BatchVK`. The `program_vk` of every per-batch PLONK.
pub const BATCH_PROGRAM_VK: [u8; 32] = [
    0x44, 0xcc, 0xdf, 0x5e, 0xb9, 0xcd, 0xf7, 0x59, 0xd9, 0xca, 0x78, 0x4b, 0x76, 0xc5, 0x06, 0x04,
    0xcc, 0x45, 0x8b, 0x2d, 0x7b, 0x98, 0x61, 0xb4, 0xbc, 0x49, 0x41, 0xdd, 0xf9, 0x61, 0xf8, 0xa7,
];

/// circuit-results ELF program vk (`circuit-results/elf/results.elf`), go-sdk
/// `CircuitRelease.ResultsVK`. Checked on a GPU `/results` job.
pub const RESULTS_PROGRAM_VK: [u8; 32] = [
    0xab, 0x98, 0x76, 0x4a, 0x01, 0x5f, 0x26, 0x85, 0xaa, 0xd1, 0x12, 0xca, 0xfe, 0xe1, 0xc4, 0x72,
    0x1a, 0xda, 0xc0, 0x98, 0xa6, 0xfe, 0x59, 0x89, 0xa4, 0xe8, 0x7b, 0x6b, 0x9e, 0xab, 0x71, 0xfb,
];

/// VADCOP-final root of the installed ZisK 1.3 snark setup, as served in
/// `root_c_vadcop_final` by every PLONK job (batch, finalize and results).
pub const ROOT_C_VADCOP_FINAL: [u8; 32] = [
    0x05, 0x00, 0x65, 0x17, 0xb6, 0xcc, 0xde, 0x5d, 0xa4, 0xd8, 0x90, 0x58, 0x7b, 0xa6, 0x28, 0x45,
    0xb5, 0xaf, 0x8a, 0x30, 0x7c, 0x00, 0xe8, 0x7d, 0x4b, 0x9d, 0x05, 0x09, 0x9b, 0x16, 0xdc, 0x80,
];

/// The davinci-circom ballot proof verification key the sequencer accepts
/// (`../davinci-circom/artifacts/ballot_proof_vkey.json`).
pub fn ballot_vk_json() -> &'static str {
    include_str!("../assets/ballot_proof_vkey.json")
}
