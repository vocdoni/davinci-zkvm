//! Shared crypto primitives for the davinci ZisK guests.
//!
//! Used by both the vote-batch circuit (`circuit/`) and the chain
//! aggregator (`circuit-aggregator/`). Everything here is independent of
//! the guests' input wire formats.

pub mod babyjubjub;
pub mod bls_fr;
pub mod bn254;
pub mod bn254_fr;
pub mod chaum_pedersen;
pub mod hash;
pub mod poseidon;
mod poseidon13_constants;
pub mod results;
pub mod smt;
pub mod types;
