//! Rust SDK for the davinci-zkvm prover: the HTTP client, the wire formats the
//! service accepts and the DAVINCI protocol primitives a host needs to build
//! them byte-exactly.
#![forbid(unsafe_code)]

pub mod ballot;
pub mod blob;
pub mod census;
pub mod client;
pub mod crypto;
mod error;
pub mod groth16;
pub mod limits;
pub mod publics;
pub mod reenc;
pub mod release;
pub mod results;
pub mod types;

pub use error::Error;
