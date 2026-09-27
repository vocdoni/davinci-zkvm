//! Guest output registers. `GET /jobs/{id}/publics` serves them as 64 u32 LE
//! (256 bytes); the on-chain `publicValues` carries the same 64 values as
//! u64 LE words (512 bytes). A 256-bit value spans 8 registers whose LE bytes,
//! concatenated, are its LE32 bytes (for a root: the raw arbo digest).

use crate::Error;

/// Registers the batch guest commits (46; the rest are zero padding).
pub const BATCH_REGS: usize = 46;
/// Registers the results guest commits.
pub const RESULTS_REGS: usize = 43;

/// Vote-batch guest publics (circuit/CIRCUIT.md).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchPublics {
    pub ok: bool,
    pub fail_mask: u32,
    pub root_before: [u8; 32],
    pub root_after: [u8; 32],
    pub voters: u32,
    pub overwrites: u32,
    /// LE32 bytes of the census root integer (the contract's `censusRoot`);
    /// for CSP, the CSP address as uint160.
    pub census_root: [u8; 32],
    /// Raw `sha256(com_0 || y_0 || ...)`.
    pub blobs_digest: [u8; 32],
    pub n_blobs: u32,
    pub occupied_before: u32,
    /// Registers 43..45: proof count, public inputs per proof (3) and
    /// `floor(log2(nproofs))`, all predictable from the request.
    pub nproofs: u32,
    pub n_public: u32,
    pub log_n: u32,
}

fn regs_from_u32_view(b: &[u8], min: usize) -> Result<Vec<u32>, Error> {
    if !b.len().is_multiple_of(4) || b.len() / 4 < min {
        return Err(Error::Input(format!(
            "publics: {} bytes, want >= {} u32 registers",
            b.len(),
            min
        )));
    }
    Ok(b.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

// 512-byte publicValues: one u64 LE word per register, upper half zero.
fn regs_from_words(pv: &[u8], min: usize) -> Result<Vec<u32>, Error> {
    if !pv.len().is_multiple_of(8) || pv.len() / 8 < min {
        return Err(Error::Input(format!(
            "publicValues: {} bytes, want >= {} u64 words",
            pv.len(),
            min
        )));
    }
    pv.chunks_exact(8)
        .map(|c| {
            if c[4..] != [0, 0, 0, 0] {
                return Err(Error::Input("publicValues word above 32 bits".into()));
            }
            Ok(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        })
        .collect()
}

fn bytes32(regs: &[u32], base: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, r) in regs[base..base + 8].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&r.to_le_bytes());
    }
    out
}

impl BatchPublics {
    /// From the u32 register view (`publics.bin`, 256 bytes).
    pub fn parse(regs: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_regs(&regs_from_u32_view(regs, BATCH_REGS)?))
    }

    /// From the 512-byte on-chain `publicValues`.
    pub fn from_public_values(pv: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_regs(&regs_from_words(pv, BATCH_REGS)?))
    }

    fn from_regs(r: &[u32]) -> Self {
        BatchPublics {
            ok: r[0] == 1,
            fail_mask: r[1],
            root_before: bytes32(r, 2),
            root_after: bytes32(r, 10),
            voters: r[18],
            overwrites: r[19],
            census_root: bytes32(r, 20),
            blobs_digest: bytes32(r, 28),
            n_blobs: r[36],
            occupied_before: r[42],
            nproofs: r[43],
            n_public: r[44],
            log_n: r[45],
        }
    }

    /// What a settlement needs: `ok == 1` and an empty fail mask.
    pub fn passed(&self) -> bool {
        self.ok && self.fail_mask == 0
    }
}

/// circuit-results publics (circuit-results/RESULTS.md §3).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ResultsPublics {
    pub ok: bool,
    pub fail_mask: u32,
    /// Raw arbo root digest.
    pub state_root: [u8; 32],
    pub results: [u64; 16],
    /// First failing CP index, `u32::MAX` if none.
    pub cp_fail_index: u32,
}

impl ResultsPublics {
    pub fn parse(regs: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_regs(&regs_from_u32_view(regs, RESULTS_REGS)?))
    }

    pub fn from_public_values(pv: &[u8]) -> Result<Self, Error> {
        Ok(Self::from_regs(&regs_from_words(pv, RESULTS_REGS)?))
    }

    fn from_regs(r: &[u32]) -> Self {
        let mut results = [0u64; 16];
        for (i, v) in results.iter_mut().enumerate() {
            *v = r[10 + 2 * i] as u64 | (r[11 + 2 * i] as u64) << 32;
        }
        ResultsPublics {
            ok: r[0] == 1,
            fail_mask: r[1],
            state_root: bytes32(r, 2),
            results,
            cp_fail_index: r[42],
        }
    }

    pub fn passed(&self) -> bool {
        self.ok && self.fail_mask == 0
    }
}

const BATCH_FAIL_BITS: [(u32, &str); 19] = [
    (1, "groth16_curve"),
    (2, "pairing"),
    (3, "ecdsa"),
    (10, "smt_voteid"),
    (11, "smt_ballot"),
    (12, "smt_results"),
    (13, "smt_process"),
    (14, "consistency"),
    (15, "ballot_ns"),
    (16, "census"),
    (17, "reencryption"),
    (18, "kzg"),
    (19, "missing_block"),
    (20, "result_accum"),
    (21, "leaf_hash"),
    (22, "binding"),
    (23, "csp"),
    (24, "refresh"),
    (31, "parse_error"),
];

const RESULTS_FAIL_BITS: [(u32, &str); 6] = [
    (0, "parse"),
    (1, "key"),
    (2, "incl_key"),
    (3, "incl_results"),
    (4, "cp"),
    (5, "range"),
];

fn names(mask: u32, table: &[(u32, &'static str)]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = table
        .iter()
        .filter(|(bit, _)| mask >> bit & 1 == 1)
        .map(|(_, n)| *n)
        .collect();
    let known = table.iter().fold(0u32, |m, (bit, _)| m | 1 << bit);
    if mask & !known != 0 {
        out.push("unknown");
    }
    out
}

/// Names of the batch guest's fail-mask bits (go-sdk `FailString` names).
pub fn fail_bits(mask: u32) -> Vec<&'static str> {
    names(mask, &BATCH_FAIL_BITS)
}

/// Names of the results guest's fail-mask bits.
pub fn results_fail_bits(mask: u32) -> Vec<&'static str> {
    names(mask, &RESULTS_FAIL_BITS)
}
