//! Census: the lean-IMT (iden3 Poseidon2) Merkle census, CSP attestations,
//! vote-id signatures and the ballot slot each census position maps to.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::crypto::field::{fr_from_le, fr_to_be, Fr};
use crate::crypto::poseidon::poseidon;
use crate::limits::{BALLOT_MAX, BALLOT_MIN, MAX_CENSUS_DEPTH};
use crate::Error;

fn hash2(a: &Fr, b: &Fr) -> Fr {
    // Two inputs is always a valid Poseidon width.
    poseidon(&[*a, *b]).unwrap_or_default()
}

/// Append-only lean incremental Merkle tree, same shape as `lean-imt-go`:
/// a node without a right sibling is carried up unchanged.
#[derive(Clone, Debug, Default)]
pub struct LeanImt {
    // levels[0] = leaves, last level = [root] once non-empty.
    levels: Vec<Vec<Fr>>,
}

impl LeanImt {
    pub fn new() -> Self {
        LeanImt {
            levels: vec![Vec::new()],
        }
    }

    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn depth(&self) -> usize {
        self.levels.len().saturating_sub(1)
    }

    /// Builds the tree bottom-up with n - 1 hashes; same levels (root and
    /// proofs) as inserting `leaves` one by one.
    pub fn from_leaves(leaves: Vec<Fr>) -> Self {
        let mut levels = vec![leaves];
        while let Some(l) = levels.last().filter(|l| l.len() > 1) {
            // A lone right-most node moves up unhashed.
            let next = l
                .chunks(2)
                .map(|p| match p {
                    [a, b] => hash2(a, b),
                    _ => p[0],
                })
                .collect();
            levels.push(next);
        }
        LeanImt { levels }
    }

    pub fn insert(&mut self, leaf: Fr) {
        if self.levels.is_empty() {
            self.levels.push(Vec::new());
        }
        let size = self.len() + 1;
        // depth = ceil(log2(size))
        let depth = (usize::BITS - (size - 1).leading_zeros()) as usize;
        while self.levels.len() < depth + 1 {
            self.levels.push(Vec::new());
        }
        let mut node = leaf;
        let mut index = size - 1;
        for level in 0..depth {
            set(&mut self.levels[level], index, node);
            if index & 1 == 1 {
                node = hash2(&self.levels[level][index - 1], &node);
            }
            index >>= 1;
        }
        self.levels[depth] = vec![node];
    }

    /// Root; zero for an empty tree.
    pub fn root(&self) -> Fr {
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or_default()
    }

    /// Compact proof: levels where the node has no sibling are skipped.
    pub fn proof(&self, index: usize) -> Result<CensusProof, Error> {
        if index >= self.len() {
            return Err(Error::Census("leaf index out of range"));
        }
        let leaf = self.levels[0][index];
        let mut siblings = Vec::new();
        let mut path_bits = 0u64;
        let mut i = index;
        for level in 0..self.depth() {
            let nodes = &self.levels[level];
            if i & 1 == 1 {
                path_bits |= 1 << siblings.len();
                siblings.push(nodes[i - 1]);
            } else if let Some(s) = nodes.get(i + 1) {
                siblings.push(*s);
            }
            i >>= 1;
        }
        Ok(CensusProof {
            root: self.root(),
            leaf,
            path_bits,
            siblings,
        })
    }
}

fn set(v: &mut Vec<Fr>, i: usize, x: Fr) {
    if i < v.len() {
        v[i] = x;
    } else {
        v.resize(i, Fr::default());
        v.push(x);
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CensusProof {
    pub root: Fr,
    pub leaf: Fr,
    pub path_bits: u64,
    pub siblings: Vec<Fr>,
}

/// Guest rules: at most 61 siblings, no path bit above the sibling count,
/// and the Poseidon2 walk reaches the root.
pub fn verify_census_proof(p: &CensusProof) -> bool {
    let n = p.siblings.len();
    if n > MAX_CENSUS_DEPTH || p.path_bits >> n != 0 {
        return false;
    }
    let mut node = p.leaf;
    for (i, s) in p.siblings.iter().enumerate() {
        node = if (p.path_bits >> i) & 1 == 1 {
            hash2(s, &node)
        } else {
            hash2(&node, s)
        };
    }
    node == p.root
}

/// Merkle census leaf `(address << 88) | weight`, weight below 2^88.
pub fn census_leaf(address: &[u8; 20], weight: u128) -> Result<Fr, Error> {
    if weight >> 88 != 0 {
        return Err(Error::Census("weight does not fit in 88 bits"));
    }
    // 248 bits, always below p.
    let mut be = [0u8; 32];
    be[1..21].copy_from_slice(address);
    be[21..].copy_from_slice(&weight.to_be_bytes()[5..]);
    be.reverse();
    fr_from_le(&be)
}

/// Weight part of a census leaf (its low 88 bits), as the guest binds it.
pub fn census_leaf_weight(leaf: &Fr) -> u128 {
    let be = fr_to_be(leaf);
    let mut w = [0u8; 16];
    w[5..].copy_from_slice(&be[21..]);
    u128::from_be_bytes(w)
}

/// Ballot slot of a Merkle voter: `0x10 + ((1 << n_siblings) | path_bits)`.
pub fn slot_key_merkle(p: &CensusProof) -> Result<u64, Error> {
    let n = p.siblings.len();
    if n > MAX_CENSUS_DEPTH || p.path_bits >> n != 0 {
        return Err(Error::Census("path bits above the proof length"));
    }
    Ok(BALLOT_MIN + ((1u64 << n) | p.path_bits))
}

/// Ballot slot of a CSP voter: `0x10 + index`, which must stay in the ballot
/// namespace (the guest fails the batch otherwise).
pub fn slot_key_csp(index: u64) -> Result<u64, Error> {
    BALLOT_MIN
        .checked_add(index)
        .filter(|k| *k <= BALLOT_MAX)
        .ok_or(Error::Census("CSP index outside the ballot namespace"))
}

/// A CSP attestation: the CSP signed `(pid, address, weight, index)`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct CspProof {
    #[serde(with = "hex::serde")]
    pub r: [u8; 32],
    #[serde(with = "hex::serde")]
    pub s: [u8; 32],
    pub recid: u8,
    #[serde(with = "hex::serde")]
    pub address: [u8; 20],
    pub weight: u128,
    pub index: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CensusWitness {
    Merkle(CensusProof),
    Csp(CspProof),
}

/// secp256k1 signature, `v` = recovery id (0 or 1; 27/28 are accepted on input).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct EcdsaSignature {
    #[serde(with = "hex::serde")]
    pub r: [u8; 32],
    #[serde(with = "hex::serde")]
    pub s: [u8; 32],
    pub v: u8,
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Ethereum personal-sign digest of a message.
fn personal_hash(msg: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg.len());
    keccak(&[prefix.as_bytes(), msg])
}

/// `keccak("\x19Ethereum Signed Message:\n92" || pid_BE32 || address || weight_BE32 || index_BE8)`.
pub fn csp_message_hash(pid: &Fr, address: &[u8; 20], weight: u128, index: u64) -> [u8; 32] {
    let mut payload = [0u8; 92];
    payload[..32].copy_from_slice(&fr_to_be(pid));
    payload[32..52].copy_from_slice(address);
    payload[68..84].copy_from_slice(&weight.to_be_bytes());
    payload[84..].copy_from_slice(&index.to_be_bytes());
    personal_hash(&payload)
}

fn sign_prehash(sk: &SigningKey, hash: &[u8; 32]) -> EcdsaSignature {
    // RFC 6979, low-S (k256 normalizes and flips the recovery id). It only
    // fails for a short prehash or an r/s of zero (probability ~2^-256).
    let (sig, recid) = sk
        .sign_prehash_recoverable(hash)
        .expect("RFC 6979 signing of a 32-byte digest");
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    EcdsaSignature {
        r,
        s,
        v: recid.to_byte(),
    }
}

fn recover_address(hash: &[u8; 32], r: &[u8; 32], s: &[u8; 32], v: u8) -> Result<[u8; 20], Error> {
    let recid = match v {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return Err(Error::Signature("recovery id not in {0, 1, 27, 28}")),
    };
    let sig =
        Signature::from_scalars(*r, *s).map_err(|_| Error::Signature("r or s out of range"))?;
    if sig.normalize_s().is_some() {
        return Err(Error::Signature("high-S signature"));
    }
    let recid = RecoveryId::from_byte(recid).ok_or(Error::Signature("bad recovery id"))?;
    let vk = VerifyingKey::recover_from_prehash(hash, &sig, recid)
        .map_err(|_| Error::Signature("recovery failed"))?;
    Ok(eth_address(&vk))
}

/// Ethereum address of a public key: `keccak(X || Y)[12..]`.
pub fn eth_address(vk: &VerifyingKey) -> [u8; 20] {
    let point = vk.to_encoded_point(false);
    let d = keccak(&[&point.as_bytes()[1..]]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&d[12..]);
    out
}

/// Deterministic CSP attestation.
pub fn csp_sign(
    sk: &SigningKey,
    pid: &Fr,
    address: &[u8; 20],
    weight: u128,
    index: u64,
) -> CspProof {
    let sig = sign_prehash(sk, &csp_message_hash(pid, address, weight, index));
    CspProof {
        r: sig.r,
        s: sig.s,
        recid: sig.v,
        address: *address,
        weight,
        index,
    }
}

/// Address of the CSP that signed `p` (the census root in CSP mode).
pub fn csp_recover(pid: &Fr, p: &CspProof) -> Result<[u8; 20], Error> {
    if p.recid > 1 {
        return Err(Error::Signature("CSP recid must be 0 or 1"));
    }
    let hash = csp_message_hash(pid, &p.address, p.weight, p.index);
    recover_address(&hash, &p.r, &p.s, p.recid)
}

/// Personal-sign digest of a vote id: the message is `PadToSign(BE8(vid))`.
pub fn vote_id_message_hash(vote_id: u64) -> [u8; 32] {
    let mut msg = [0u8; 32];
    msg[24..].copy_from_slice(&vote_id.to_be_bytes());
    personal_hash(&msg)
}

/// The voter's signature over its vote id (deterministic, RFC 6979).
pub fn vote_id_sign(sk: &SigningKey, vote_id: u64) -> EcdsaSignature {
    sign_prehash(sk, &vote_id_message_hash(vote_id))
}

/// Signer address of a vote-id signature. Rejects high-S and `v` outside
/// `{0, 1, 27, 28}`.
pub fn vote_id_recover(vote_id: u64, sig: &EcdsaSignature) -> Result<[u8; 20], Error> {
    recover_address(&vote_id_message_hash(vote_id), &sig.r, &sig.s, sig.v)
}
