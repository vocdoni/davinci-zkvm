# DAVINCI zkVM Circuit — Formal Specification

This document describes every constraint checked by the DAVINCI zkVM circuit,
how inputs and outputs relate to those constraints, and the security properties
they guarantee. It mirrors the Rust source code in `circuit/src/` and should be
updated whenever the circuit logic changes.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Input Format](#2-input-format)
3. [Output Registers](#3-output-registers)
4. [Phase 1: Ballot Proof Verification](#4-phase-1-ballot-proof-verification)
5. [Phase 2: Authentication](#5-phase-2-authentication)
6. [Phase 3: Eligibility](#6-phase-3-eligibility)
7. [Phase 4: State Transition](#7-phase-4-state-transition)
8. [Phase 5: Data Availability](#8-phase-5-data-availability)
9. [Phase 6: Cross-Block Binding](#9-phase-6-cross-block-binding)
10. [Final Verdict](#10-final-verdict)
11. [Fail-Mask Reference](#11-fail-mask-reference)
12. [Security Properties](#12-security-properties)
13. [Known Limitations](#13-known-limitations)
14. [Cryptographic Primitives](#14-cryptographic-primitives)

---

## 1. Architecture Overview

The DAVINCI zkVM circuit is a single RISC-V program (compiled for `riscv64ima-zisk-zkvm`)
that replaces three Gnark circuits (VoteVerifier + Aggregator + StateTransition) with one
unified verifier. It runs inside the ZisK zkVM and produces a STARK proof attesting that
all protocol constraints hold for a given batch of votes.

```
┌─────────────────────────────────────────────────────────────┐
│                     ZisK Guest Circuit                       │
│                                                              │
│  Binary Input ──→ Parse ──→ Phase 1 (Groth16 Batch)         │
│                         ├──→ Phase 2 (ECDSA Auth)            │
│                         ├──→ Phase 3 (Census Eligibility)    │
│                         ├──→ Phase 4 (State Transition)      │
│                         │     ├─ 4.1 Consistency             │
│                         │     ├─ 4.2 SMT Chains              │
│                         │     ├─ 4.3 Re-encryption           │
│                         │     └─ 4.4 Result Accumulator      │
│                         ├──→ Phase 5 (KZG Data Availability) │
│                         └──→ Phase 6 (Cross-Block Binding)   │
│                                                              │
│  ──→ Final Verdict ──→ 46 Output Registers                   │
└─────────────────────────────────────────────────────────────┘
```

**All six phases are mandatory.** If any block is absent from the input, the
circuit sets `FAIL_MISSING_BLOCK` and the overall verdict is FAIL.

---

## 2. Input Format

The circuit reads a single binary blob from the ZisK input tape. The blob is
structured as a sequence of typed blocks, each identified by an 8-byte
little-endian ASCII magic number.

### Block ordering (required)

| Order | Magic        | Module    | Content                                  |
|-------|-------------|-----------|------------------------------------------|
| 1     | `GROTH16B`  | `io.rs`   | Header + VK + Proofs + Hints + ECDSA     |
| 2     | `STATETX!`  | `io.rs`   | Full state-transition data               |
| 3     | `CENSUS!!`  | `io.rs`   | Census lean-IMT Poseidon proofs          |
| 4     | `REENCBLK`  | `io.rs`   | Re-encryption entries + public key       |
| 5     | `KZGBLK!!`  | `io.rs`   | KZG blob + evaluation claim              |

### Groth16 Header

```
offset  size   field
──────  ────   ─────
0       8      magic ("GROTH16B" LE)
8       8      nproofs (u64, total batch size including padding)
16      8      n_public (u64, public inputs per proof)
24      8      log_n (u64, log₂ of nproofs)
```

### STATETX Block

```
offset  size   field
──────  ────   ─────
0       8      magic ("STATETX!" LE)
8       8      n_voters (u64, real votes in batch)
16      8      n_overwritten (u64, votes that replaced an existing ballot)
24      8      n_levels (u64, SMT tree depth)
32      32     process_id (FrRaw LE, arbo hex)
64      32     old_state_root (FrRaw LE)
96      32     new_state_root (FrRaw LE)
128     ...    VoteID chain (n_voters entries)
...     ...    Ballot chain (n_voters entries)
...     ...    ResultsAdd transition (optional)
...     ...    ResultsSub transition (optional)
...     ...    Process config proofs (4 entries)
...     ...    Ballot proof data (voter ballots, overwritten ballots, old results)
```

Each SMT transition entry is:

```
old_root[32] new_root[32] old_key[32] old_value[32]
is_old0[1]   new_key[32]  new_value[32]
fnc0[1]      fnc1[1]
siblings[n_levels × 32]
```

---

## 3. Output Registers

The circuit writes 46 `u32` output registers. Registers 0–27 are the **public
outputs** that correspond to the davinci-node `StateTransitionBatchProofInputs`
and are verified on-chain.

```
Register    Name                    Encoding
────────    ────                    ────────
[0]         overall_ok              1 = all checks passed, 0 = at least one failed
[1]         fail_mask               per-check failure bits (see §11)

[2..9]      RootHashBefore          256-bit FrRaw → 8 × u32 LE
[10..17]    RootHashAfter           256-bit FrRaw → 8 × u32 LE
[18]        VotersCount             number of real (non-dummy) votes
[19]        OverwrittenVotesCount   number of ballots that replaced existing ones

[20..27]    CensusRoot              256-bit FrRaw → 8 × u32 LE

[28..31]    BlobCommitment limb 0   128-bit (4 × u32 LE)
[32..35]    BlobCommitment limb 1   128-bit (4 × u32 LE)
[36..39]    BlobCommitment limb 2   128-bit (4 × u32 LE)

[40]        batch_ok                Groth16 batch verification passed
[41]        ecdsa_ok                ECDSA batch verification passed
[42]        (reserved)              —
[43]        nproofs                 number of Groth16 proofs
[44]        n_public                public inputs per proof
[45]        log_n                   log₂(nproofs)
```

**FrRaw → u32 encoding:** A `FrRaw = [u64; 4]` LE value occupies 8 output
registers. For limb `i` (0–3): `reg[base + 2i] = limb[i] & 0xFFFFFFFF`,
`reg[base + 2i + 1] = limb[i] >> 32`.

---

## 4. Phase 1: Ballot Proof Verification

**Module:** `groth16.rs`  
**Fail bits:** `FAIL_CURVE` (bit 1), `FAIL_PAIRING` (bit 2)

### Purpose

Verify that each voter correctly encrypted their ballot using the election's
public key. The ballot proof is a Groth16 BN254 zero-knowledge proof generated
by the Circom `BallotCircuit`. Up to 128 proofs are verified in a single batch
using Fiat-Shamir randomization.

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 1.1 | VK points (α, β, γ, δ, γ_abc[]) are on the BN254 curve and in the correct subgroup | FAIL_CURVE |
| 1.2 | Each proof point A_i is on BN254 G1 and in the prime-order subgroup | FAIL_CURVE |
| 1.3 | Each proof point B_i is on the BN254 G2 twist curve | FAIL_CURVE |
| 1.4 | Each proof point C_i is on BN254 G1 and in the prime-order subgroup | FAIL_CURVE |
| 1.5 | Host hint points (neg_alpha_rsum, neg_g_ic, neg_acc_c, scaled_a[]) are on curve | FAIL_CURVE |
| 1.6 | Fiat-Shamir challenge `r_shift ≠ 0` (derived from SHA-256 of full proof transcript) | FAIL_PAIRING |
| 1.7 | Batch pairing equation holds: `e(-α·r_sum, β) · e(-Σ r_i·g_ic_i, γ) · e(-Σ r_i·C_i, δ) · Π e(r_i·A_i, B_i) = 1_GT` | FAIL_PAIRING |

### Fiat-Shamir transcript

```
"groth16-batch-v1" ‖ A_0 ‖ B_0 ‖ C_0 ‖ pubs_0 ‖ A_1 ‖ B_1 ‖ C_1 ‖ pubs_1 ‖ ...
```

All curve points and field elements are serialized as their `[u64; N]` LE limbs.
The transcript is first hashed to 32 bytes with SHA-256, then processed by
`challenge_fr()` which applies double-SHA-256 wide reduction with a counter
until a non-zero BN254 Fr element is obtained.

### Security rationale

The host provides pre-computed aggregation hints (scaled points). These hints
are **not trusted** — their correctness is enforced by the pairing equation
itself. If the host provides incorrect hints, the pairing equation fails.
The Fiat-Shamir challenge binds the random linear combination to the specific
proof transcript, preventing the host from crafting valid hints for invalid proofs.

---

## 5. Phase 2: Authentication

**Module:** `ecdsa.rs`  
**Fail bits:** `FAIL_ECDSA` (bit 3)

### Purpose

Verify that each voter controls the private key corresponding to their declared
Ethereum address. The authentication binds voter identity to the specific ballot
they submitted.

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 2.1 | ECDSA block is present (non-empty) | FAIL_ECDSA |
| 2.2 | At least 2 public inputs per proof (address, voteID) | FAIL_ECDSA |
| 2.3 | ECDSA entry count == proof count | FAIL_ECDSA |
| 2.4 | VoteID upper limbs are zero (`pubs[1][1..3] == 0`); voteID is uint64 | FAIL_ECDSA |
| 2.5 | `secp256k1_ecdsa_verify(pk, z, r, s)` where `z = keccak256(ethSignedMessage(voteID))` | FAIL_ECDSA |
| 2.6 | Ethereum address derived from pk matches `pubs[0]`: `keccak256(pk.x ‖ pk.y)[12..] == address` | FAIL_ECDSA |

### Signature scheme

```
message   = PadToSign(vote_id_BE8)                         // 32 bytes: 24×0x00 ‖ vote_id_BE8
envelope  = "\x19Ethereum Signed Message:\n32" ‖ message   // 60 bytes
z         = keccak256(envelope)                             // 256-bit hash
```

This matches `davinci-node/crypto/signatures/ethereum.Sign()`.

### Extensibility

The authentication method is currently hardcoded to secp256k1 ECDSA. The
architecture supports future extension to RSA, BLS, EdDSA, or other schemes,
selected by a process configuration parameter (similar to `censusOrigin`).

---

## 6. Phase 3: Eligibility

**Module:** `census.rs`  
**Fail bits:** `FAIL_CENSUS` (bit 16), `FAIL_MISSING_BLOCK` (bit 19)

### Purpose

Verify that each voter is authorized to participate in the election by proving
membership in the census tree. The census is a lean incremental Merkle tree
(lean-IMT) using iden3 Poseidon over BN254.

### Census leaf encoding

```
leaf = PackAddressWeight(address, weight) = (address << 88) | weight
```

Where `address` is the 160-bit Ethereum address and `weight` is the voter's
weight (up to 88 bits). The leaf is stored as a BN254 Fr element.

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 3.1 | Census block is present (non-empty) | FAIL_MISSING_BLOCK |
| 3.2 | All proofs reference the **same census root** | FAIL_CENSUS |
| 3.3 | No duplicate leaves across all proofs in the batch | FAIL_CENSUS |
| 3.4 | Each proof's Merkle path is valid: recomputed root matches declared root | FAIL_CENSUS |

### Merkle path verification

For each proof `(root, leaf, index, siblings[])`:

```
node ← leaf
for i in 0..siblings.len():
    if (index >> i) & 1 == 1:
        node ← poseidon2(siblings[i], node)    // node is right child
    else:
        node ← poseidon2(node, siblings[i])    // node is left child
assert node == root
```

### Extensibility

The eligibility method is currently lean-IMT Poseidon. Future census mechanisms
(e.g., CSP blind signatures, ZK-credential proofs) will be selected by the
`censusOrigin` process config parameter (key 0x06).

---

## 7. Phase 4: State Transition

Phase 4 is the core of the DAVINCI protocol. It verifies that the batch of
votes is correctly recorded in the election state tree (Arbo SHA-256 SMT) and
that the election tally is properly maintained.

### 4.1 Consistency Checks

**Module:** `consistency.rs`  
**Fail bits:** `FAIL_CONSISTENCY` (bit 14), `FAIL_BALLOT_NS` (bit 15)

These checks ensure that the SMT keys fall in the correct namespace and that
the ballot/voteID data is bound to the corresponding ballot proof.

| # | Check | Fails on |
|---|-------|----------|
| 4.1.1 | STATETX block is present | FAIL_MISSING_BLOCK |
| 4.1.2 | Each `vote_id_chain[i].new_key[0] ≥ 0x8000_0000_0000_0000` (VoteID namespace) | FAIL_CONSISTENCY |
| 4.1.3 | Each `vote_id_chain[i].new_key[0] == proofs[i].public_inputs[1][0]` (VoteID binding) | FAIL_CONSISTENCY |
| 4.1.4 | VoteID public input upper limbs zero: `pubs[1][1..3] == 0` | FAIL_CONSISTENCY |
| 4.1.5 | Each `ballot_chain[i].new_key[0] ∈ [0x10, 0x7FFF_FFFF_FFFF_FFFF]` (Ballot namespace) | FAIL_BALLOT_NS |
| 4.1.6 | `(ballot_key - 0x10) & 0xFFFF == proofs[i].public_inputs[0][0] & 0xFFFF` (address lo16) | FAIL_BALLOT_NS |

**Key namespace layout:**

```
0x00 .. 0x0F    Process config keys (reserved)
0x10 .. 0x7FFF...  Ballot keys:  BallotMin + (censusIdx << 16) + (addr & 0xFFFF)
0x8000... .. 0xFFFF...  VoteID keys: unique per ballot proof
```

### 4.2 SMT Chain Verification

**Module:** `smt.rs`  
**Fail bits:** `FAIL_SMT_VOTEID` (bit 10), `FAIL_SMT_BALLOT` (bit 11),
`FAIL_SMT_RESULTS` (bit 12), `FAIL_SMT_PROCESS` (bit 13)

The state tree evolves through a chain of SMT transitions. The circuit verifies
each transition independently (Merkle proof validity) and that transitions chain
correctly (each `new_root` feeds the next `old_root`).

```
                    ┌──────────────┐
OldStateRoot ─────→ │ VoteID Chain │ ────→ (intermediate root)
                    │  [0..n_voters]│
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Ballot Chain │ ────→ (intermediate root)
                    │  [0..n_voters]│
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ ResultsAdd   │ ────→ (intermediate root)
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ ResultsSub   │ ────→ NewStateRoot
                    └──────────────┘
```

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 4.2.1 | `vote_id_chain.len() == n_voters` | FAIL_SMT_VOTEID |
| 4.2.2 | `ballot_chain.len() == n_voters` | FAIL_SMT_BALLOT |
| 4.2.3 | Actual UPDATE count in ballot chain == `n_overwritten` | FAIL_SMT_BALLOT |
| 4.2.4 | Every VoteID transition is INSERT (`fnc0=true, fnc1=false`) | FAIL_SMT_VOTEID |
| 4.2.5 | Every Ballot transition is INSERT or UPDATE (no DELETE, no NOOP) | FAIL_SMT_BALLOT |
| 4.2.6 | VoteID chain: `chain[0].old_root == OldStateRoot` | FAIL_SMT_VOTEID |
| 4.2.7 | VoteID chain: each `chain[i].new_root == chain[i+1].old_root` | FAIL_SMT_VOTEID |
| 4.2.8 | VoteID chain: last `new_root == ballot_chain[0].old_root` | FAIL_SMT_VOTEID |
| 4.2.9 | Ballot chain chaining (same as VoteID) | FAIL_SMT_BALLOT |
| 4.2.10 | Each SMT transition is valid (Merkle proof against old root, new root recomputation) | Various |
| 4.2.11 | ResultsAdd transition valid and chains from end of ballot chain | FAIL_SMT_RESULTS |
| 4.2.12 | ResultsSub transition valid and chains to NewStateRoot | FAIL_SMT_RESULTS |

#### SMT Transition Verification (Circomlib SMT Processor)

For each individual transition, the circuit implements the Circomlib `Processor`
logic that supports INSERT, UPDATE, DELETE, and NOOP operations:

```
Given: (old_root, new_root, old_key, old_value, is_old0, new_key, new_value,
        fnc0, fnc1, siblings[n_levels])

Compute:
  old_leaf = leaf_hash(old_key, old_value)    if !is_old0
  new_leaf = leaf_hash(new_key, new_value)

  For INSERT (fnc0=true, fnc1=false):
    - Verify old_root from (old_leaf or empty slot, siblings, old_key path)
    - Verify new_root from (new_leaf, siblings, new_key path)
    - If !is_old0: the displaced old leaf must be re-inserted at its correct position

  For UPDATE (fnc0=false, fnc1=true):
    - old_key == new_key (updating same slot)
    - Verify old_root from (old_leaf, siblings, old_key path)
    - Verify new_root from (new_leaf, siblings, new_key path)

  For NOOP / read (fnc0=false, fnc1=false):
    - old_root == new_root
    - Verify Merkle inclusion of (new_key, new_value) in old_root
```

**Hash functions (Arbo SHA-256 compatible):**

```
leaf_hash(key, value) = SHA-256(key_LE32 ‖ value_LE32 ‖ 0x01)    // 65 bytes
node_hash(left, right) = SHA-256(left_LE32 ‖ right_LE32)          // 64 bytes
```

All byte arrays use **little-endian** encoding (Arbo's `BigIntToBytes` convention).

#### Process Config Read-Proofs

| # | Check | Fails on |
|---|-------|----------|
| 4.2.P1 | Exactly 4 process proofs | FAIL_SMT_PROCESS |
| 4.2.P2 | Each proof: `old_root == new_root == OldStateRoot` (read-only) | FAIL_SMT_PROCESS |
| 4.2.P3 | Each proof is a valid SMT transition (NOOP) | FAIL_SMT_PROCESS |
| 4.2.P4 | Key order: `[0x00, 0x02, 0x03, 0x06]` (ProcessID, BallotMode, EncryptionKey, CensusOrigin) | FAIL_SMT_PROCESS |
| 4.2.P5 | `process_proofs[0].new_value == state.process_id` (ProcessID matches header) | FAIL_SMT_PROCESS |

### 4.3 Re-encryption Verification

**Module:** `babyjubjub.rs`  
**Fail bits:** `FAIL_REENC` (bit 17), `FAIL_MISSING_BLOCK` (bit 19)

Verifies that each voter's ballot was correctly re-encrypted before storage,
ensuring vote privacy (unlinkability between voter and stored ballot) while
preserving the homomorphic structure needed for tallying.

#### Algorithm

For each voter, the re-encryption uses a deterministic key derived via Poseidon:

```
k'  = poseidon1(k)                          // derive re-encryption scalar
δ₁  = k' · B8                               // delta for C1 (BabyJubJub generator)
δ₂  = k' · pubKey                           // delta for C2 (election public key)

For each ciphertext i in [0..8):
  newC1[i] = origC1[i] + δ₁                 // twisted Edwards point addition
  newC2[i] = origC2[i] + δ₂
```

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 4.3.1 | Re-encryption block is present (public key exists) | FAIL_MISSING_BLOCK |
| 4.3.2 | Public key `(x, y)` satisfies BabyJubJub curve equation: `a·x² + y² = 1 + d·x²·y²` | FAIL_REENC |
| 4.3.3 | `original.len() == reencrypted.len()` per entry | FAIL_REENC |
| 4.3.4 | For each of the 8 ciphertexts: `newC1 == origC1 + k'·B8` and `newC2 == origC2 + k'·pubKey` | FAIL_REENC |

**BabyJubJub parameters (iden3 standard):**

```
a     = 168700
d     = 168696
B8.x  = 5299619240641551281634865583518297030282874472190772894086521144482721001553
B8.y  = 16950150798460657717958625567821834550301663161624707787222815936182638968203
```

### 4.4 Result Accumulator

**Module:** `results.rs`  
**Fail bits:** `FAIL_RESULT_ACCUM` (bit 20), `FAIL_LEAF_HASH` (bit 21)

Verifies the homomorphic ballot tally and binds re-encrypted ballot data to
the state tree.

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 4.4.1 | `voter_ballots.len() == ballot_chain.len()` | FAIL_LEAF_HASH |
| 4.4.2 | For each voter: `SHA-256(serialize(voter_ballots[i])) == ballot_chain[i].new_value` | FAIL_LEAF_HASH |
| 4.4.3 | For each UPDATE: `SHA-256(serialize(overwritten_ballots[j])) == ballot_chain[k].old_value` | FAIL_LEAF_HASH |
| 4.4.4 | `overwritten_ballots.len() == count of UPDATE entries in ballot_chain` | FAIL_LEAF_HASH |
| 4.4.5 | ResultsAdd: `SHA-256(serialize(OldResultsAdd + Σ voter_ballots)) == results_add.new_value` | FAIL_RESULT_ACCUM |
| 4.4.6 | ResultsAdd: `SHA-256(serialize(OldResultsAdd)) == results_add.old_value` | FAIL_RESULT_ACCUM |
| 4.4.7 | ResultsSub: `SHA-256(serialize(OldResultsSub + Σ overwritten_ballots)) == results_sub.new_value` | FAIL_RESULT_ACCUM |
| 4.4.8 | ResultsSub: `SHA-256(serialize(OldResultsSub)) == results_sub.old_value` | FAIL_RESULT_ACCUM |
| 4.4.9 | If `voter_ballots` is non-empty, ResultsAdd transition must be present | FAIL_RESULT_ACCUM |
| 4.4.10 | If `overwritten_ballots` is non-empty, ResultsSub transition must be present | FAIL_RESULT_ACCUM |
| 4.4.11 | If `n_voters > 0`, voter ballot data must be present | FAIL_RESULT_ACCUM |

**Ballot serialization:** Each ballot is 32 BN254 Fr elements (8 ElGamal ciphertexts × 4
coordinates). Each Fr element is serialized as 32 big-endian bytes. The full serialization
is `32 × 32 = 1024 bytes`.

**Homomorphic addition:** `(a + b)[i] = bn254_fr::add(a[i], b[i])` for all 32 elements.

---

## 8. Phase 5: Data Availability

**Module:** `kzg.rs`  
**Fail bits:** `FAIL_KZG` (bit 18), `FAIL_MISSING_BLOCK` (bit 19)

### Purpose

Verify the EIP-4844 KZG blob commitment. The blob contains the complete vote
data for on-chain data availability. The circuit verifies the barycentric
polynomial evaluation `Y = P(Z)`.

### Evaluation point derivation

```
preimage = processID_BE32 ‖ rootHashBefore_BE32 ‖ commitment_48bytes    // 112 bytes
Z = SHA-256(preimage) mod p_bls                                         // BLS12-381 Fr
```

This binds the evaluation point to the specific election and state transition,
preventing replay of blob commitments across different contexts.

### Barycentric evaluation formula

```
ωᵢ = generator^(bit_reverse(i))   for i ∈ [0, 4096)    // 4096 roots of unity
dᵢ = blob[i]                      (interpreted as BLS12-381 Fr)

Y = (Z^N - 1) / N · Σᵢ (dᵢ · ωᵢ / (Z - ωᵢ))
```

Where `N = 4096` and `ω` is a primitive 4096th root of unity in BLS12-381 Fr.

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 5.1 | KZG block is present | FAIL_MISSING_BLOCK |
| 5.2 | Barycentric evaluation matches claimed Y: `eval(blob, Z) == y_claimed` | FAIL_KZG |

### Performance note

All BLS12-381 Fr operations use the ZisK `arith256_mod` precompile. The evaluation
requires approximately 28,000 precompile calls (dominated by the 4096-entry
batch inverse and barycentric sum).

---

## 9. Phase 6: Cross-Block Binding

**Module:** `main.rs` (Phase 6 section)  
**Fail bits:** `FAIL_BINDING` (bit 22)

### Purpose

The input contains independently-parsed binary blocks (STATETX, KZGBLK,
REENCBLK, CENSUS, Groth16). Each block carries its own copy of shared values.
An attacker could provide a valid KZG commitment for a *different* election or a
*different* state root if these copies are not cross-checked. This phase
enforces that all blocks agree on the same context and that per-voter data is
correctly bound across blocks.

### Constraint checks

| # | Check | Description | Fails on |
|---|-------|-------------|----------|
| 6.1 | `kzg.process_id == state.process_id` | KZG blob bound to correct election | FAIL_BINDING |
| 6.2 | `kzg.root_hash_before == state.old_state_root` | KZG blob bound to correct state | FAIL_BINDING |
| 6.3 | `SHA-256(reenc_pubkey_X_BE32 ‖ reenc_pubkey_Y_BE32) == process_proofs[2].new_value` | Re-encryption key matches process config (key 0x03) | FAIL_BINDING |
| 6.4 | `census_proofs.len() == state.n_voters` | One census proof per voter | FAIL_BINDING |
| 6.5 | `reenc_entries.len() == state.n_voters` | One re-encryption entry per voter | FAIL_BINDING |
| 6.6 | For each voter `i`: address extracted from `census_proofs[i].leaf` matches `proofs[i].public_inputs[0]` | Census proof bound to the specific voter | FAIL_BINDING |

### Census address extraction

The census leaf is `(address << 88) | weight`. The address is extracted by
right-shifting 88 bits:

```rust
addr[0] = (leaf[1] >> 24) | (leaf[2] << 40)   // bits 88..152 → bits 0..64
addr[1] = (leaf[2] >> 24) | (leaf[3] << 40)   // bits 152..216 → bits 64..128
addr[2] = leaf[3] >> 24                         // bits 216..248 → bits 128..160
addr[3] = 0
```

The comparison uses the lower 160 bits (3 limbs, masked at limb[2]).

---

## 10. Final Verdict

```rust
overall_ok = fail_mask == 0
    && batch_ok        // Phase 1
    && auth_ok         // Phase 2
    && eligibility_ok  // Phase 3
    && consistency_ok  // Phase 4.1
    && state_ok        // Phase 4.2
    && reenc_ok        // Phase 4.3
    && results_ok      // Phase 4.4
    && kzg_ok          // Phase 5
    && binding_ok      // Phase 6
```

**All phases must pass** for `overall_ok = 1`. The `fail_mask` provides granular
failure information for debugging. A proof with `overall_ok = 0` is invalid and
must be rejected by the verifier.

---

## 11. Fail-Mask Reference

| Bit | Constant | Module | Meaning |
|-----|----------|--------|---------|
| 1 | `FAIL_CURVE` | groth16.rs | Proof/VK point not on curve or not in subgroup |
| 2 | `FAIL_PAIRING` | groth16.rs | Batch pairing equation failed |
| 3 | `FAIL_ECDSA` | ecdsa.rs | Signature invalid or address binding failed |
| 10 | `FAIL_SMT_VOTEID` | smt.rs | VoteID insertion chain invalid |
| 11 | `FAIL_SMT_BALLOT` | smt.rs | Ballot insertion/update chain invalid |
| 12 | `FAIL_SMT_RESULTS` | smt.rs | ResultsAdd/Sub SMT transition invalid |
| 13 | `FAIL_SMT_PROCESS` | smt.rs | Process config read-proof invalid or missing |
| 14 | `FAIL_CONSISTENCY` | consistency.rs | VoteID namespace or proof binding mismatch |
| 15 | `FAIL_BALLOT_NS` | consistency.rs | Ballot namespace or address binding mismatch |
| 16 | `FAIL_CENSUS` | census.rs | Census membership proof invalid |
| 17 | `FAIL_REENC` | babyjubjub.rs | Re-encryption verification failed |
| 18 | `FAIL_KZG` | kzg.rs | KZG barycentric evaluation mismatch |
| 19 | `FAIL_MISSING_BLOCK` | various | A mandatory protocol block is absent |
| 20 | `FAIL_RESULT_ACCUM` | results.rs | Homomorphic ballot sum doesn't match results |
| 21 | `FAIL_LEAF_HASH` | results.rs | Ballot SMT leaf hash mismatch |
| 22 | `FAIL_BINDING` | main.rs | Cross-block binding mismatch |
| 31 | `FAIL_PARSE` | io.rs | Binary format / parse error |

---

## 12. Security Properties

The following security properties are guaranteed when `overall_ok = 1`:

### 12.1 Ballot Integrity

Every ballot in the batch has a valid Groth16 BN254 proof, attesting that the
voter correctly encrypted their choices under the election public key according
to the ballot circuit constraints.

### 12.2 Voter Authentication

Every voter demonstrated knowledge of the private key corresponding to their
Ethereum address by producing a valid secp256k1 ECDSA signature over the
voteID. The public key hash matches the address declared in the ballot proof.

### 12.3 Census Membership

Every voter has a valid Merkle inclusion proof in the census tree. The census
address is bound to the ballot proof address (Phase 6.6), preventing reuse of
census proofs across voters. No duplicate census leaves exist within a batch.

### 12.4 State Integrity

The state tree evolves through a valid chain of SMT transitions from
`OldStateRoot` to `NewStateRoot`. VoteIDs are insert-only (no overwrites or
deletes). Ballot entries are insert or update only. The transition chain is
contiguous with no gaps.

### 12.5 Process Binding

The process configuration (ProcessID, BallotMode, EncryptionKey, CensusOrigin)
is read from the state tree at `OldStateRoot` and verified via SMT inclusion
proofs. The processID matches the state block header. The encryption key matches
the re-encryption public key. The KZG blob is bound to the same processID and
state root.

### 12.6 Vote Privacy

Ballots are re-encrypted with a deterministic key before storage. The
re-encryption is verified to be correct (original + EncryptedZero = re-encrypted).
The re-encryption key matches the election's public key stored in the process
configuration.

### 12.7 Tally Correctness

The homomorphic result accumulators (`ResultsAdd`, `ResultsSub`) are verified to
equal the element-wise sum of all voter ballots (and overwritten ballots,
respectively). Ballot leaf hashes bind the serialized ballot data to the SMT
leaf values, preventing substitution.

### 12.8 Data Availability

The KZG blob commitment is verified via barycentric polynomial evaluation. The
evaluation point Z is derived from the process context, binding the blob to this
specific state transition.

---

## 13. Known Limitations

### 13.1 Ballot-to-Re-encryption Binding

The ballot proof's public inputs are `[address, voteID, inputsHash]`. The raw
ciphertext data (8 × ElGamal `(C1, C2)` pairs) is **not** exposed as public
inputs of the Circom ballot circuit. Therefore, the circuit cannot directly
verify that the re-encryption `original` ciphertexts match the ballot proven
by the Groth16 proof.

The `inputsHash` public input is a commitment to the ballot data. A future
enhancement could verify that `SHA-256(original_ciphertexts) == inputsHash`,
which would close this gap.

**Mitigation:** The sequencer generates both the ballot proof and the
re-encryption data from the same source ballot. A dishonest sequencer could
substitute different ballot data, but this would be detectable during
decryption/tallying (the decrypted tally would not match the expected results).

### 13.2 BabyJubJub Subgroup Check

The BabyJubJub curve has cofactor 8. The `is_on_bjj_curve()` check verifies
the curve equation but does not verify prime-order subgroup membership.

**Mitigation:** The public key is constrained to match the process
configuration's encryption key (Phase 6.3, verified via SHA-256 hash against
the state tree). An attacker cannot substitute a low-order public key without
modifying the process configuration.

### 13.3 KZG Opening Proof

The circuit verifies the barycentric polynomial evaluation (`Y = P(Z)`) but
does not verify the KZG opening proof (which requires BLS12-381 pairings).
This matches the Gnark `VerifyBarycentricEvaluation` circuit.

**Mitigation:** The full KZG opening proof will be verified once BLS12-381
pairing precompiles are available in ZisK.

### 13.4 CSP Census Proofs

Only lean-IMT Poseidon census proofs are supported. The Gnark circuit also
supports CSP/blind-signature census proofs, which are not yet implemented.

### 13.5 Blob Content Verification

The circuit does not verify that the blob content matches the state transition
data (votes, results, etc.). The blob is treated as an opaque polynomial
evaluated at Z.

---

## 14. Cryptographic Primitives

| Primitive | Module | Implementation | Notes |
|-----------|--------|---------------|-------|
| SHA-256 | `hash.rs` | ZisK `sha256_once` precompile | Hardware-accelerated |
| Keccak-256 | `hash.rs` | ZisK `keccak256_short` precompile | For ECDSA envelope |
| BN254 Groth16 Pairing | `groth16.rs` | ZisK `pairing_batch_bn254` precompile | Multi-pairing |
| BN254 G1/G2 curve checks | `bn254.rs` | ZisK `is_on_curve_bn254/twist` precompiles | |
| secp256k1 ECDSA | `ecdsa.rs` | ZisK `secp256k1_ecdsa_verify` precompile | |
| BN254 Fr arithmetic | `bn254_fr.rs` | ZisK `arith256_mod` precompile (syscall 0x802) | `(a·b+c) mod p` |
| BLS12-381 Fr arithmetic | `bls_fr.rs` | ZisK `arith256_mod` precompile (syscall 0x802) | `(a·b+c) mod p` |
| Poseidon (iden3, BN254) | `poseidon.rs` | Software (bn254_fr precompile for field ops) | 54 full rounds |
| BabyJubJub | `babyjubjub.rs` | Software (bn254_fr precompile for field ops) | Twisted Edwards |
| Arbo SMT | `smt.rs` | Software (SHA-256 precompile for hashing) | Circomlib Processor |
