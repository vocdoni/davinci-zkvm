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
15. [Performance Optimizations](#15-performance-optimizations)

---

## 1. Architecture Overview

The DAVINCI zkVM circuit is a single RISC-V program (compiled for `riscv64ima-zisk-zkvm`).
It runs inside the ZisK zkVM and produces a STARK proof attesting that
all protocol constraints hold for a given batch of votes. Per-batch mode wraps
that proof in PLONK; chained mode folds it with the aggregator guest.

```
┌────────────────────────────────────────────────────────────────┐
│                     ZisK Circuit                               │
│                                                                │
│  Binary Input ---> Parse ---> Phase 1 (Groth16 Batch)          │
│                         ├---> Phase 2 (Signature Auth)         │
│                         ├---> Phase 3 (Census Eligibility)     │
│                         ├---> Phase 4 (State Transition)       │
│                         │     ├─ 4.1 Consistency               │
│                         │     ├─ 4.2 SMT Chains                │
│                         │     ├─ 4.3 Re-encryption             │
│                         │     ├─ 4.4 Result Accumulator        │
│                         │     └─ 4.5 Silent Refresh            │
│                         ├---> Phase 5 (KZG Data Availability)  │
│                         └---> Phase 6 (Cross-Block Binding)    │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

The phases run in this order; 4.3 and the re-encryption half of 4.5 share one
pass over the offset-scalar chain, before 4.4. A failing phase does not stop
the later ones.

**Mandatory blocks.** STATETX, REENCBLK and the eligibility block that
`censusOrigin` selects (CENSUS or CSPBLK) must be present; an absent one sets
`FAIL_MISSING_BLOCK` and the verdict is FAIL. The ECDSA signatures are part of
the Groth16 block. The KZG block is optional: without it Phase 5 passes with a
zero digest and `NBlobs = 0` (chained mode); the per-batch settlement contract
rejects `NBlobs = 0`.

A valid batch carries at least one vote: an empty census or CSP block fails
Phase 3, and 6.4 requires one eligibility proof per voter.

---

## 2. Input Format

The circuit reads one `read_slice` frame from the ZisK input tape. The frame
is a sequence of blocks, each opened by an 8-byte magic (ASCII, read as a
little-endian u64). All integers are u64 little-endian. An `Fr` is 32 bytes,
four u64 LE limbs, least-significant first (`FrRaw`). A G1 point is `x ‖ y`
(8 limbs), a G2 point `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` (16 limbs); the identity is
the all-zero encoding.

### Block ordering (required)

| Order | Magic        | Module    | Content                                  |
|-------|-------------|-----------|------------------------------------------|
| 1     | `GROTH16B`  | `io.rs`   | Header + VK + proofs + ECDSA signatures  |
| 2     | `STATETX!`  | `io.rs`   | Full state-transition data               |
| 3     | `CENSUS!!`  | `io.rs`   | Census lean-IMT Poseidon proofs (censusOrigin ≠ 4) |
| 3'    | `CSPBLK!!`  | `io.rs`   | CSP ECDSA census proofs (censusOrigin 4) |
| 4     | `REENCBLK`  | `io.rs`   | Election key, batch-scoped seed, re-encryption entries |
| 5     | `KZGBLK!!`  | `io.rs`   | DA blob commitments (guest rebuilds cells) |

The parser reads the blocks in this order, each right after the previous one.
Blocks 2–5 are recognised by their magic and may be missing at parse time;
the phases decide whether a missing block fails. Bytes left after the last
recognised block set `FAIL_PARSE`, so a block out of order is a parse failure.

> Blocks 3 and 3' are mutually exclusive by convention: the guest uses the one
> `censusOrigin` selects and ignores the other.

### Groth16 Block

```
offset  size   field
──────  ────   ─────
0       8      magic ("GROTH16B" LE)
8       8      log_n (u64; the host writes floor(log₂ nproofs); echoed, not checked)
16      8      nproofs (u64, 1..=MAX_BATCH_SIZE = 1024)
24      8      n_public (u64, ≤ 256; 3 for the ballot circuit)

VK      alpha_g1 (G1) ‖ beta_g2 (G2) ‖ gamma_g2 (G2) ‖ delta_g2 (G2)
        gamma_abc_len (u64, must equal n_public + 1)
        gamma_abc[gamma_abc_len] (G1 each)
Proofs  nproofs (u64, repeated, must equal the header value)
        nproofs × ( A (G1) ‖ B (G2) ‖ C (G1) ‖ pubs[n_public] (Fr each) )
ECDSA   nproofs × ( r (Fr) ‖ s (Fr) ‖ recid (u64, low byte used) )
```

The block carries no batch-verification hints: the guest computes the whole
random linear combination itself (§4). `nproofs` must equal `n_voters` (6.8).
The VK hash, `SHA-256` over the VK bytes from `alpha_g1` through the last
`gamma_abc` point (read as a big-endian integer), is bound to config key 0x07
(6.7).

### STATETX Block

```
offset  size   field
──────  ────   ─────
0       8      magic ("STATETX!" LE)
8       8      n_voters (u64, real votes in batch)
16      8      n_overwritten (u64, votes that replaced an existing ballot)
24      8      occupied_before (u64, ballot leaves alive in the tree before batch)
32      32     process_id (FrRaw LE, arbo hex)
64      32     old_state_root (FrRaw LE)
96      32     new_state_root (FrRaw LE)

Then, in order:
  VoteID chain          count (≤ MAX_BATCH_SIZE), n_levels, count × entry
  Ballot chain          count (≤ MAX_BATCH_SIZE), n_levels, count × entry
  Refresh chain         count (≤ MAX_REFRESH = 2048), n_levels, count × entry  (§4.5)
  Results transition    has (0|1), n_levels, entry if has              (single net leaf)
  Process config proofs n (0|5); if 5: n_levels, 5 × entry              (§4.2 read-proofs)
  Ballot payload data   has (0|1); if 1:
                          old_results          64 × Fr
                          n_vb (≤ 4096)         n_vb × 64 × Fr   voter_ballots
                          n_ob (≤ 4096)         n_ob × 64 × Fr   overwritten_ballots
                          n_rb (≤ MAX_REFRESH)  n_rb × 64 × Fr   refreshed_ballots
```

Every count, flag and `n_levels` is a u64 word. `n_levels` is at most
`SMT_LEVELS = 64` (the arbo tree depth, davinci-node `StateTreeMaxLevels`).
Counts or `n_levels` above their caps set `FAIL_PARSE` and are clamped before
any allocation. A process-proof count other than 0 or 5 is a parse failure;
0 parses but fails 4.2.P1. With the payload flag at 0 the ballot lists are
empty and `old_results` is all-zero. A ballot is 64 × 32 B (`NUM_FIELDS = 16`
ciphertexts × 4 TE coords, `[c1x, c1y, c2x, c2y]` per ciphertext).

A leaf at depth 64 would need 64 siblings, the last one non-zero, plus the
zero leaf-level sentinel the processor expects, which does not fit; arbo never
creates one (`Add` fails with `ErrMaxVirtualLevel` for a key that agrees with
an existing key on its first 63 path bits), so such a vote-id simply cannot be
inserted and the voter resubmits with a fresh `k`.

Each SMT transition entry is:

```
old_root[32] new_root[32] old_key[32] old_value[32]
is_old0[8]   new_key[32]  new_value[32]
fnc0[8]      fnc1[8]
siblings[n_levels × 32]
```

`is_old0`, `fnc0` and `fnc1` are u64 words (non-zero = true). Siblings run
root → leaf, zero-padded to `n_levels`.

### CENSUS Block

```
offset  size   field
──────  ────   ─────
0       8      magic ("CENSUS!!" LE)
8       8      n_proofs (u64, ≤ 4096)
then n_proofs × ( root (Fr) ‖ leaf (Fr) ‖ index (u64) ‖ n_siblings (u64, ≤ 64) ‖ siblings (Fr each) )
```

The CSPBLK layout is in §6 (3B).

### REENCBLK Block

```
offset  size   field
──────  ────   ─────
0       8      magic ("REENCBLK" LE)
8       8      n_voters (u64, ≤ MAX_BATCH_SIZE)
16      32     pub_key_x (Fr, TE x of the election key)
48      32     pub_key_y (Fr, TE y)
80      32     seed (Fr, batch-scoped chain seed)
112     ...    n_voters × ( original[16] ‖ reencrypted[16] ), each ciphertext
               c1x ‖ c1y ‖ c2x ‖ c2y (Fr), 4096 B per voter
```

### KZGBLK Block

```
offset  size            field
──────  ────            ─────
0       8               magic ("KZGBLK!!" LE)
8       32              process_id (FrRaw LE; big-endian hex in the /prove JSON)
40      32              root_hash_before (FrRaw LE)
72      8               n_blobs (u64 LE, 1..=MAX_BLOBS = 32)
80      n_blobs × 48    commitments (compressed BLS12-381 G1, 48 B each, big-endian)
```

No `y_claimed`, no blob bytes. The guest rebuilds the blob cells from
verified state (vote-id list, sorted slot updates, and the NEW net
accumulator; see §8) and evaluates each polynomial itself. `n_blobs` above
`MAX_BLOBS` or a truncated commitment list sets `FAIL_PARSE`; zero blobs, or
a count other than the one the reconstructed cells need, sets `FAIL_KZG`.

### Parse failures

`FAIL_PARSE` (bit 31) covers: a wrong Groth16 magic, `nproofs` of 0 or above
`MAX_BATCH_SIZE`, `n_public > 256`, `gamma_abc_len ≠ n_public + 1`, a repeated
proof count different from the header, truncated data, any count above its
cap, `n_levels` above 64, a process-proof count other than 0 or 5, and
trailing bytes. Phase 1 is skipped when `FAIL_PARSE` is set.

---

## 3. Output Registers

The circuit writes 46 `u32` output registers with `commit_slice` (184 LE
bytes). A ZisK proof carries 64 u32 publics, so publics 46..63 are zero; the
on-chain `publicValues` is the same 64 values as u64 LE words (512 B).
Registers 2–27 mirror the public inputs of davinci-node's state-transition
circuit. The settlement contract reads registers 0–36 and 42; the fold guest
reads 0–27 and 42; 40, 41 and 43–45 are diagnostics.

```
Register    Name                    Encoding
────────    ────                    ────────
[0]         overall_ok              1 = all checks passed, 0 = at least one failed
[1]         fail_mask               per-check failure bits (see §11)

[2..9]      RootHashBefore          STATETX old_state_root, FrRaw → 8 × u32 LE
[10..17]    RootHashAfter           STATETX new_state_root, FrRaw → 8 × u32 LE
[18]        VotersCount             STATETX n_voters
[19]        OverwrittenVotesCount   STATETX n_overwritten

[20..27]    CensusRoot              lean-IMT root of census proof 0, or the
                                    recovered CSP address as uint160;
                                    FrRaw → 8 × u32 LE
[28..35]    BlobsDigest             SHA-256 over ordered (commitment, y) pairs;
                                    reg[28+i] = u32_le(digest[4i..4i+4]).
                                    Zero without a KZG block and on FAIL_KZG.
[36]        NBlobs                  number of blob commitments (0..=MAX_BLOBS = 32);
                                    zero without a KZG block
[37..39]    reserved                zero

[40]        batch_ok                Groth16 batch verification passed
[41]        ecdsa_ok                ECDSA batch verification passed
[42]        OccupiedBefore          STATETX occupied_before, truncated to u32
                                    (overflow of u32 sets FAIL_REFRESH; the fold
                                     guest and the settlement contract check it
                                     equals total_voters - total_overwrites)
[43]        nproofs                 header nproofs (equals n_voters when overall_ok = 1)
[44]        n_public                header n_public
[45]        log_n                   header log_n, echoed unchecked
```

Without a STATETX block, registers 2–19 and 42 are zero. The census root is
not bound to the state tree in-guest; the consumers compare it with the
process census root (13.6).

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
by the Circom `BallotCircuit`. Up to `MAX_BATCH_SIZE = 1024` proofs are
verified in a single multi-pairing using Fiat-Shamir randomization. The phase
is skipped (`batch_ok = 0`, no bit of its own) when `FAIL_PARSE` is set.

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 1.1 | VK: α and every γ_abc[j] are on BN254 G1 and not the identity; β, γ, δ are on the G2 twist, in the prime-order subgroup and not the identity | FAIL_CURVE |
| 1.2 | Each proof point A_i is on BN254 G1 and not the identity (G1 has cofactor 1, so on-curve means in-group) | FAIL_CURVE |
| 1.3 | Each proof point B_i is on the BN254 G2 twist. No subgroup check; the code's argument is that the transcript fixes B_i before the random coefficients exist | FAIL_CURVE |
| 1.4 | Each proof point C_i is on BN254 G1 and not the identity | FAIL_CURVE |
| 1.5 | Batch pairing equation holds: `e(-(Σr_i)·α, β) · e(-Σ r_i·L_i, γ) · e(-Σ r_i·C_i, δ) · Π e(r_i·A_i, B_i) = 1_GT` | FAIL_PAIRING |

### Fiat-Shamir transcript

```
transcript = "groth16-batch-v2" ‖ A_0 ‖ B_0 ‖ C_0 ‖ pubs_0 ‖ A_1 ‖ B_1 ‖ C_1 ‖ pubs_1 ‖ ...
digest     = SHA-256(transcript)
r_0        = 1
r_i        = lo128(SHA-256(digest ‖ le64(i)))          i ≥ 1
```

Curve points and public inputs enter as their raw `[u64; N]` LE limbs (64 B
per G1, 128 B per G2, 32 B per input). `lo128` reads bytes 0..16 of the hash
as two LE u64 limbs; the all-zero value maps to 1. The coefficients are
independent 128-bit values (small-exponents batch test, 2⁻¹²⁸ soundness
error). The VK is not in the transcript; it is pinned per process by 6.7.

### Security rationale

The guest computes the entire random linear combination itself — every scalar
multiplication over the proof points, public inputs and VK. The wire format
carries no precomputed points: a host-supplied aggregate would be unsound,
because one GT equation cannot bind n+3 free G1 points (a host could balance
`B_i = c_i·β` against the α term and zero the γ and δ terms, which the pairing
skips as identities). The γ-side term is aggregated as
`(Σr_i)·γ_abc[0] + Σ_j (Σ_i r_i·pubs_ij)·γ_abc[j+1]`, which is algebraically
identical to `Σ_i r_i·L_i` but needs only `n_public + 1` scalar muls per batch.
Public inputs enter that sum reduced mod r, so a non-canonical input verifies
as its residue; 2.6 and 6.6 compare the raw low 160 bits of `pubs[0]`.

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
| 2.1 | ECDSA entries are present (non-empty) | FAIL_ECDSA |
| 2.2 | At least 2 public inputs per proof (address, voteID) | FAIL_ECDSA |
| 2.3 | ECDSA entry count == proof count | FAIL_ECDSA |
| 2.4 | VoteID upper limbs are zero (`pubs[1][1..3] == 0`); voteID is uint64 | FAIL_ECDSA |
| 2.5 | `pk = ecdsa_recover_secp256k1(r, s, z, recid)` succeeds, where `z = keccak256(ethSignedMessage(voteID))` read as a big-endian integer | FAIL_ECDSA |
| 2.6 | The Ethereum address of the recovered key matches the low 160 bits of `pubs[0]`: `keccak256(pk.x_BE32 ‖ pk.y_BE32)[12..32] == address_BE20` | FAIL_ECDSA |

The checks stop at the first failing entry.

### Signature scheme

```
message   = PadToSign(vote_id_BE8)                         // 32 bytes: 24×0x00 ‖ vote_id_BE8
envelope  = "\x19Ethereum Signed Message:\n32" ‖ message   // 60 bytes
z         = keccak256(envelope)                             // 256-bit hash
```

This matches `davinci-node/crypto/signatures/ethereum.Sign()`. The voter's
public key is not in the input: the guest recovers it from `(r, s, z, recid)`.

### Extensibility

The authentication method is fixed to secp256k1 ECDSA. The architecture
supports extension to RSA, BLS, EdDSA, or other schemes, selected by a process
configuration parameter (similar to `censusOrigin`).

---

## 6. Phase 3: Eligibility

**Module:** `census.rs`, `csp.rs`  
**Fail bits:** `FAIL_CENSUS` (bit 16), `FAIL_CSP` (bit 23), `FAIL_MISSING_BLOCK` (bit 19)

### Purpose

Verify that each voter is authorized to participate in the election. The method
is selected by the `censusOrigin` process config parameter (key 0x06), read as
limb 0 of that leaf's value:

| censusOrigin | Method | Module | Description |
|:---:|--------|--------|-------------|
| ≠ 4 (1-3) | lean-IMT Poseidon | `census.rs` | Merkle tree membership proof |
| 4   | CSP ECDSA | `csp.rs` | Credential Service Provider signature |

### 3A. Merkle Census (censusOrigin 1-3)

#### Census leaf encoding

```
leaf = PackAddressWeight(address, weight) = (address << 88) | weight
```

Where `address` is the 160-bit Ethereum address and `weight` is the voter's
weight (up to 88 bits). The leaf is stored as a BN254 Fr element.

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 3A.1 | Census block is present (non-empty) | FAIL_MISSING_BLOCK |
| 3A.2 | All proofs reference the **same census root** | FAIL_CENSUS |
| 3A.3 | No duplicate leaves (raw 256-bit equality) across all proofs in the batch | FAIL_CENSUS |
| 3A.4 | Each proof has a canonical shape: `siblings.len() <= 61` and `index >> siblings.len() == 0` (no path bit the walk never reads) | FAIL_CENSUS |
| 3A.5 | Each proof's Merkle path is valid: recomputed root matches declared root | FAIL_CENSUS |

#### Merkle path verification

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

The `census_root` output is taken from the first census proof's root field.

The path does not fix the voter's ballot slot. A lean-IMT root does not
commit to the tree size, and path bits are free on the levels a compact proof
keeps, so one leaf verifies at several positions (and a growing census moves
every position). The slot comes from the leaf's address instead (4.1.6).

### 3B. CSP ECDSA Census (censusOrigin 4)

In CSP mode, a trusted Credential Service Provider signs each voter's eligibility
using secp256k1 ECDSA. The census root is the CSP's Ethereum address (20-byte, uint160).

#### CSP message format (Ethereum personal-sign)

```
payload  = processID_BE32(32) ‖ address_BE20(20) ‖ weight_BE32(32) ‖ index_BE8(8)  = 92 bytes
envelope = "\x19Ethereum Signed Message:\n92" ‖ payload                             = 120 bytes
z        = keccak256(envelope)
```

- **processID**: the STATETX `process_id`, which 4.2 pins to config key 0x00
- **address**: voter's 20-byte Ethereum address, the low 160 bits of `voter_address`
- **weight**: voter's voting weight (256-bit big-endian)
- **index**: CSP-assigned index; the voter's ballot slot is `BallotMin + index` (4.1.6)

#### CSPBLK binary block format

```
Header:  CSP_MAGIC("CSPBLK!!") | n_entries(u64)            (n_entries <= 4096, else FAIL_PARSE)
Entry:   r(FrRaw) | s(FrRaw) | recid(u64, low byte used) | voter_address(FrRaw) | weight(FrRaw) | index(u64)
```

The block carries no CSP key. The guest recovers it from each entry with
`ecdsa_recover_secp256k1(r, s, z, recid)` and requires every entry to recover
the same point as entry 0.

#### CSP address derivation

```
pk_0        = ecdsa_recover_secp256k1(r_0, s_0, z_0, recid_0)
csp_address = keccak256(pk_0.x_BE32 ‖ pk_0.y_BE32)[12..32]
census_root = uint160(csp_address) as FrRaw
```

Only one keccak runs per batch: entries 1.. compare the recovered point with
`pk_0` instead of deriving an address.

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 3B.1 | CSP block is present when censusOrigin=4 | FAIL_MISSING_BLOCK |
| 3B.2 | CSP block has at least 1 entry | FAIL_CSP |
| 3B.2b | Every `voter_address` is a canonical uint160: `voter_address[2] >> 32 == 0` and `voter_address[3] == 0`. The message, the binding (6.6) and ECDSA (2.6) read only the low 160 bits, so without this one address with bit 160 set would pass 3B.3 as a second address | FAIL_CSP |
| 3B.3 | No duplicate `voter_address` and no duplicate `index` across entries (the index is the ballot slot, 4.1.6; the CSP must assign one index per voter) | FAIL_CSP |
| 3B.4 | Each entry recovers a key (`ecdsa_recover_secp256k1(r, s, z, recid)` succeeds), and every recovered key equals `pk_0` | FAIL_CSP |

### Extensibility

The eligibility dispatch reads `censusOrigin` from the process config (key 0x06).
New census mechanisms can be added by extending the dispatch in `main.rs` Phase 3.

---

## 7. Phase 4: State Transition

Phase 4 is the core of the DAVINCI protocol. It verifies that the batch of
votes is correctly recorded in the election state tree (Arbo SHA-256 SMT) and
that the election tally is properly maintained.

### 4.1 Consistency Checks

**Module:** `consistency.rs`  
**Fail bits:** `FAIL_CONSISTENCY` (bit 14), `FAIL_BALLOT_NS` (bit 15)

These checks ensure that the SMT keys fall in the correct namespace and that
the ballot/voteID data is bound to the corresponding ballot proof. They pass
trivially when `n_voters = 0`; the ballot rows run when the ballot chain is
non-empty (4.2.2 requires `n_voters` entries).

| # | Check | Fails on |
|---|-------|----------|
| 4.1.1 | STATETX block is present | FAIL_MISSING_BLOCK |
| 4.1.2 | Each `vote_id_chain[i].new_key[0] ≥ 0x8000_0000_0000_0000` (VoteID namespace) | FAIL_CONSISTENCY |
| 4.1.3 | Each `vote_id_chain[i].new_key[0] == proofs[i].public_inputs[1][0]` (VoteID binding) | FAIL_CONSISTENCY |
| 4.1.4 | VoteID public input upper limbs zero: `pubs[1][1..3] == 0` | FAIL_CONSISTENCY |
| 4.1.4b | `vote_id_chain[i].new_key[1..3] == 0` and `ballot_chain[i].new_key[1..3] == 0`: slot keys are u64, and the DA blob publishes limb 0 only, so a leaf at `key + 2^64` would be unreconstructible | FAIL_CONSISTENCY / FAIL_BALLOT_NS |
| 4.1.5 | Each `ballot_chain[i].new_key[0] ∈ [0x10, 0x7FFF_FFFF_FFFF_FFFF]` (Ballot namespace) | FAIL_BALLOT_NS |
| 4.1.6 | `ballot_chain[i].new_key[0] == slot(i)` (slot binding): Merkle census `slot = address_slot(addr_i)` with `addr_i` the address of census leaf `i` (below); CSP census `slot = BallotMin + entries[i].index` (the index the CSP signed; a sum above `BallotMax` never matches) | FAIL_BALLOT_NS |
| 4.1.7 | The keys `ballot_chain[*].new_key[0]` are pairwise distinct (both census modes). It shares `FAIL_BALLOT_NS` with the slot binding and has no bit of its own | FAIL_BALLOT_NS |

Merkle slot rule:

```
addr_i          = 20 bytes, big-endian, of (census_proofs[i].leaf >> 88) mod 2^160
address_slot(a) = BallotMin + (be64(SHA-256("davinci-slot-v1" ‖ a)[0..8]) mod (2^63 − 16))
```

`addr_i` is exactly the value 6.6 compares with ballot proof `i`'s address,
which 2.6 binds to the ECDSA signer, so a ballot can only be written to its
signer's slot. Leaf bits above 247 are not part of `addr_i`: a leaf carrying
them either fails 6.6 or maps to its signer's slot, never to a second one. The
result is always inside `[BallotMin, BallotMax]`. The tag is 15 ASCII bytes and
the preimage 35 bytes, hashed on the `sha256f` precompile.

Distinct addresses can share a slot. Finding an address whose slot collides
with one of N members takes about 2^63/N key generations (hours of GPU time
at N = 10^6), and the colliding voter would overwrite that member's ballot;
the guest cannot tell, because it sees the slot's old ballot and not its
owner. Slot uniqueness is therefore part of the census manager's contract:
an on-chain census must reject a registration whose slot is taken, and the
sequencer must refuse a census with colliding slots. Within one batch the guest
enforces it itself (4.1.7): a crafted census with two leaves for one address,
or a collision, would otherwise write one slot twice. The CSP rule already
has distinct indexes (3B.3); 4.1.7 applies there too.

**Key namespace layout:**

```
0x00 .. 0x0F    Process config keys (reserved)
0x10 .. 0x7FFF...  Ballot keys:  address_slot(address)   (Merkle)
                                 BallotMin + csp_index    (CSP)
0x8000... .. 0xFFFF...  VoteID keys: unique per ballot proof
```

Keys are u64 in a 64-level tree, so distinct keys never share a leaf. Two
kinds of key collide. Vote-id keys are 63-bit truncated hashes: a collision
makes the INSERT fail and that voter resubmits with a fresh `k`. Merkle ballot
slots are 63-bit address hashes: two members whose slots collide would share
one slot, so the census manager must keep slots unique (see the slot rule
above), and 4.1.7 rejects a batch that writes one slot twice.

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
                    │Refresh Chain │ ────→ (intermediate root)
                    │ [0..refresh] │        (§4.5, may be empty)
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │   Results    │ ────→ NewStateRoot
                    │  (net leaf)  │
                    └──────────────┘
```

An empty chain passes its start root through unchanged; with no Results
transition the last chain must end at `NewStateRoot`.

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 4.2.1 | `vote_id_chain.len() == n_voters` | FAIL_SMT_VOTEID |
| 4.2.2 | `ballot_chain.len() == n_voters` | FAIL_SMT_BALLOT |
| 4.2.3 | Actual UPDATE count in ballot chain == `n_overwritten` | FAIL_SMT_BALLOT |
| 4.2.4 | Every VoteID transition is INSERT (`fnc0=true, fnc1=false`) with `new_value == 0` (davinci-node's `VoteIDLeafValue`), so the DA blob only needs the identifier keys for an observer to rebuild the tree | FAIL_SMT_VOTEID |
| 4.2.5 | Every Ballot transition is INSERT or UPDATE (no DELETE, no NOOP) | FAIL_SMT_BALLOT |
| 4.2.6 | VoteID chain: `chain[0].old_root == OldStateRoot` | FAIL_SMT_VOTEID |
| 4.2.7 | VoteID chain: each `chain[i].new_root == chain[i+1].old_root` | FAIL_SMT_VOTEID |
| 4.2.8 | VoteID chain: last `new_root == ballot_chain[0].old_root` | FAIL_SMT_VOTEID |
| 4.2.9 | Ballot chain chaining (same as VoteID); it ends at `refresh_chain[0].old_root`, or at `results.old_root` / `NewStateRoot` when the refresh chain is empty | FAIL_SMT_BALLOT |
| 4.2.10 | Each SMT transition is valid (Processor below: Merkle proof against old root, new root recomputation) | the chain's own bit |
| 4.2.11 | Results transition valid, chains from end of ballot chain (or refresh chain if present), and `new_root == NewStateRoot` | FAIL_SMT_RESULTS |
| 4.2.12 | Results transition is pinned to key `0x04` — `fnc0=false, fnc1=true, !is_old0, old_key == new_key == [0x04, 0, 0, 0]`. Rejects NOOP (which only asserts `old==new_root`) and INSERT-at-unused-key, both of which would otherwise pass §4.2.11 while letting `verify_results` skip the actual tally. Reproduced by `TestCheatResultsNoop` | FAIL_SMT_RESULTS |

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

  For NOOP (fnc0=false, fnc1=false):
    - old_root == new_root (the Processor only asserts roots are unchanged;
      it does NOT touch the siblings, so a NOOP proves nothing about
      membership). No chain in this circuit accepts a NOOP.
```

Siblings run root → leaf (`siblings[0]` is the root level). The path bit at
level `i` is bit `i` of key limb 0, LSB first. For an enabled transition the
leaf-level sibling must be zero and exactly one insertion level must exist
(circomlib `LevIns`: the leaf sits one level below the last non-zero sibling),
and the state machine must end in exactly one terminal state. A transition
with zero siblings is rejected. INSERT of a key already in the tree fails:
with `old_key == new_key` the state machine never reaches a terminal state,
and any other witness misses `old_root`.

> **Read-proofs use the Verifier, not a Processor NOOP.** A Processor NOOP
> only checks `old_root == new_root` and ignores the siblings, so it cannot
> bind `(key, value)` to the tree. Anything that needs to *read* a committed
> value out of the state tree (the process config read-proofs, §4.2.P) uses
> the circomlib `SMTVerifier` inclusion path (`smt.rs::verify_inclusion`),
> which reconstructs the root from the leaf and siblings. See §4.2.P.

**Hash functions (Arbo SHA-256 compatible):**

```
leaf_hash(key, value) = SHA-256(key_LE8 ‖ value_LE32 ‖ 0x01)     // 41 bytes (arbo, 8-byte keys)
node_hash(left, right) = SHA-256(left_LE32 ‖ right_LE32)          // 64 bytes
```

All byte arrays use **little-endian** encoding (Arbo's `BigIntToBytes` convention).
Only limb 0 of a key is hashed or walked; 4.1.4b and 4.5.3 pin the upper limbs.

#### Process Config Read-Proofs

The election config (ProcessID, BallotMode, EncryptionKey, CensusOrigin,
BallotVKHash) is read out of the state tree at `OldStateRoot`. Each value is
bound to the tree with a genuine **SMTVerifier inclusion proof**
(`smt.rs::verify_inclusion`), matching davinci-node's `MerkleProof.Verify`.
This is *not* a Processor NOOP: a NOOP only asserts `old_root == new_root` and
never inspects the siblings, so it would let a prover assert an arbitrary
config value — most dangerously a forged EncryptionKey, which is not a public
output and so has no external backstop, enabling tally manipulation. Inclusion
reconstructs the root from `leaf_hash(key, value)` and the siblings and
rejects any mismatch. Only `new_key`, `new_value` and the siblings of a
read-proof are used; its other fields are ignored.

| # | Check | Fails on |
|---|-------|----------|
| 4.2.P1 | Exactly 5 process proofs | FAIL_SMT_PROCESS |
| 4.2.P2 | Each proof: `old_root == new_root == OldStateRoot` (read-only) | FAIL_SMT_PROCESS |
| 4.2.P3 | Each proof: genuine SMT inclusion of `(key, value)` under `OldStateRoot` (SMTVerifier) | FAIL_SMT_PROCESS |
| 4.2.P4 | Key order: `[0x00, 0x02, 0x03, 0x06, 0x07]` (ProcessID, BallotMode, EncryptionKey, CensusOrigin, BallotVKHash) | FAIL_SMT_PROCESS |
| 4.2.P5 | `process_proofs[0].new_value == state.process_id` (ProcessID matches header) | FAIL_SMT_PROCESS |

The values feed the rest of the guest: BallotMode gives `num_fields` (4.3.6)
and enters the inputs hash (6.9), CensusOrigin selects Phase 3, EncryptionKey
is checked in 6.3 and BallotVKHash in 6.7.

### 4.3 Re-encryption Verification

**Module:** `babyjubjub.rs`  
**Fail bits:** `FAIL_REENC` (bit 17), `FAIL_MISSING_BLOCK` (bit 19)

Verifies that each voter's ballot was correctly re-encrypted before storage,
ensuring vote privacy (unlinkability between voter and stored ballot) while
preserving the homomorphic structure needed for tallying.

#### Algorithm

The REENCBLK carries ONE batch-scoped `seed` (the sequencer's per-transition
secret). The guest derives every per-ciphertext offset scalar in-circuit
through a single SHA-256 chain: `H(bytes) = sha256(bytes)` read as a
big-endian integer and reduced mod p (the BN254 scalar field, BabyJubJub's
base field). `be32(x)` is the 32-byte big-endian encoding of the raw limbs.
The chain starts from the seed and the STATETX `old_root`. Every ACTIVE
ciphertext, in block order then field order, consumes one chain element and
the chain advances once. Entry N+1 continues where entry N left off; every
chain element is consumed exactly once.

```
r₀ = H( "davinci-reenc-v1" || be32(seed) || be32(old_root) )   // chain start, 80-byte preimage
r_{t+1} = H( be32(r_t) )                                       // chain step

For each entry in block order:
  For each active ciphertext i in [0..num_fields):
    δ₁ = r_t · B8                              // delta for C1
    δ₂ = r_t · pubKey                          // delta for C2
    newC1[i] = origC1[i] + δ₁                 // twisted Edwards point add
    newC2[i] = origC2[i] + δ₂
    r_{t+1} = H( be32(r_t) )                  // advance the chain
  For each padded ciphertext i in [num_fields..16):
    assert origC*[i] == newC*[i] == identity  // (0,1); EC work skipped, chain not advanced
```

The original coordinates are reduced mod p before the add; the claimed
re-encrypted point must equal the precompile's canonical output coordinate
for coordinate. Test vector: `seed = 1`, `old_root = 2` give
`r₀ = 0x0a63922a58b3fe4dbec15e6db1be5438713862d2fa6fa543af70812000d38d7d`.

#### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 4.3.1 | Re-encryption block is present (public key exists) | FAIL_MISSING_BLOCK |
| 4.3.2 | Public key `(x, y)` satisfies BabyJubJub curve equation: `a·x² + y² = 1 + d·x²·y²` | FAIL_REENC |
| 4.3.2b | Public key is in the prime-order subgroup: `pk ≠ identity` and `l · pk == identity`, with `l = 2736030358979909402780800718157159386076813972158567259200215660948447373041` (BabyJubJub subgroup order). Rejects small-order points; a co-factor-8 point would let a malicious key extract residues of the ballot scalars. The check and the fixed-base table for `r · pk` both use the key reduced mod p, so a key committed as `(x + p, y)` is the same point and never reaches the precompile unreduced | FAIL_REENC |
| 4.3.3 | `original.len() == reencrypted.len()` per entry (both fixed at 16 by the wire format) | FAIL_REENC |
| 4.3.4 | Padded slots (`i ≥ num_fields`) carry the TE identity, encoded exactly as `(0,1)`, on both sides | FAIL_REENC |
| 4.3.5 | For every active ciphertext, in block order then field order: `newC1 == origC1 + r_t·B8` and `newC2 == origC2 + r_t·pubKey`, where `r_t` is the next unused chain element derived from `(seed, old_root)` | FAIL_REENC |
| 4.3.6 | `num_fields`, bits 0..7 of the BallotMode leaf value (`process_proofs[1].new_value`), is in `1..=NUM_FIELDS` (16). Out of range, the guest falls back to 16 and fails | FAIL_REENC |

4.3.2 and 4.3.2b run once per batch, and only when there is at least one
entry or refresh (always, in a valid batch).

#### Security rationale

The seed is the ONLY source of secrecy; the tag and `old_root` are public and
only exist to move chains from different transitions onto disjoint starting
points. Because every chain element is used exactly once, no offset scalar
can repeat within a transition, nor across transitions (`old_root` differs),
so the same plaintext re-encrypted twice never produces the same delta. No
per-voter scalar travels on the wire, so the sequencer cannot reuse one by
accident or on purpose.

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
| 4.4.5 | Results (net): `SHA-256(serialize(OldResults + Σ voter_ballots − Σ overwritten_ballots + refresh_delta)) == results.new_value`, where `refresh_delta = Σ_j (refreshed_new[j] − refreshed_ballots[j])` is assembled by §4.5's re-encryption. Called `4.4.5'` in the source | FAIL_RESULT_ACCUM |
| 4.4.6 | Results (net): `SHA-256(serialize(OldResults)) == results.old_value` | FAIL_RESULT_ACCUM |
| 4.4.7 | If `n_voters > 0`, voter ballot data must be present (checked when all three ballot lists are empty; otherwise 4.4.1 catches it) | FAIL_RESULT_ACCUM |
| 4.4.8 | If `voter_ballots`, `overwritten_ballots` AND `refreshed_ballots` are all empty, no Results transition may be present. When any of the three is non-empty a Results transition is required (any refresh must move the tally). Called `4.4.8'` in the source | FAIL_RESULT_ACCUM |
| 4.4.9 | Padded slots (`i ≥ num_fields`) of every voter ballot, every overwritten ballot and `OldResults` are the TE identity `(0,1)` | FAIL_RESULT_ACCUM |

The length rule 4.5.9 runs first. With all three lists empty only 4.4.7 and
4.4.8 apply and the rest is skipped. `SHA-256(serialize(b))` is the digest
read as a big-endian integer into `FrRaw`.

Each ballot is `NUM_FIELDS = 16` ElGamal ciphertexts (64 BN254 Fr coords, 2048 B
serialized). Padded slots `i ≥ num_fields` must be the TE identity `(0,1)`; the
accumulator and refresh both skip the per-field EC work on padded slots and
would otherwise let a prover stash data in columns the accumulator ignores.
The accumulator emits the identity for padded slots. Point subtraction uses
the affine BabyJubJub add precompile with the group inverse `bjj_neg`, not
projective coordinates.

> **4.4.8' — empty-batch Results lock.** With no ballots and no refreshes
> there is nothing to accumulate, so the net Results leaf must not change.
> Without this check a prover could ship a valid stand-alone SMT update of
> the Results leaf to an arbitrary value and chain it into `NewStateRoot`,
> injecting a forged tally that no accumulation check binds. The guard
> rejects any `results` transition when `voter_ballots`, `overwritten_ballots`
> and `refreshed_ballots` are all empty. Any refresh moves the net (its
> `refresh_delta` is non-identity on the active fields), so the mirror rule
> also holds: a batch with refreshes MUST carry a Results transition.

**Net accumulation:** the circuit verifies a single net Results leaf,
`NewResults = OldResults + Σ(voter_ballots) − Σ(overwritten_ballots) + refresh_delta`,
mirroring davinci-node's `Ballot.Add(sumAll, Neg(sumOverwritten))` plus the
refresh delta.
`refresh_delta = Σ_j (refreshed_new[j] − refreshed_ballots[j])` is folded
active-field by active-field inside §4.5's re-encryption, so it never leaves
the guest. Subtraction is the exact BabyJubJub group inverse (`bjj_neg`, TE
inverse `(−x, y)`). All ballot sets stay pinned by leaf-hash checks
4.4.2/4.4.3 and 4.5.5/4.5.6, so folding them into one net leaf changes which
value the result commits to, not what the prover may choose. Non-negativity
needs no per-field `add ≥ sub` guard: every subtracted ballot is one the tree
holds (4.4.3), and the results guests only accept a u64 plaintext, so a net
that wrapped below zero has no provable decryption.

**Ballot serialization:** Each ballot is `BALLOT_FIELDS = NUM_FIELDS × 4 = 64`
BN254 Fr elements (`NUM_FIELDS = 16` ElGamal ciphertexts × 4 TE coords). Each
Fr element is serialized as 32 big-endian bytes; the full serialization is
`64 × 32 = 2048 bytes`.

**Homomorphic op:** add is `(a + b)[i]` BabyJubJub point add via the affine
`babyjubjub_add` precompile per coordinate pair; subtract is `a + bjj_neg(b)`
with the same precompile. No projective coordinates, no field inversions.
Inputs are reduced mod p first.

### 4.5 Silent Refresh Chain

**Module:** `smt.rs::verify_refresh_chain`, `babyjubjub.rs::verify_batch_from_parsed`, `results.rs::verify_results`, `main.rs`
**Fail bits:** `FAIL_REFRESH` (bit 24)

Every batch also re-randomizes a set of ballot leaves the batch itself did
not write: a re-encryption in place, no plaintext change. An observer who
watches the ballot leaves then cannot tell a revote (overwrite) from a
routine refresh, which is what keeps revoting deniable.

Wire contract: `refresh_chain: Vec<SmtTransition>` and
`refreshed_ballots: Vec<BallotData>` in STATETX, same length; each transition
is an UPDATE (`fnc0=false, fnc1=true`, `is_old0=false`) with
`old_key == new_key` in the ballot namespace `[0x10, 2^63)`.
`refreshed_ballots[j]` carries the OLD ciphertexts of entry `j`; the guest
recomputes the new (refreshed) ciphertexts in-circuit from the same
offset-scalar chain used by the batch re-encryption, so no `refreshed_new`
ships on the wire.

Chain continuation: §4.3's SHA-256 offset chain runs first through every
REENC voter entry (block order, field order for active fields), then through
every refresh entry (`refreshed_ballots` order, field order for active
fields). Padded slots `i ≥ num_fields` must be the TE identity `(0,1)` and
consume no chain elements.

Policy: the sequencer must include at least
`min(target, occupied_before − n_overwritten)` refreshes per batch, where
`target = min(MAX_REFRESH, max(REFRESH_MIN, REFRESH_TAU · n_overwritten,
REFRESH_KAPPA · n_voters))` and the constants are
`MAX_REFRESH = 2048, REFRESH_MIN = 16, REFRESH_TAU = 2, REFRESH_KAPPA = 1`
(`circuit-primitives/src/types.rs`).

| # | Check | Fails on |
|---|-------|----------|
| 4.5.1 | `refresh_chain.len() ≤ MAX_REFRESH` (the parser also caps this, with FAIL_PARSE) | FAIL_REFRESH |
| 4.5.2 | `occupied_before ≥ n_overwritten`, and `refresh_chain.len() ≥ min(target, occupied_before − n_overwritten)` with `target = min(MAX_REFRESH, max(REFRESH_MIN, REFRESH_TAU·n_overwritten, REFRESH_KAPPA·n_voters))`. Saturating arithmetic keeps the count math within u64 | FAIL_REFRESH |
| 4.5.3 | Every entry is UPDATE with `!is_old0` and `old_key == new_key`, key in ballot namespace `[0x10, 2^63)` (upper limbs zero); keys strictly increasing across the chain; no refresh key equals any `ballot_chain[i].new_key` | FAIL_REFRESH |
| 4.5.4 | Refresh chain roots chain: `refresh[0].old_root == last_ballot.new_root` (or `last_voteid.new_root` / `OldStateRoot` when earlier chains are empty), `refresh[N-1].new_root == results.old_root` (or `NewStateRoot` when no Results transition); each entry is a valid Processor transition | FAIL_REFRESH |
| 4.5.5 | For each `j`: `SHA-256(serialize(refreshed_ballots[j])) == refresh_chain[j].old_value` | FAIL_REFRESH |
| 4.5.6 | For each `j`: `SHA-256(serialize(refreshed_new[j])) == refresh_chain[j].new_value`, where `refreshed_new[j]` is the guest-computed re-encryption of `refreshed_ballots[j]` using the next chain elements (see §4.3) | FAIL_REFRESH |
| 4.5.7 | Every `refreshed_ballots[j]` has TE identity in padded slots `i ≥ num_fields` (mirrors §4.3.4) | FAIL_REFRESH |
| 4.5.8 | Output register 42 (`OccupiedBefore`) equals the STATETX `occupied_before` (u32 truncation). Overflow of u32 sets FAIL_REFRESH | FAIL_REFRESH |
| 4.5.9 | `refreshed_ballots.len() == refresh_chain.len()` (and the guest-computed `refreshed_new` has the same count). Checked before anything else in 4.4, so a refresh chain without ballot data cannot pass as an empty batch | FAIL_REFRESH |

The fold guest cross-checks register 42 against its running
`total_voters − total_overwrites` per batch, and the settlement contract
against the process's `voteCount − overwrittenCount`, so a batch that lies
about its tree size fails there even if it passes here.

---

## 8. Phase 5: Data Availability

**Module:** `kzg.rs`, `circuit-primitives/src/da_blob.rs`
**Fail bits:** `FAIL_KZG` (bit 18)

Runs **after** §4.2 (SMT chains), §4.3 (re-encryption) and §4.4 (result
accumulator): it needs the state chains, the guest-computed `refreshed_new`
ballots and the NEW net accumulator that §4.4 returns.

### Purpose

Bind the sequencer's DA-blob commitments to what the circuit has just proved.
Blob cells are not host input: the guest rebuilds them from verified state
(vote-id list, sorted slot updates covering new votes, overwrites and silent
refreshes alike, and the NEW net accumulator), packs them into 4096-cell
EIP-4844 blobs, and evaluates each blob polynomial at the point derived from
that blob's commitment. The emitted `BlobsDigest` (§3) hashes the ordered
`(commitment, y)` pairs; the settlement contract checks each pair against the
blob's versioned hash via the EIP-4844 point-evaluation precompile.

The KZG block itself carries only the process context and the per-blob
commitments (see §2 KZGBLK). Absent KZG block or absent STATETX: trivially
pass with `BlobsDigest = 0` and `NBlobs = 0`.

### Cell layout

Cells are 32-byte big-endian BLS12-381 Fr elements. Encoders:

- `enc_u64(v)` = `v` as a 32-byte big-endian integer (top 24 bytes zero).
- `pack(x, y)` = `y_canon + ((x_canon & 1) << 254)`, where `x_canon`,
  `y_canon` are the BabyJubJub coords reduced mod BN254 Fr. Fits in
  BLS12-381 Fr since `p_bn254 + 2²⁵⁴ < r_bls`; BN254 Fr `< 2²⁵⁴`, so bit 254
  of `y_canon` is 0 (no collision with the parity tag). The TE identity
  `(0, 1)` packs to the integer `1`.

Layout in cell order:

```
enc_u64(n_vids)
enc_u64(vid_0) .. enc_u64(vid_{n_vids-1})               // ascending
enc_u64(n_updates)
for each (key, ballot) update, ascending by key (stable):
    enc_u64(key)
    pack(c1_0) pack(c2_0) .. pack(c1_{nf-1}) pack(c2_{nf-1})
for f in 0..nf:
    pack(acc_c1_f) pack(acc_c2_f)                       // NEW net accumulator
zero cells to end of last blob
```

Where:

- Vote ids come from `state.vote_id_chain[*].new_key[0]` (the upper limbs
  are zero by 4.1.4b), sorted ascending.
- Updates cover EVERY slot the batch touched: first the ballot-chain entries
  (in ballot-chain order, ballot = `state.voter_ballots[i]`), then the
  refresh-chain entries (in refresh-chain order, ballot = `refreshed_new[j]`
  as re-encrypted in §4.3/§4.5). The combined list is then stable-sorted by
  `key = transition.new_key[0]`, so an on-chain reader sees one uniform
  sorted list and cannot tell a new vote, an overwrite and a silent refresh
  apart. `nf = num_fields` from the BallotMode config; padded fields
  `f ≥ nf` are not emitted (soundness rests on §4.3.4 / §4.5.7 pinning
  them to the TE identity).
- The accumulator pack cells carry the NEW net Results ballot
  (`OldResults + Σ voter_ballots − Σ overwritten + refresh_delta` from §4.4).

Cell count:

```
T = 2 + n_vids + n_updates · (1 + 2·nf) + 2·nf
n_blobs = ceil(T / 4096)          // 1 ≤ n_blobs ≤ MAX_BLOBS = 32
```

### Evaluation point derivation

Per blob `b`, `com_b = commitments[b]` (48 B big-endian):

```
z_b = SHA-256( processID_BE32 ‖ rootHashBefore_BE32 ‖ com_b ) mod r_bls   // BLS12-381 Fr
```

`processID` and `rootHashBefore` are the KZG block's copies, bound to the
STATETX by 6.1 and 6.2. Every blob evaluated by the guest is bound to the same
election and the same `root_hash_before`, so a commitment for a different
election or a different state root is unusable.

### Barycentric evaluation

Standard EIP-4844 / go-eth-kzg convention. For each blob, the 4096 cells are
identified with the values `d_i = blob[i]` at the 4096th roots of unity
`ω_i = ω^{bitreverse(i)}`, and:

```
y_b = (z_b^N − 1) / N · Σ_i (d_i · ω_i / (z_b − ω_i))                    // N = 4096
```

with the direct-lookup shortcut when `z_b == ω_k` for some `k`. All BLS12-381
Fr arithmetic uses the ZisK `arith256_mod` precompile and a single 4096-entry
batch inverse. Field inverses come from a host hint checked with one
multiplication; a wrong hint aborts the run (a zero inverse would zero every
evaluation).

### Digest

```
digest = SHA-256( com_0 ‖ y_0_BE32 ‖ com_1 ‖ y_1_BE32 ‖ ... ‖ com_{n_blobs-1} ‖ y_{n_blobs-1}_BE32 )
```

Emitted at registers [28..35] as 8 × u32 LE; `NBlobs` at [36].

### Constraint checks

| # | Check | Fails on |
|---|-------|----------|
| 5.1 | KZG block absent (or STATETX absent): Phase 5 short-circuits with digest = 0, NBlobs = 0. The chained-mode path relies on that; STATETX absence is caught by the rest of the pipeline (`FAIL_MISSING_BLOCK`) so Phase 5 does not double-count it | — |
| 5.2 | `1 ≤ n_blobs ≤ MAX_BLOBS = 32` (above the cap is already a parse failure, §2) | FAIL_KZG |
| 5.3 | `n_blobs == ceil(T / 4096)`, with T from the reconstructed cell count. Under- or over-commitment forbidden | FAIL_KZG |
| 5.4 | For every `b`: `y_b = eval_barycentric(cells_b, z_b)` where `z_b = SHA-256(pid_BE32 ‖ root_before_BE32 ‖ com_b) mod r_bls`. Emitted BlobsDigest = SHA-256 of the ordered `(com_b, y_b)` pairs | — |

On `FAIL_KZG` the digest registers stay zero and `NBlobs` carries the number of
commitments shipped. Check 5.4 has no fail bit: the guest evaluates and commits
to `(com, y)`; the settlement contract does the KZG opening check against the
blob-tx versioned hash. A wrong commitment shows up on-chain as a mismatched
point-evaluation result, not as a `FAIL_KZG` bit.

### Security rationale

- **No unbound blob bytes.** Every cell is reconstructed from data already
  bound by earlier phases (SMT chains, ballot leaf hashes, net-Results leaf
  and refresh checks). A malicious sequencer cannot smuggle extra cells or
  swap contents without breaking one of those.
- **Uniform update stream.** Overwrites, new votes and silent refreshes go
  through the same sort key. The public DA layout does not distinguish them,
  matching the deniability property from §4.5.
- **Per-blob binding.** `z_b` folds in the commitment and the process
  context, so a commitment for the wrong election / wrong `root_before`
  produces a `y` no honest KZG opening can hit; the digest changes and
  the on-chain check fails.
- **BLS12-381 Fr fit.** `p_bn254 + 2²⁵⁴ < r_bls`, so `pack(x, y)` always
  lands inside the BLS Fr range. The parity tag lives in bit 254; BN254 Fr
  `< 2²⁵⁴` keeps `y_canon` clear of it.

### Performance note

Each blob costs roughly 25k–33k `arith256_mod` calls, depending on how many
cells are non-zero: the 4096-entry root-of-unity table (rebuilt per blob), the
4096 differences, the batch inverse (the largest part, ~12k) and the weighted
sum. Small transitions fit in one blob. `MAX_BLOBS = 32` (131072 cells) is
above the largest valid transition (1024 votes, 2048 refreshes, 16 fields:
T = 102434, 26 blobs); a 1024-vote batch with 1024 refreshes at 16 fields
needs 17.

---

## 9. Phase 6: Cross-Block Binding

**Module:** `main.rs` (Phase 6 section)  
**Fail bits:** `FAIL_BINDING` (bit 22)

### Purpose

The input contains independently-parsed binary blocks (Groth16, STATETX,
CENSUS or CSPBLK, REENCBLK, KZGBLK). Each block carries its own copy of shared
values. An attacker could provide a valid KZG commitment for a *different*
election or a *different* state root if these copies are not cross-checked.
This phase enforces that all blocks agree on the same context and that
per-voter data is correctly bound across blocks.

### Constraint checks

| # | Check | Description | Fails on |
|---|-------|-------------|----------|
| 6.1 | `kzg.process_id == state.process_id` | KZG blob bound to correct election | FAIL_BINDING |
| 6.2 | `kzg.root_hash_before == state.old_state_root` | KZG blob bound to correct state | FAIL_BINDING |
| 6.3 | `SHA-256(reenc_pubkey_X_BE32 ‖ reenc_pubkey_Y_BE32) == process_proofs[2].new_value` | Re-encryption key matches process config (key 0x03) | FAIL_BINDING |
| 6.4 | Eligibility proof count == `state.n_voters` | One eligibility proof per voter (Merkle or CSP) | FAIL_BINDING |
| 6.5 | `reenc_entries.len() == state.n_voters` | One re-encryption entry per voter | FAIL_BINDING |
| 6.6 | For each voter `i`: address from eligibility proof matches the low 160 bits of `proofs[i].public_inputs[0]` | Eligibility bound to the specific voter | FAIL_BINDING |
| 6.7 | `SHA-256(VK wire bytes) == process_proofs[4].new_value` | Groth16 VK matches process config (key 0x07); the VK is fixed for the process lifetime | FAIL_BINDING |
| 6.8 | If `n_voters > 0`: `proofs.len() == n_voters`, `n_public ≥ 3`, `reenc_entries.len() == n_voters`, `voter_ballots.len() == n_voters`, 5 process proofs and a REENCBLK key present | Preconditions of 6.9/6.10; ties the Groth16 proof count to `n_voters` | FAIL_BINDING |
| 6.9 | For each voter `i`: `inputsHash(i) == proofs[i].public_inputs[2]` (below) | Original ciphertexts bound to the voter's ballot proof | FAIL_BINDING |
| 6.10 | For each voter `i`: `reenc_entries[i].reencrypted == state.voter_ballots[i]` (all 16 ciphertexts, raw coords) | SMT ballot leaf and accumulator bound to the verified re-encryption | FAIL_BINDING |

6.1 and 6.2 apply when a KZG block is present. 6.3 and 6.7 apply when there
are exactly 5 process proofs (otherwise 4.2.P1 has already failed). 6.6
compares the first `min(n_voters, eligibility count, proofs)` voters and needs
`n_public ≥ 1`. 6.9 and 6.10 stop at the first mismatch.

### Ballot inputs hash

```
in[0..71] = processID, ballotMode, pk.x, pk.y, pubs[0], pubs[1],
            original[0].c1x, c1y, c2x, c2y, …, original[15].c2y, weight
inputsHash = poseidon5( p16(in[0..16]), p16(in[16..32]), p16(in[32..48]),
                        p16(in[48..64]), p7(in[64..71]) )
```

This is davinci-node's `BallotInputsHash` (`PoseidonMultiHash` over 71 inputs,
16-wide chunks). `processID` is the STATETX value, `ballotMode` the key 0x02
leaf value, `pk` the REENCBLK key as shipped. The weight is the low 88 bits of
the census leaf in Merkle mode and `CspEntry.weight` in CSP mode.

### Eligibility address extraction

**Merkle mode** (censusOrigin 1-3): The census leaf is `(address << 88) | weight`.
The address is extracted by right-shifting 88 bits.

**CSP mode** (censusOrigin 4): The `CspEntry.voter_address` field contains the
voter's Ethereum address directly as uint160 in FrRaw. The lower 3 limbs (160 bits)
are compared against the ballot proof's `public_inputs[0]`.

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
    && state_ok        // Phase 4.2 (and the 4.5 chain checks)
    && reenc_ok        // Phase 4.3 (and the 4.5 re-encryption)
    && results_ok      // Phase 4.4
    && kzg_ok          // Phase 5
    && binding_ok      // Phase 6
```

The `occupied_before` overflow bit (4.5.8) is set just before the verdict, so
it feeds both `overall_ok` and the mask.

**All phases must pass** for `overall_ok = 1`. The `fail_mask` provides granular
failure information for debugging; checks within a phase often stop at the
first failure, so the mask is not an exhaustive list of violated rules. A
proof with `overall_ok = 0` is invalid and must be rejected by the verifier.

---

## 11. Fail-Mask Reference

| Bit | Constant | Module | Meaning |
|-----|----------|--------|---------|
| 1 | `FAIL_CURVE` | groth16.rs | Proof/VK point off-curve or the identity, or β/γ/δ outside the G2 subgroup (1.1–1.4) |
| 2 | `FAIL_PAIRING` | groth16.rs | Batch pairing equation failed |
| 3 | `FAIL_ECDSA` | ecdsa.rs | Signature entries missing, voteID not u64, key recovery failed or address binding failed (2.1–2.6) |
| 10 | `FAIL_SMT_VOTEID` | smt.rs | VoteID insertion chain invalid |
| 11 | `FAIL_SMT_BALLOT` | smt.rs | Ballot insertion/update chain invalid |
| 12 | `FAIL_SMT_RESULTS` | smt.rs | Net Results SMT transition invalid or not an UPDATE of key 0x04 |
| 13 | `FAIL_SMT_PROCESS` | smt.rs | Process config read-proof invalid or missing |
| 14 | `FAIL_CONSISTENCY` | consistency.rs | VoteID namespace, upper limbs or proof binding mismatch (4.1.2–4.1.4b) |
| 15 | `FAIL_BALLOT_NS` | consistency.rs | Ballot namespace, upper limbs, slot binding (4.1.6) or duplicate slot in the batch (4.1.7) |
| 16 | `FAIL_CENSUS` | census.rs | Census roots differ, duplicate leaf, non-canonical shape or invalid path (3A.2–3A.5) |
| 17 | `FAIL_REENC` | babyjubjub.rs / main.rs | Election key invalid, re-encryption mismatch, padded slot not identity, or `num_fields` out of range (4.3.2–4.3.6) |
| 18 | `FAIL_KZG` | kzg.rs | Blob count zero or not `ceil(T / 4096)` (5.2, 5.3) |
| 19 | `FAIL_MISSING_BLOCK` | various | STATETX, REENCBLK, or the census block `censusOrigin` selects is absent or empty |
| 20 | `FAIL_RESULT_ACCUM` | results.rs | Net Results leaf mismatch, Results transition missing or unexpected, or padded slot not identity (4.4.5–4.4.9) |
| 21 | `FAIL_LEAF_HASH` | results.rs | Ballot SMT leaf hash or ballot count mismatch (4.4.1–4.4.4) |
| 22 | `FAIL_BINDING` | main.rs | Cross-block binding mismatch (6.1–6.10) |
| 23 | `FAIL_CSP` | csp.rs | CSP block empty, entry non-canonical, duplicated, or its key recovery failed or disagreed (3B.2–3B.4) |
| 24 | `FAIL_REFRESH` | smt.rs / babyjubjub.rs / results.rs / main.rs | Silent-refresh chain over the cap (§4.5.1), count rule (§4.5.2), per-entry format / disjointness (§4.5.3), root chaining (§4.5.4), leaf-hash pin (§4.5.5–§4.5.6), padded-slot identity (§4.5.7), `occupied_before` overflowed the 32-bit output register (§4.5.8), or refresh ballot count mismatch (§4.5.9) |
| 31 | `FAIL_PARSE` | io.rs | Binary format / parse error (§2) |

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

Every voter has a valid eligibility proof:
- **Merkle mode** (censusOrigin 1-3): valid lean-IMT Poseidon inclusion proof in the census tree.
- **CSP mode** (censusOrigin 4): valid ECDSA signature from the CSP authority.

The eligibility address is bound to the ballot proof address (Phase 6.6),
preventing reuse of eligibility proofs across voters. In Merkle mode, no
duplicate census leaves exist within a batch. In CSP mode, no two entries
share a `voter_address` or an `index`. In both modes a batch writes each
ballot slot at most once (4.1.7).

### 12.4 State Integrity

The state tree evolves through a valid chain of SMT transitions from
`OldStateRoot` to `NewStateRoot`. VoteIDs are insert-only (no overwrites or
deletes). Ballot entries are insert or update only. Refresh entries are
updates of distinct ballot slots the batch did not write. The Results leaf
changes only through an update of key `0x04`. The transition chain is
contiguous with no gaps.

### 12.5 Process Binding

The process configuration (ProcessID, BallotMode, EncryptionKey, CensusOrigin,
BallotVKHash) is read from the state tree at `OldStateRoot` and verified via
SMT inclusion proofs. The processID matches the state block header. The
encryption key matches the re-encryption public key, and the ballot VK hash
matches the Groth16 VK in the input. The KZG blob is bound to the same
processID and state root.

### 12.6 Vote Privacy

Ballots are re-encrypted before storage with per-ciphertext offset scalars
derived in-guest from a single sequencer-private, batch-scoped seed and the
STATETX `old_root` (SHA-256 chain, one element per active ciphertext,
threaded across all voters). The re-encryption is verified to be correct
(`original + EncryptedZero = reencrypted`); the election public key used for
`EncryptedZero` matches the encryption key stored in the process
configuration. Because every chain element is consumed exactly once and
`old_root` differs across transitions, no offset scalar can repeat within or
across transitions. Scalar reuse, which would let anyone holding two
originals link them to their stored ciphertexts, is impossible by construction.

### 12.7 Tally Correctness

A single net result accumulator (`Results`, key `0x04`) is verified to equal
`OldResults + Σ(voter ballots) − Σ(overwritten ballots) + refresh_delta`, the
homomorphic net tally (the refresh delta is an encryption of zero per active
field). Ballot leaf hashes bind the serialized ballot data to the SMT leaf
values, preventing substitution.

### 12.8 Data Availability

Blob cells are rebuilt in-guest from verified state (vote-id list, sorted
slot updates covering new votes, overwrites and silent refreshes, and the
NEW net accumulator). Each blob polynomial is evaluated at
`z_b = SHA-256(pid ‖ root_before ‖ com_b) mod r_bls` and the ordered
`(com_b, y_b)` pairs are hashed into `BlobsDigest`. The settlement contract
verifies each `(com_b, y_b)` against the blob-tx versioned hash via the
EIP-4844 point-evaluation precompile, so an unavailable or tampered blob is
rejected on-chain even though the guest itself does no BLS12-381 pairings.

---

## 13. Known Limitations

### 13.1 Ballot-to-Re-encryption Binding

The ballot proof's public inputs are `[address, voteID, inputsHash]`; the
ciphertexts themselves are not public inputs of the Circom circuit. Phase 6
closes the gap: the guest recomputes `inputsHash` as the Poseidon commitment
over `(processID, ballotMode, encKey, address, voteID, the 16 original
ciphertexts, weight)` and requires it to equal `public_inputs[2]` (6.9), which
binds `reenc_entries[i].original` to the proven ballot. It then requires
`reenc_entries[i].reencrypted` to equal `state.voter_ballots[i]` (6.10), which
binds the SMT ballot leaf and the results accumulator to the verified
re-encryption. A sequencer cannot pair a valid proof with a different
ballot, nor store anything but the chain-derived re-encryption of it.

### 13.2 BabyJubJub Cofactor

The BabyJubJub curve has cofactor 8. The election key must be on the curve,
not the identity and in the prime-order subgroup (`l · pk == identity`,
§4.3.2 and §4.3.2b), checked before any offset scalar is consumed; 6.3 binds
it to the process configuration. Ciphertext points are not curve-checked in
this guest: originals are bound to the ballot proof (6.9), and stored and
refreshed ballots to their SMT leaves.

### 13.3 KZG Opening Proof

The guest evaluates each blob polynomial (`y_b = eval(cells_b, z_b)`) but
does not verify the KZG opening proof itself (which requires BLS12-381
pairings unavailable as precompiles).

**Mitigation:** The emitted `BlobsDigest` binds each `(com_b, y_b)` pair.
The settlement contract feeds every pair to the EIP-4844 point-evaluation
precompile against the blob-tx versioned hash, so an opening that does not
match the on-chain blob is rejected there.

### 13.4 CSP Census — Revocation

CSP credential revocation is not implemented: once the CSP signs a voter's
eligibility, it cannot be revoked within the circuit. Revocation would need
to be handled at the application layer (e.g., by not including the voter
in subsequent batches).

### 13.5 Blob Content Verification

The KZG block carries no blob bytes: the guest rebuilds the cells from
verified state (vote-id list, sorted slot updates covering new votes,
overwrites and silent refreshes, and the NEW net accumulator) and evaluates
each blob polynomial itself (§8). The only host-chosen values are the
commitments, which the settlement contract checks against the blob versioned
hashes (13.3).

### 13.6 Checks Left to the Verifier

The guest proves a transition from whatever `OldStateRoot` and census it is
given. The consumer (settlement contract in per-batch mode, fold guest in
chained mode) must also check:

- the proof under the pinned vote-batch program vk, `overall_ok == 1` and
  `fail_mask == 0`;
- `RootHashBefore` equals the process's last root;
- `CensusRoot` equals the process census root (the Merkle root, or the CSP
  address);
- `OccupiedBefore` equals the running `voters − overwrites`;
- in per-batch mode, `NBlobs ≥ 1` and every `(com_b, y_b)` against its blob's
  versioned hash.

---

## 14. Cryptographic Primitives

| Primitive | Module | Implementation | Notes |
|-----------|--------|---------------|-------|
| SHA-256 | `hash.rs` | `zisklib::sha256` on the `sha256f` precompile | SMT, leaf hashes, transcripts, offset chain |
| Keccak-256 | `hash.rs` | `zisklib::keccak256` on the `keccak_f` precompile | ECDSA envelope, Ethereum address |
| BN254 Groth16 pairing | `circuit/src/groth16.rs` | `zisklib::pairing_batch_bn254` | Multi-pairing |
| BN254 G1 MSM | `circuit/src/groth16.rs` | `zisklib::scalar_mul_bn254`, `add_bn254` | In-guest random linear combination |
| BN254 G1/G2 curve checks | `bn254.rs` | `zisklib::is_on_curve_bn254`, `is_on_curve_twist_bn254`, `is_on_subgroup_twist_bn254` | Identity rejected separately |
| secp256k1 ECDSA | `circuit/src/ecdsa.rs`, `circuit/src/csp.rs` | `zisklib::ecdsa_recover_secp256k1` | Public-key recovery |
| BN254 Fr arithmetic | `bn254_fr.rs` | ZisK `arith256_mod` precompile (syscall 0x802) | `(a·b+c) mod p` |
| BLS12-381 Fr arithmetic | `bls_fr.rs` | ZisK `arith256_mod` precompile (syscall 0x802) | `(a·b+c) mod p`; inverse = checked host hint |
| Poseidon (iden3, BN254) | `poseidon.rs` | Software (bn254_fr precompile for field ops) | t=3 (8 full + 57 partial rounds) for the census; t=17/8/6 for the inputs hash |
| BabyJubJub | `babyjubjub.rs` | `babyjubjub_add` precompile (syscall 0x81D), affine | Twisted Edwards; curve check on bn254_fr |
| Arbo SMT | `smt.rs` | Software (SHA-256 precompile for hashing) | Circomlib Processor + Verifier |

> Modules without a `circuit/src/` prefix live in the shared
> `circuit-primitives` crate, used by the vote-batch guest (`circuit/`), the
> recursive aggregator (`circuit-aggregator/`) and the results guest
> (`circuit-results/`); their paths are relative to that crate's `src/`.

---

## 15. Performance Optimizations

SHA-256 (one `sha256f`-backed call per hash) and BabyJubJub point additions
dominate the circuit's step count. The optimizations below change when work
happens, not what is checked.

### 15.1 SMT node-hash skip on padding levels (`smt.rs`)

The host pads SMT proofs to the 64 levels of the tree, but the real depth is
only ~log₂(N). On the "not-applicable" levels below the insertion point the
reconstructed node hash is discarded by the state machine, so
`processor_level` computes the `node_hash` SHA-256 only inside the
`stTop | stBot | stNew1` guard and skips it otherwise. This elides the large
majority of node hashes per transition.

### 15.2 SMT lazy leaf hashing (`smt.rs::verify_transition`)

`leaf_hash(old)` and `leaf_hash(new)` are each a SHA-256, but `processor_level`
only consumes `old1leaf` when some level is `bot | new1 | upd`, and `new1leaf`
when some level is `new1 | old0 | upd`. The two hashes are computed lazily,
after the per-level state machine has run, only when a consuming state actually
fires. `is_old0` INSERTs (the VoteID leaves) elide the old-leaf hash; NOOP
transitions elide both. Inputs are identical whenever a hash is consumed, so
the result is unchanged.

### 15.3 Affine re-encryption with fixed-base tables (`babyjubjub.rs`)

Points stay in affine coordinates: every add is one `babyjubjub_add`
precompile call (complete twisted-Edwards law, so doubling is `add(P, P)`),
with no projective `Z` and no field inversion, and re-encryption equality is
a direct coordinate compare against the precompile's canonical output.
`r · B8` uses a compile-time 8-bit window table (`b8_table.rs`, 32 × 255
affine points), at most one add per non-zero window. The election key's table
is built once per batch: 4-bit windows (64 × 15 points, ~1.2k adds to build)
below 256 expected multiplications, 8-bit windows (32 × 255 points, ~8.4k
adds) from 256 up, where expected = (entries + refreshes) × `num_fields`.
Neither table nor the subgroup check (`l · pk` by double-and-add) runs when a
batch has no re-encryption entries and no refreshes.

### 15.4 Padded-field skips

Fields `i ≥ num_fields` skip the re-encryption and refresh EC work (4.3.4,
4.5.7), the accumulator adds (4.4.9) and the DA pack cells (§8). In the inputs
hash (§9), a 16-input chunk made only of padded coordinates is replaced by the
constant `poseidon16([0, 1, 0, 1, …])`. Each skip is sound only because the
padded slots are asserted to be the identity.

### 15.5 Groth16 MSM (`groth16.rs`)

The γ-side term is aggregated across proofs (§4), so a batch needs
`n_public + 1` scalar muls on γ_abc instead of `n·(n_public + 1)`. The batch
coefficients are 128-bit, and `scalar_mul_bn254` starts at the scalar's MSB,
so the per-proof `r_i·A_i` and `r_i·C_i` muls cost about half of a full-width
mul.
