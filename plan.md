# DAVINCI ZkVM — Implementation Plan

## Goal

Replace the 3 Gnark circuits (VerifierCircuit/BLS12-377 + AggregationCircuit/BW6-761 +
StateTransitionCircuit/BN254) with a single ZisK RISC-V circuit.
The Circom BallotCircuit (BN254, voter-side) remains unchanged.

---

## Architecture

```
Circom BallotCircuit  (BN254, run by voter)
    │  60 Groth16 proofs + 60 ECDSA sigs
    ↓
davinci-zkvm HTTP API  ←  davinci-node sequencer
    │
ZisK Guest Circuit (RISC-V)
    │  1. 60 Groth16 BN254 batch verify     ✅ done
    │  2. 60 ECDSA secp256k1 sigs            ✅ done
    │  3. Arbo SHA-256 SMT (voteID chain)    ✅ basic done
    │  4. Arbo SHA-256 SMT (ballot chain)    Step 2
    │  5. Process config read-proofs         Step 5
    │  6. lean-imt Poseidon census proof     Step 7
    │  7. BabyJubJub ElGamal re-encryption   Step 6
    │  8. KZG blob commitment                SKIP (no BLS12-381 in ZisK)
    ↓
ZisK STARK proof  →  (future: zkSNARK via FFLONK/PLONK)
```

---

## Protocol Constants (from davinci-node/spec/params)

| Constant | Value |
|---|---|
| VotesPerBatch | 60 |
| FieldsPerBallot | 8 |
| StateTreeMaxLevels | 64 |
| MaxCensusDepth | 24 |
| VoteIDMin | 0x8000_0000_0000_0000 |
| BallotMin | 0x10 |

---

## State Tree (Arbo SHA-256, MaxLevels=64)

Key namespaces (uint64):
- `[0x00, 0x0F]` Config: processID=0x0, ballotMode=0x2, encKey=0x3, resultsAdd=0x4, resultsSub=0x5, censusOrigin=0x6
- `[0x10, 0x7FFF_FFFF_FFFF_FFFF]` Ballots: `BallotMin + (censusIdx << 16) + (address & 0xFFFF)`
- `[0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF]` VoteIDs: `VoteIDMin + (Poseidon(processID, address, k) & 63bits)`

---

## Circuit Outputs

| Index | Meaning |
|---|---|
| 0 | overall_ok (1=all pass) |
| 1 | fail_mask (bitmask of failures) |
| 7 | groth16_batch_ok |
| 8 | ecdsa_ok |
| 9 | smt_ok (1=valid, 0=fail, 2=absent) |
| 10-11 | old_state_root (lo/hi u64) |
| 12-13 | new_state_root (lo/hi u64) |
| 14 | voters_count |
| 15 | overwritten_count |

---

## Binary Input Format

```
Header : magic(u64="GROTH16B") log_n(u64) nproofs(u64) n_public(u64)
VK     : alpha_g1 beta_g2 gamma_g2 delta_g2 gamma_abc_len gamma_abc[...]
Proofs : nproofs [a b c pubs[...]] × nproofs
Hints  : scaled_a[...] neg_alpha_rsum neg_g_ic neg_acc_c
ECDSA  : [r s px py](FrRaw each) × nproofs
SMTBLK : [optional, legacy] magic="SMTBLK!!" n_transitions n_levels [transitions...]
STATETX: [optional] magic="STATETX!" → full state-transition block (see below)
```

### STATETX block format

```
magic:             u64 = "STATETX!"
n_voters:          u64
n_overwritten:     u64
process_id:        FrRaw
old_state_root:    FrRaw
new_state_root:    FrRaw
// VoteID chain (n_voters transitions)
vote_id_n:         u64
vote_id_n_levels:  u64
[SmtTransition × vote_id_n]
// Ballot chain (n_voters transitions)
ballot_n:          u64
ballot_n_levels:   u64
[SmtTransition × ballot_n]
// ResultsAdd (0 or 1)
has_results_add:   u64
results_n_levels:  u64
[SmtTransition × has_results_add]
// ResultsSub (0 or 1)
has_results_sub:   u64
[SmtTransition × has_results_sub]  // same n_levels as results_add
// Process read-proofs (exactly 4)
process_n_levels:  u64
[SmtTransition × 4]  // order: processID, ballotMode, encKey, censusOrigin
```

Each `SmtTransition`:
```
old_root, new_root, old_key, old_value : FrRaw each (LE word order)
is_old0, new_key, new_value, fnc0, fnc1 : u64 each (0/1)
siblings[n_levels] : FrRaw each
```

---

## Implementation Steps

### ✅ Done
- Groth16 BN254 batch verifier (Fiat-Shamir)
- secp256k1 ECDSA verify + Ethereum address binding
- Arbo SHA-256 SMT single-insert verifier
- Go SDK, HTTP service, integration tests
- **Step 1: Wire format extension (STATETX block)**
  - `go-sdk/types.go`: added `StateTransitionData` struct with all chain fields; `ProveRequest.State`
  - `go-sdk/encode.go`: `EncodeStateBlock()` Go helper for binary encoding
  - `service/src/types.rs`: added `StateTransitionJson` mirroring Go types
  - `service/src/api/prove.rs`: serializes `state` → `write_state_block()` when present
  - `input-gen/src/lib.rs`: added `StateData` + `write_state_block()` with helpers
  - `circuit/src/types.rs`: added `StateBlock` struct + `STATE_MAGIC`
  - `circuit/src/io.rs`: parses STATETX block; `ParsedInput.state: Option<StateBlock>`
  - `circuit/src/smt.rs`: added `verify_chain()` + `verify_state()` (outputs 10-15)
  - `circuit/src/main.rs`: wires `verify_state()`, outputs 10-15
  - `circuit/elf/circuit.elf`: rebuilt (312520 bytes)
  - `plan.md`: written to repository

### Step 1 — Wire format extension (STATETX block) [TODO]
- `go-sdk/types.go`: add `StateTransitionData` struct, field `State *StateTransitionData` in ProveRequest
- `service/src/types.rs`: mirror new JSON types
- `input-gen/src/lib.rs`: `write_state_block()` serializer
- `circuit/src/types.rs`: `StateBlock` struct
- `circuit/src/io.rs`: parse STATETX magic → `ParsedInput.state`
- `circuit/src/main.rs`: outputs 10-15

### Step 2 — Chained SMT verifier [TODO, depends: Step 1]
- `circuit/src/smt.rs`: `verify_chain(transitions, old_root, new_root) -> bool`
- Wire up voteID chain + ballot chain + results chains in main.rs
- Test: `TestChainedSMT` — 5 arbo SHA-256 inserts

### Step 3 — Ballot-VoteID consistency + namespace [TODO, depends: Step 2]
- For vote i: `pubs[i][1] == VoteIDSmt[i].new_key` (as u64)
- `BallotSmt[i].new_key` encodes `BallotMin + (censusIdx<<16) + (addr & 0xFFFF)`
- VoteID key ≥ VoteIDMin (`0x8000_0000_0000_0000`)
- Test: `TestVoteIDConsistency`, `TestVoteIDRange`

### Step 4 — Process params read-proofs [TODO, depends: Step 2]
- Verify 4 config entries exist in OldStateRoot (fnc0=0, fnc1=0 read proofs)
- Keys: 0x0, 0x2, 0x3, 0x6
- Test: `TestProcessParams`

### Step 5 — Poseidon BN254 in Rust [DONE]
- `circuit/src/poseidon.rs`: iden3-compatible 2-input Poseidon (BN254, pure Rust)
- Constants extracted from go-iden3-crypto v0.0.17 (t=3 slice)
- Tested via TestCensusProofEmulator (output[0]=1 confirms correctness)

### Step 6 — BabyJubJub + ElGamal re-encryption [TODO, depends: Step 5]
- `circuit/src/babyjubjub.rs`: twisted Edwards over BN254 Fr (a=168700, d=168696)
  - `bjj_add`, `bjj_double`, `bjj_scalar_mult`, `bjj_generator`
  - `verify_reencryption()`: for each ballot field, `newC1=C1+k'*G`, `newC2=C2+k'*P`
- Wire: `ReencryptionK FrRaw`, `ReencryptedBallots[60][8]` ciphertexts
- Extend STATETX binary format: reencryption_k + reencrypted_ballots
- Test: `TestReencryption`

### Step 7 — Census lean-imt Poseidon proof [DONE]
- `circuit/src/census.rs`: lean-imt compatible verifier using poseidon2
- `go-sdk/types.go`: CensusProof type + CensusProofs field in ProveRequest
- `go-sdk/encode.go`: EncodeCensusBlock() + beHexToFrLE() helper
- `circuit/src/io.rs`: CENSUS!! block parser
- `circuit/src/types.rs`: CensusProofEntry + CENSUS_MAGIC constants
- Test: TestCensusProofEmulator — PASSES (output[0]=1)

### Step 8 — Full e2e integration test [TODO, depends: Steps 2-7]
- `go-sdk/tests/statetransition_test.go`:
  - Build arbo SHA-256 state tree with process params
  - Build lean-imt census (Poseidon) with voter addresses
  - 3 real + dummy-padded votes
  - Build full ProveRequest → run via ziskemu
  - Verify output[0]=1, output[9]=1 or 0 depending on checks enabled

---

## File Map

```
circuit/src/
  main.rs       — entry point, wires all verifiers
  io.rs         — binary format parser
  types.rs      — shared type aliases and structs
  groth16.rs    — Groth16 BN254 batch verifier
  ecdsa.rs      — secp256k1 ECDSA + address verify
  smt.rs        — Arbo SHA-256 SMT verifier (+ verify_chain)
  bn254.rs      — BN254 curve arithmetic (precompiles)
  hash.rs       — SHA-256 / keccak256 utilities
  poseidon.rs   — [NEW] iden3 Poseidon BN254 (Steps 5,6,7)
  babyjubjub.rs — [NEW] twisted Edwards + ElGamal re-encrypt (Step 6)
  census.rs     — [NEW] lean-imt Poseidon inclusion proof (Step 7)

go-sdk/
  types.go      — ProveRequest, SmtEntry, StateTransitionData, etc.
  client.go     — HTTP client (WaitForJob, etc.)

input-gen/src/lib.rs — binary serializer (generate_input_bytes)

service/src/types.rs  — JSON API types mirroring go-sdk/types.go
```

---

## Notes

- All arbo field elements are **little-endian** `[u64;4]` (word[0] = least significant 64 bits).
  Go helper: `leHex32ToFrLE()` (direct memcopy, no byte reversal needed).
- lean-imt Poseidon: iden3 `poseidon.Hash([]*big.Int{a, b})` over BN254 Fr.
  Must match iden3's concrete constants (not Vocdoni's MultiPoseidon).
- VotesPerBatch=60 is the protocol constant. The circuit currently handles up to 128
  proofs in the Groth16/ECDSA blocks; for full-protocol mode cap at 60.
- BabyJubJub: pure Rust scalar mult will be slow in ZisK STARK. Accept this for now;
  ZisK team is adding BabyJubJub precompiles in a future release.
- Poseidon in Rust: no precompile → pure field arithmetic, ~57×3 multiplications.
  Acceptable because BabyJubJub scalar mult dominates anyway.
