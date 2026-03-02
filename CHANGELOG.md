# Changelog

All notable changes to davinci-zkvm are documented here.

## Unreleased — Cross-Block Binding Security Checks

### Security

- **Cross-block binding verification** (`circuit/src/main.rs` Phase 6). The circuit now
  verifies that fields shared between protocol blocks are consistent. Previously, each block
  (STATETX, KZGBLK, REENCBLK) was validated independently, allowing an attacker to supply
  a valid KZG commitment for a different processID or state root than the one in the state
  transition. New checks:
  - KZG processID must match STATETX processID
  - KZG rootHashBefore must match STATETX old state root
  - Re-encryption public key must match the encryption key stored in process config (key 0x03)
  - Failure sets `FAIL_BINDING` (bit 22) in the fail mask

- **Process config key/value validation** (`circuit/src/smt.rs`). Process proofs must contain
  exactly 4 entries with keys [0x00, 0x02, 0x03, 0x06] (ProcessID, BallotMode, EncryptionKey,
  CensusOrigin). The processID value (key 0x00) must match the state block header. Previously,
  process proofs were counted but key IDs were not validated.

### Fixed

- **Go-SDK fail-mask constants** (`go-sdk/outputs.go`). Corrected bit shifts: FailCurve was
  `1<<0` but circuit uses `1<<1` (FAIL_CURVE). FailPairing and FailECDSA were similarly off by
  one. Added missing constants: FailMissingBlock (bit 19), FailResultAccum (bit 20),
  FailLeafHash (bit 21), FailBinding (bit 22).

- **KZG/STATETX encoding consistency** (`go-sdk/tests/integration/`). The STATETX block uses
  arbo little-endian hex (parsed by `hex32_to_smt_fr` in Rust), while the KZG block uses
  standard big-endian hex (parsed by `be_hex32_to_fr_le`). Both produce identical FrRaw limbs
  in the circuit. The integration test now correctly uses `processIDArboHex()` for STATETX and
  `ProcessIDHex()` for KZG, with `arboHexToBEHex()` for root conversion.

## Unreleased — Remove Legacy SMT Batch + Mandatory Protocol Blocks

### Breaking Changes

- **Removed legacy SMT batch (SMTBLK)** — The simple SMT batch format that predated the full
  DAVINCI state-transition protocol has been removed entirely. All SMT operations now go through
  the `STATETX!` block format which enforces chained transitions, vote/ballot separation, result
  accumulator verification, and process config proofs. API consumers must use the `State` field
  (not the removed `Smt` field) in `ProveRequest`.

  **Removed across the stack:**
  - Circuit: `SMT_MAGIC`, `FAIL_SMT_BATCH` (bit 9), `verify_batch()`, output slot 42 (smt_ok)
  - Go SDK: `OutputSMTOk`, `FailSMTBatch`, `ProveRequest.Smt`, `ProveRequestBuilder.SetLegacySmt()`
  - Service: `ProveRequestJson.smt`, legacy block encoding path
  - Input-gen: `SMT_MAGIC`, `write_smt_block()`
  - Tests: `TestSMTEmulator`, `smt_service_test.go`, legacy encoding helpers

## Mandatory Protocol Blocks + Circuit Restructure

### Circuit (`circuit/src/`)

- **Mandatory protocol blocks** (`kzg.rs`, `census.rs`, `babyjubjub.rs`, `consistency.rs`,
  `smt.rs`). All verification blocks are now mandatory. Previously, absent blocks returned
  `true` (pass), allowing a proof to succeed without data availability, eligibility, or
  re-encryption verification. Now any missing block sets `FAIL_MISSING_BLOCK` (bit 19) in
  the fail mask and returns `false`. This closes a protocol soundness gap where an attacker
  could omit the KZG blob commitment, census proofs, or re-encryption data and still
  produce a passing proof.

- **Circuit restructured into 5 DAVINCI protocol phases** (`main.rs`). The circuit entry
  point now follows the protocol specification with clear phase annotations:
  1. **Ballot Proof Verification** — Groth16 BN254 batch pairing
  2. **Authentication** — secp256k1 ECDSA (extensible to RSA, BLS, EdDSA)
  3. **Eligibility** — lean-IMT Poseidon census proofs (extensible via censusOrigin)
  4. **State Transition** — consistency + SMT chains + re-encryption
  5. **Data Availability** — KZG blob commitment (mandatory)

- **Compilation bug fixed** (`main.rs`). The `parsed` variable was used before being declared
  (lines 63-65), making the circuit uncompilable. Fixed by reordering to parse input first.

- **New fail-mask constant** (`types.rs`). Added `FAIL_MISSING_BLOCK` (bit 19) to signal
  that a mandatory protocol block is absent from the circuit input.

- **Result accumulator verification** (`results.rs`, new module). Implements the homomorphic
  ballot tally check from the DAVINCI protocol:
  - `NewResultsAdd = OldResultsAdd + Σ(all voter ballots)` (element-wise BN254 Fr addition)
  - `NewResultsSub = OldResultsSub + Σ(overwritten ballots)` (for vote overwrites)
  - Verifies ballot leaf hashes: `SHA-256(serialize(ballot)) == SMT new_value` for each
    voter ballot, binding re-encrypted ballot data to the state tree
  - New fail-mask bits: `FAIL_RESULT_ACCUM` (bit 20) and `FAIL_LEAF_HASH` (bit 21)
  - Each ballot is 32 BN254 Fr field elements (8 ElGamal ciphertexts × 4 coordinates)

- **Extended state block parsing** (`io.rs`, `types.rs`). Added `BallotData` type and
  parsing for the optional ballot proof data section: `OldResultsAdd`, `OldResultsSub`,
  per-voter ballot data, and overwritten ballot data.

### Go SDK (`go-sdk/`)

- **Ballot proof encoding** (`types.go`, `encode.go`). Added `BallotProofData` struct
  and encoding support for the result accumulator binary section.

### Tests (`go-sdk/tests/`)

- **Unit tests updated for mandatory blocks**. Component-specific tests (SMT, census,
  re-encryption, KZG) now verify their component's diagnostic output rather than
  `overall_ok`, since they intentionally omit other protocol blocks. Full end-to-end
  validation with all blocks is handled by integration tests.

- **Result accumulator test** (`statetransition_test.go`, `TestResultAccumulator`). End-to-end
  test that builds deterministic ballot data, computes SHA-256 leaf hashes, inserts into arbo
  with proper LE byte ordering, and verifies the circuit accepts the result accumulation.

## Unreleased — Go SDK Strongly-Typed Integration API

### Go SDK (`go-sdk/`)

- **Strongly-typed converter functions** (`converters.go`). Added native Go types
  (`EcdsaSignature`, `Groth16Proof`, `VerificationKey`, `PublicInput`, `ArboTransition`)
  with custom JSON marshaling that produces the exact format expected by the Rust service.
  Constructor functions accept `*big.Int` values and handle all hex encoding internally:
  `SmtEntryFromArboTransition`, `SmtReadProof`, `CensusProofFromBigInts`,
  `ReencryptionEntryFromBigInts`, `NewReencryptionData`, `NewStateTransitionData`,
  `NewKZGRequest`, `BigIntToHex32BE` (exported).

- **Public outputs parser** (`outputs.go`). Added `ParseOutputs([]uint32)` to decode
  the 46 u32 ZisK output registers into `PublicOutputs` — matching davinci-node's
  `StateTransitionBatchProofInputs`. Added `ABIEncode()` for on-chain uint256[8]
  encoding, `ABIValues()` for go-ethereum integration, `FailString()` for
  human-readable fail mask decoding, and `String()` for one-line summaries.

- **Fluent request builder** (`builder.go`). Added `ProveRequestBuilder` with
  `SetVerificationKey` / `SetVerificationKeyJSON`, `AddProof` / `AddProofJSON`,
  `AddEcdsaSignature`, `SetStateTransition`, `SetCensusProofs`, `SetReencryption`,
  `SetKZG`, and `Build()` with validation. Supports both strongly-typed inputs and
  raw snarkjs JSON pass-through for zero-copy integration.

- **Unit tests** (`converters_test.go`). 19 tests covering all new types, constructors,
  JSON marshaling, builder validation, ABI encoding, fail mask decoding, and edge cases.

## Unreleased — BN254 Fr Precompile Optimization

### Performance

- **BN254 Fr field arithmetic via `arith256_mod` precompile** (`circuit/src/bn254_fr.rs`).
  Created a new module that performs all BN254 Fr field operations (mul, add, sub, inv,
  pow, exp5) using the ZisK `arith256_mod` hardware precompile (`syscall 0x802`).
  Each precompile call computes `(a·b + c) mod p` in a single prover row, replacing
  software Montgomery multiplication that required ~50 RISC-V instructions per operation.

- **Poseidon hash migrated to precompile** (`circuit/src/poseidon.rs`).
  Replaced all `ark_bn254::Fr` operations with `bn254_fr` precompile calls. The `mix()`
  function uses fused multiply-add (`muladd`) to halve the number of precompile calls
  compared to separate mul+add. For 128 voters, Poseidon performs ~80K field multiplications,
  each now a single prover row instead of ~50 rows.

- **BabyJubJub curve migrated to precompile** (`circuit/src/babyjubjub.rs`).
  Replaced all `ark_bn254::Fr` operations with `bn254_fr` precompile calls. BabyJubJub
  scalar multiplication performs ~1M field multiplications for 128 voters, all now
  hardware-accelerated.

- **Groth16 Fiat-Shamir challenge via precompile** (`circuit/src/groth16.rs`).
  Replaced `ArkFr::from_random_bytes` with `bn254_fr::from_random_bytes_32`, eliminating
  an unused `d1` SHA-256 computation (~72 prover rows saved per Groth16 challenge).

- **Removed ark-ff, ark-ec, ark-bn254 dependencies** (`circuit/Cargo.toml`).
  The circuit ELF shrank from 451KB to 365KB (19% reduction). The only remaining
  dependency is `ziskos v0.15.0`.

### Test Fixes

- **TestChainedSMT updated for protocol hardening** (`go-sdk/tests/statetransition_test.go`).
  The test now builds both VoteID and Ballot chains in a single arbo tree with proper
  key namespaces, matching the protocol's chain-length validation requirements added
  in the security audit.

## Security Audit & Protocol Hardening

### Security Fixes

- **Service: eliminated panic on malformed re-encryption data** (`service/src/api/prove.rs`).
  The re-encryption ciphertext parsing used `unwrap()` inside `std::array::from_fn`,
  which would crash the service process on invalid hex input instead of returning
  a proper 400 Bad Request error. Replaced with explicit error propagation via
  `with_context`.

- **Service: removed `unwrap()` on JSON serialization** (`service/src/api/prove.rs`).
  The prove endpoint used `serde_json::to_value(...).unwrap()` when constructing the
  response. Replaced with `serde_json::json!` macro which is infallible.

### Protocol Hardening (circuit)

- **VoteID chain: enforce INSERT-only transitions** (`circuit/src/smt.rs`).
  Every voteID transition must be an INSERT (`fnc0=true, fnc1=false`). VoteIDs are
  unique identifiers that must never be updated or deleted. Previously the circuit
  accepted any valid SMT transition in the voteID chain.

- **Ballot chain: enforce INSERT or UPDATE only** (`circuit/src/smt.rs`).
  Ballot transitions must be either INSERT (new voter) or UPDATE (overwrite).
  DELETE and NOOP transitions are now explicitly rejected.

- **Validate `n_voters` against actual chain lengths** (`circuit/src/smt.rs`).
  The declared `n_voters` count is now checked against the actual lengths of the
  voteID and ballot chains. A mismatch sets the corresponding fail-mask bit.

- **Validate `n_overwritten` against actual ballot UPDATEs** (`circuit/src/smt.rs`).
  The declared overwrite count is now checked against the actual number of UPDATE
  operations in the ballot chain. Previously the declared value was passed through
  as a public output without verification.

- **Process read-proofs: verify `new_root == old_state_root`** (`circuit/src/smt.rs`).
  Process config read-proofs (NOOP transitions) now explicitly check that both
  `old_root` and `new_root` equal the declared `old_state_root`, providing
  defence-in-depth beyond the SMT Processor's own fnc0/fnc1 logic.

### Bug Fixes

- **Stale KZG comment in main.rs**: removed "Currently always zero (KZG blob
  commitment not yet implemented)" from the output register documentation. The
  KZG commitment limbs have been populated since the KZGBLK implementation.

- **Stale KZG comment in go-sdk/types.go**: updated `OutputBlobCommitment`
  documentation to reflect that the KZG commitment is now populated.

- **Dead code in go-sdk/encode.go**: removed an incorrectly computed magic
  constant (`0x4b4c434e45455200`) that was declared, immediately suppressed
  with `_ = magic`, and shadowed by the correct computation from literal bytes.

- **Suppressed `write_zero_smt_entry` dead-code warning** in `input-gen/src/lib.rs`.

### Known Protocol Differences vs davinci-node

The following are intentional design differences between the zkVM circuit and the
original Gnark StateTransitionCircuit. They do not affect correctness of the
proofs produced by the zkVM, but they mean the davinci-node sequencer needs
minor changes to produce compatible input data.

1. **SMT hash function**: SHA-256 (ZisK hardware-accelerated) replaces Poseidon.
   The state tree uses `arbo.HashFunctionSha256` instead of Poseidon.

2. **Transition ordering**: The Gnark circuit interleaves ballot and voteID
   transitions (`Ballot[0], VoteID[0], Ballot[1], VoteID[1], ...`). The zkVM
   circuit chains all voteID transitions first, then all ballot transitions
   (`VoteID[0..n], Ballot[0..n], ResultsAdd, ResultsSub`). Both orderings
   produce the same final state root; the sequencer must generate Merkle proofs
   in the order expected by the target circuit.

3. **Batch size flexibility**: The Gnark circuit uses a fixed `VotesPerBatch=60`
   with a VoteMask for dummy padding. The zkVM circuit accepts any batch size
   (variable-length chains), with no dummy votes needed.

4. **Aggregator proof**: The Gnark circuit verifies a recursive BW6-761 Groth16
   aggregator proof. The zkVM directly verifies up to 128 BN254 Groth16 ballot
   proofs in a single batch, eliminating the aggregation layer.

### Known Limitations

These features are present in the Gnark StateTransitionCircuit but not yet
implemented in the zkVM circuit. They are tracked for future work.

1. **Ballot homomorphic sum verification** (`VerifyBallots`): The Gnark circuit
   sums all re-encrypted ballots using ElGamal homomorphic addition and checks
   that `ResultsAdd.new = ResultsAdd.old + sum(ballots)` and
   `ResultsSub.new = ResultsSub.old + sum(overwritten_ballots)`. The zkVM verifies
   the SMT transitions for ResultsAdd/Sub but does not verify that the stored
   values correspond to the homomorphic sums of the actual ballot data. This
   means the sequencer is trusted to compute the result accumulation correctly.

2. **Leaf hash verification** (`VerifyLeafHashes`): The Gnark circuit verifies
   that each SMT leaf value equals `hash(serialized_data)` for ballots, process
   config entries, and results. The zkVM verifies the SMT proof validity but
   does not check that the leaf values match the expected serialized content.

3. **Blob construction verification** (`VerifyBlobs`): The Gnark circuit builds
   the EIP-4844 blob from the votes and results inside the circuit and verifies
   the full KZG commitment+opening. The zkVM only verifies the barycentric
   evaluation (`Y = P(Z)`) and does not verify that the blob content matches
   the state transition data. Full KZG opening proof verification requires
   BLS12-381 pairings (not yet available as a ZisK precompile).

4. **CSP census proofs**: The Gnark circuit supports two census types (Merkle
   tree and CSP/blind signatures). The zkVM implements Merkle census proofs only.

### Code Quality

- Removed unused import `ProveResponse` from `service/src/api/prove.rs`.
