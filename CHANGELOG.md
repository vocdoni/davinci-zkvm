# Changelog

All notable changes to davinci-zkvm are documented here.

## Unreleased — Security Audit & Protocol Hardening

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
