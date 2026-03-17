# CIRCUIT

This guest verifies the active `davinci-stark` ballot protocol and binds it to
the zkVM state-transition blocks. The ballot path is no longer Groth16,
BabyJubJub, or BN254-ElGamal based.

## Batch-size configuration

- `MAX_BATCH_SIZE` is compiled into both `davinci-zkvm/input-gen` and the guest.
- Source: build-time environment variable `DAVINCI_MAX_BATCH_SIZE`
- Requirements:
  - power of two
  - at least `2`
- Default: `128`

The Go integration helpers have a matching runtime cap via the same environment
variable name and must use the same value as the Rust build.

## Active input blocks

1. `DSTARKB!`
   - `davinci-stark` proof bytes plus decoded public values
   - per-voter public statement:
     - `inputs_hash[4]`
     - `address[4]`
     - `vote_id`
     - `inputs_preimage[114]`
2. ECDSA signature block
3. Optional `STAG5TX!`
   - state-transition SMT chains
   - ecgfp5 result-accumulator payload
4. Optional `CENSUS!!` or `CSPBLK!!`
5. Optional `REG5BLK!`
   - ecgfp5 re-encryption witnesses
6. Optional `KZGBLK!!`

## Gadget inventory

### 1. Ballot proof verifier

- Proof system: `davinci-stark` built with Plonky3 univariate STARK + HidingFriPcs (ZK)
- Base field: Goldilocks
- Extension field: Goldilocks quadratic extension (D=2)
- STARK transcript / infrastructure hash:
  - width-8 Goldilocks Poseidon2 (`default_goldilocks_poseidon2_8()`)
  - digest: 4 Goldilocks elements
- Ballot statement hash inside `davinci-stark`:
  - same width-8 Goldilocks Poseidon2
  - verifier-side `inputs_hash` recomputation from the AIR-bound public preimage
- Curve for ballot encryption proved by `davinci-stark`: `ecgfp5`
- Guest entry point: [davinci_stark.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/davinci_stark.rs)

#### Operating modes

**Standalone mode** (legacy): The guest verifies each individual ballot STARK
proof inline. This is slow (~55M cycles/ballot) due to Goldilocks field
arithmetic without a ZisK precompile.

**Aggregated mode** (`BALLOT_AGGREGATION=1`): The service strips ballot proof
bytes from the guest input. The guest detects empty proof bytes and skips STARK
verification entirely, running only the lightweight checks (ECDSA, census, SMT,
binding, re-encryption). The ballot STARK proofs are verified externally via
Plonky3-recursion aggregation. This reduces proof time from ~76s to ~20-24s for
4 ballots.

The `recursion-aggregator/` crate provides the CPU-side aggregation: it folds N
individual ballot proofs into a single batch-STARK proof using binary-tree
`build_and_prove_aggregation_layer()`. The outer verifier checks both the
aggregated batch-STARK proof and the ZisK proof.

### 2. Voter authentication

- Signature scheme: secp256k1 ECDSA
- Message hash: Ethereum `personal_sign`
- Hash function: Keccak-256
- Acceleration:
  - `secp256k1_ecdsa_verify` ZisK primitive
  - Keccak-f ZisK precompile via [hash.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/hash.rs)
- Guest code: [ecdsa.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/ecdsa.rs)

Per voter, the guest verifies:
- the ECDSA signature over `vote_id`
- the recovered Ethereum address derived from the secp256k1 public key matches
  the address declared by the STARK proof

### 3. Census membership

There are two mutually exclusive eligibility modes.

#### 3a. Lean-IMT census mode

- Tree hash: iden3 Poseidon over BN254 Fr
- Arity: 2-input Poseidon (`poseidon2(left, right)` in local naming)
- Leaf encoding: `PackAddressWeight(address, weight)` over BN254 Fr
- Guest code: [census.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/census.rs)

This path is kept because the external census/state tree format is still BN254
Poseidon-based.
The local implementation lives in
[poseidon.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/poseidon.rs)
and is intentionally retained until the external census format changes.

#### 3b. CSP authorization mode

- Signature scheme: secp256k1 ECDSA
- Message hash: Ethereum `personal_sign`
- Hash function: Keccak-256
- Guest code: [csp.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/csp.rs)

In CSP mode, the guest treats the CSP Ethereum address as the census root and
verifies CSP signatures over `(process_id, voter_address, weight, index)`.

### 4. State-transition SMT checks

- Tree type: Arbo-style sparse Merkle transitions already supplied in the input
- Hash function for SMT nodes: SHA-256
- Acceleration: SHA-256 ZisK precompile via [hash.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/hash.rs)
- Guest code: [smt.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/smt.rs)

The guest verifies the transition chains for:
- vote IDs
- ballot leaves
- result accumulator leaves
- process config reads

### 5. Re-encryption verification

- Encryption scheme: ecgfp5 ElGamal
- Curve/group: `ecgfp5`
- Hash for encryption public-key binding: SHA-256 over the 40-byte encoded key
- Guest code: [ecgfp5_verify.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/ecgfp5_verify.rs)

Per voter, the guest checks:
- `delta1 = k * G`
- `delta2 = k * PK`
- every ciphertext satisfies:
  - `C1' = C1 + delta1`
  - `C2' = C2 + delta2`

### 6. Result accumulation and ballot leaf hashing

- Ciphertext type: ecgfp5 ElGamal ciphertexts
- Homomorphic operation: ecgfp5 point addition on encoded ciphertext components
- Ballot leaf hash: SHA-256 over the canonical 8-field ecgfp5 ciphertext encoding
- Guest code: [results.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/results.rs) and [ecgfp5_verify.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/ecgfp5_verify.rs)

The guest verifies:
- the stored result leaf hashes match the ecgfp5 ballots
- `ResultsAdd` and `ResultsSub` transitions match ecgfp5 homomorphic addition

### 7. KZG barycentric evaluation

- Polynomial commitment domain: EIP-4844 blob domain
- Scalar field: BLS12-381 Fr
- Evaluation-point hash: SHA-256
- Arithmetic acceleration: `arith256_mod` ZisK precompile via `bls_fr.rs`
- Guest code: [kzg.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/kzg.rs)

Important scope limit:
- the guest verifies barycentric evaluation `Y = P(Z)`
- it does **not** verify the pairing-based KZG opening proof itself

## Cross-block binding

The guest does not treat these blocks independently. It binds them together in
[binding.rs](/home/p4u/davinci-miden/davinci-stark/davinci-zkvm/circuit/src/binding.rs).

Current bindings include:
- STARK `process_id` == state `process_id`
- STARK packed ballot mode == process config ballot mode
- STARK election public key == re-encryption public key
- STARK ciphertexts == `REG5BLK!` original ballots
- `REG5BLK!` reencrypted ballots == `STAG5TX!` voter ballots
- STARK voter address == census/CSP identity
- STARK weight == census/CSP weight
- KZG process/root == state process/root
- re-encryption key hash == process config encryption-key hash

## Output fail-mask highlights

- bit 2: `FAIL_STARK_PROOF`
- bit 3: `FAIL_ECDSA`
- bits 10-13: SMT failures
- bit 16: `FAIL_CENSUS`
- bit 17: `FAIL_REENC`
- bit 18: `FAIL_KZG`
- bit 20: `FAIL_RESULT_ACCUM`
- bit 21: `FAIL_LEAF_HASH`
- bit 22: `FAIL_BINDING`
- bit 23: `FAIL_CSP`
- bit 31: `FAIL_PARSE`
