# Architecture

davinci-zkvm proves DAVINCI state transitions with the ZisK zkVM. The protocol
logic is ordinary Rust compiled to RISC-V (the *guests*); ZisK proves that a
guest ran to completion on a given input and what it wrote to its public
outputs. The service around it queues jobs, feeds the prover and returns
proofs that the Solidity verifier accepts.

## Components

| Path | Role |
|---|---|
| `circuit/` | Vote-batch guest. Verifies one batch of ballots and the state transition it causes. Spec: [`circuit/CIRCUIT.md`](../circuit/CIRCUIT.md). |
| `circuit-results/` | Results guest. Proves the decrypted tally of an election under its final state root. Spec: [`circuit-results/RESULTS.md`](../circuit-results/RESULTS.md). |
| `circuit-aggregator/` | Aggregator guest for chained mode. Verifies vote-batch STARKs in-guest and folds them into one proof per election. |
| `circuit-primitives/` | `no_std` library shared by the guests: sparse Merkle tree, Poseidon, BabyJubJub, BN254 and BLS12-381 field arithmetic, DA blob layout, Chaum-Pedersen. |
| `input-gen/` | Host-side encoder from typed protocol data to the guests' binary input. Owns the wire format. |
| `service/` | HTTP API (axum). Validates requests, builds guest inputs, runs `cargo-zisk prove` one job at a time on the GPU and extracts the on-chain payload. |
| `go-sdk/` | Go client, protocol helpers, the chained-mode orchestrator (`go-sdk/chain`) and the integration test suites. |
| `rust-sdk/` | Rust client (`davinci-zkvm-sdk`): wire types, publics parsers, DA blob builder and decoder, release pins and the protocol primitives a sequencer needs. |
| `solidity/` | The ZisK PLONK verifier (vendored unchanged from the ZisK release) and a reference per-batch settlement contract. |

The guest ELFs are committed under `*/elf/`. They are built reproducibly, so a
given source tree always produces the same bytes and therefore the same
program verification key (vk). CI rebuilds them and fails if they differ.

## Per-batch mode

A sequencer submits each batch to `POST /prove`. The vote-batch guest checks,
in one execution:

| Check | What it covers |
|---|---|
| Ballot proofs | Batched Groth16 (BN254) verification of every voter's ballot proof, with the random linear combination computed in-guest. |
| Signatures | secp256k1 recovery of each voter's signature over its vote ID, bound to the address in the ballot proof. |
| Eligibility | lean-IMT Poseidon census proofs, or signatures from a Credential Service Provider (CSP census). |
| State transition | Arbo SHA-256 sparse Merkle tree updates for vote IDs, ballots and the results leaf, plus read proofs of the process configuration. |
| Re-encryption | Every stored ballot is the voter's ballot re-encrypted with scalars derived in-guest from one secret seed per batch. |
| Silent revoting | Occupied slots the batch did not write are re-randomized too, so an overwrite looks like a routine refresh. |
| Tally | The encrypted results accumulator is updated homomorphically: new ballots added, overwritten ballots subtracted, refresh deltas added. |
| Data availability | The guest lays out the EIP-4844 blob contents itself, evaluates each blob polynomial at a bound point and publishes a digest of the commitments and evaluations. |
| Cross-block binding | Process ID, state root and keys agree across the input blocks. |

A failed check sets a bit in `fail_mask`, the remaining checks still run, and
the batch is proved with `ok = 0`. A finished job can therefore hold a
rejected batch: the consumer must read the public outputs and require
`ok == 1`.

The public outputs (46 registers, see CIRCUIT.md section 3) carry the state
roots before and after, the census root, the vote and overwrite counts, the
occupied-slot count before the batch, the blob digest and the blob count. The
guest proves a transition from whatever root and census it is given, so the
verifier must also check:

- the proof under the pinned vote-batch program vk;
- `ok == 1` and `fail_mask == 0`;
- the root before equals the process's last settled root;
- the census root equals the process census root;
- the occupied-slot count equals the running `votes - overwrites`;
- every blob commitment and evaluation against the blob transaction's
  versioned hashes, with the EIP-4844 point-evaluation precompile.

`solidity/DavinciSettlement.sol` is a reference contract that does exactly
this. The production contracts live in
[davinci-contracts](https://github.com/vocdoni/davinci-contracts).

When voting ends, the election key holders decrypt the accumulator and
`POST /results` proves the tally with the results guest: the key and the
accumulator are leaves of the final state root, and each plaintext comes with
a Chaum-Pedersen decryption proof. The contract checks that `state_root` is
the process's last root before reading the tally.

### Proof format

Every PLONK job returns the four arguments of
`ZiskVerifier.verifySnarkProof(programVK, rootCVadcopFinal, publicValues, proofBytes)`:
32 + 32 bytes of keys, 512 bytes of public values (64 registers as 8-byte
little-endian words) and a 768-byte proof. The size does not depend on the
batch size or the ballot field count.

`programVK` identifies the guest ELF and `rootCVadcopFinal` the ZisK setup.
A consumer should compare both against pinned values rather than trust the
ones the service returns. The pins live in `rust-sdk/src/release.rs` and
`go-sdk/chain/release.go`.

## Chained mode

Chained mode replaces one on-chain verification per batch with one per
election. Batches are proved as vadcop-final STARKs (`"output": "stark"`), and
the aggregator guest folds them:

1. **Genesis fold.** Recomputes the genesis state root from the immutable
   election config (process ID, ballot mode, encryption key, census origin
   and root, ballot VK hash) and folds the first batch proofs onto it.
2. **Fold.** Verifies the previous fold proof and the next batch proofs
   in-guest, enforces state-root continuity, the census root, each batch's
   `ok` flag and the occupied-slot count, and accumulates the vote counts.
3. **Finalize.** Verifies the last fold, proves the results leaf is included
   under the final root, checks one Chaum-Pedersen proof per ciphertext and
   commits the plaintext tally. Only this step is wrapped in PLONK.

Chained batches carry no DA blobs; the blob registers stay zero.

The fold output is a 53-word digest (`go-sdk/chain/digest.go`): the number
of fold steps (not batches), total votes and overwrites, a config commitment, the state root, both program
vks and, after finalize, the tally.

**Verification-key binding.** A guest cannot know its own vk. The digest
commits the aggregator vk (`fold_vk`) and the vote-batch vk (`batch_vk`), and
`config_commitment = sha256(config frame || batch_vk || fold_vk)` binds both
to the election parameters. After verifying the final PLONK, a verifier
checks that `fold_vk` equals the proof's `programVK`, that both vks match the
pinned release, and that the commitment matches the published config.
`chain.VerifyDigest` implements these checks.

The first fold is submitted once without `fold_vk` as a bootstrap: its own
`program_vk` (read from `GET /jobs/{id}/stark`) is the aggregator vk, which
the genesis fold then binds.

Over HTTP the flow is:

```
POST /prove     {"output": "stark", ...}          one per batch
POST /fold      {config, batch_jobs}              genesis fold
POST /fold      {config, prev_fold_job, batch_jobs}
POST /finalize  {config, fold_job, results}       returns the final PLONK
```

`chain.Sequencer` in the Go SDK drives all of it: it owns the process state
tree, re-encrypts ballots, picks refresh slots, submits folds every
`foldEvery` batches and runs the binding checks at finalize. Fold inputs are
read from the service's own job directory, so a fold and the batches it
covers must be on the same prover. `POST /jobs/import` registers a STARK
proved elsewhere so a fold worker can use it; the aggregator re-verifies every
imported proof in-guest. [davinci-fold](https://github.com/vocdoni/davinci-fold)
uses this to spread batch proving over several provers.

## Privacy of the witness

The guest input is the private witness: it contains the re-encryption seed
and which slots were overwritten or refreshed. The service deletes each job's
`input.bin` after proving unless it runs with `DAVINCI_KEEP_INPUTS=1`. The
seed and the refresh selection must come from fresh OS randomness for every
batch and must never be derivable from public data; otherwise an observer
can tell overwrites from refreshes.

## Limits

| Limit | Value | Set in |
|---|---|---|
| Ballots per batch | 1024 | `MAX_BATCH_SIZE` |
| Silent refreshes per batch | 2048 | `MAX_REFRESH` |
| Ciphertexts per ballot | 16 | `NUM_FIELDS` |
| DA blobs per batch | 32 | `MAX_BLOBS` |
| State tree depth | 64 | `SMT_LEVELS` |

The constants live in `circuit-primitives/src/types.rs` and are mirrored in
`input-gen`, `go-sdk/types.go` and `rust-sdk/src/limits.rs`. Changing one
changes the guest and its vk. A settlement transaction can carry at most six
blobs (EIP-7594), which caps the settleable batch size below 1024 for ballots
with more than five fields; `davinci.MaxSingleTxBatch(nf)` (Go) and
`blob::max_votes_for_cap` (Rust) compute it.
