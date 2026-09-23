# davinci-zkvm

A [ZisK](https://github.com/0xPolygonHermez/zisk) zkVM service for the
[DAVINCI](https://github.com/vocdoni/davinci-node) voting protocol. Hand it a
batch of voter ballots and the state-transition data; it runs the whole
protocol inside one RISC-V circuit and returns a PLONK SNARK you can verify
on Ethereum with the contracts in [`solidity/`](solidity/).

The pipeline stays zero-knowledge throughout. Voters send Groth16 ballot
proofs over ElGamal-encrypted votes. The service folds the batch through
ZisK. The output is around 2.7 KB of proof, and Ethereum verifies it in
roughly 300 ms.

The service supports two operating modes:

- **Per-batch mode** — every batch gets its own PLONK SNARK, and an
  external verifier (e.g. an Ethereum contract following the davinci-node
  model) checks each state transition.
- **Chained mode** — batches are proven as STARKs and recursively folded
  inside ZisK; the whole election (genesis state, every transition, and
  the decrypted results) collapses into **one final PLONK**. See
  [Chained mode](#chained-mode-one-proof-per-election).

## What the circuit checks

In a single ZisK execution, the circuit verifies:

| Step | Description |
|---|---|
| Groth16 batch verify | BN254 pairing check for every voter ballot proof. |
| ECDSA batch verify | secp256k1 signature recovery for each voter (and for the CSP, in CSP mode). |
| Census membership | Lean-IMT Poseidon BN254 inclusion proofs, or ECDSA CSP authentication. |
| State SMT transitions | Arbo SHA-256 sparse Merkle tree updates for the vote-ID, ballot, results, and process chains. |
| ElGamal re-encryption | BabyJubJub re-encryption of every written ballot, scalars derived in-guest from one sequencer seed. |
| Silent refreshes | Re-randomization of occupied slots the batch did not write, so an overwrite is indistinguishable from a routine refresh; count rule, distinctness and accumulator deltas enforced. |
| Result accumulation | Homomorphic tally with overwrite support, pinned to the Results leaf. |
| DA blob binding | The guest lays out the EIP-4844 blob cells itself (vote identifiers, one sorted list of slot updates, the new accumulator), evaluates every blob polynomial at its bound point and publishes a digest of the (commitment, evaluation) pairs. |
| Cross-block binding | Cryptographic glue between the protocol blocks. |

The public outputs are the two state roots, the census root, the voter and
overwrite counts, the occupied-slot count before the batch, the blob digest
and blob count, and a diagnostic fail-mask. `solidity/DavinciSettlement.sol`
consumes them (see "Settle a transition on-chain").

## Chained mode: one proof per election

Chained mode targets single-sequencer deployments that rely entirely on
ZisK: instead of verifying one PLONK per batch on-chain, the election
produces **one final PLONK** that attests to everything. A second guest,
the aggregator (`circuit-aggregator/`), verifies vadcop-final STARK
proofs *inside* ZisK and runs in three modes:

1. **Genesis + fold** — recomputes the genesis state root in-circuit from
   the immutable election config (process ID, ballot mode, encryption
   key, census origin/root) and folds the first batch proofs from it.
2. **Fold** — verifies the previous fold proof plus K new batch STARKs,
   enforcing state-root continuity, the census root, and per-batch
   success flags. Voter counts accumulate in the public digest.
3. **Finalize** — verifies the last fold, proves the Results leaves'
   SMT inclusion under the final root, checks the trustees' Chaum-Pedersen
   decryption proofs, and commits the plaintext results. Only this proof
   gets the PLONK wrap.

The final PLONK's public digest exposes the plaintext results, the vote
count, the config commitment, the final state root, and the two program
verification keys (`batch_vk`, `fold_vk`). KZG blob evaluation is omitted
in this mode (there is no per-batch on-chain data availability step).

**Silent refreshes.** Every batch also re-randomizes a target number of
occupied ballot slots it did not write, so an observer cannot tell an
overwrite from routine re-encryption noise. The sequencer picks the
slots from OS randomness and drives them through the same scalar chain
as the batch's own votes; neither the seed nor the selection is ever
persisted. The guest enforces the count via `RefreshTarget`, that keys
are distinct and stay inside the ballot namespace, and that each entry
is a valid re-randomization of the stored ballot. `occupied_before` is
a public output the fold guest checks against its running voters −
overwrites.

**Verification key binding.** A guest cannot know its own verification
key, so the chain commits both vks in every digest and the verifier
closes the loop externally with two equality checks after verifying the
PLONK: `digest.fold_vk == proof.program_vk` and `digest.batch_vk ==
<known vote-batch vk>`. `chain.Digest.VerifyBinding` in the Go SDK
implements exactly this; on-chain it is two 32-byte comparisons.

The flow over HTTP (the Go `chain.Sequencer` automates all of it):

```
POST /prove  (output=stark)   per batch → vadcop-final STARK
POST /fold   (genesis)        config + first batch jobs
POST /fold   (chained)        prev fold job + next batch jobs
POST /finalize                last fold + decrypted results + CP proofs → PLONK
```

The first fold is submitted once without `fold_vk` as a *bootstrap*: its
own `program_vk` (returned by `GET /jobs/{id}/stark`) is the aggregator
vk, which the real genesis fold then binds.

### Driving it from Go

```go
import "github.com/vocdoni/davinci-zkvm/go-sdk/chain"

seq, _ := chain.NewSequencer(client, chain.Config{
    ProcessID:    processID,   // *big.Int
    BallotMode:   ballotMode,  // *big.Int
    EncKey:       encKey,      // *bjj_gnark.BJJ ElGamal public key
    CensusOrigin: 1,           // 1 = lean-IMT, 4 = CSP
    CensusRoot:   censusRoot,  // *big.Int
}, foldEvery, timeout)

// Per batch: votes carry the ballot key parts + ciphertexts; req carries
// the Groth16 proofs, signatures and census material. The sequencer owns
// the state tree, re-encrypts ballots, proves the batch as a STARK and
// folds automatically every foldEvery batches.
jobID, err := seq.ProveBatch(votes, req)

// After the DKG reveals the decryption key: decrypts the accumulators,
// builds the Chaum-Pedersen proofs, proves the results in-guest, wraps
// the chain in the final PLONK and runs all consistency + vk-binding
// checks.
final, err := seq.Finalize(encPrivKey)
// final.Snark is the on-chain payload; final.Results the plaintext tally.
```

The Solidity side is unchanged: the final PLONK verifies with the same
`ZiskVerifier.verifySnarkProof`, just with the aggregator's `program_vk`
and the digest as public values.

See [BENCHMARK.md](BENCHMARK.md) for chained-mode throughput numbers;
`make benchmark` reproduces them (see [benchmark/](benchmark/README.md)).

## Layout

```
davinci-zkvm/
├── circuit/             ZisK RISC-V guest: the vote-batch circuit
│   ├── elf/             Pre-built circuit ELF (tracked in git)
│   └── src/             groth16, ecdsa, census, csp, kzg, …
├── circuit-aggregator/  ZisK RISC-V guest: recursive aggregator (chained mode)
│   ├── elf/             Pre-built aggregator ELF (tracked in git)
│   └── src/             in-guest STARK verification, genesis, fold, finalize
├── circuit-primitives/  no_std crate shared by both guests
│   └── src/             smt, babyjubjub, poseidon, chaum_pedersen, hash, …
├── input-gen/           Typed protocol blocks → ZisK binary input
├── service/             HTTP API (axum + tokio)
│   └── src/
│       ├── api/         POST /prove, /fold, /finalize, GET /jobs/*, /health
│       └── prover/      Background queue, worker, snark/recursion extractors
├── solidity/            Vendored Solidity verifier (PlonkVerifier + ZiskVerifier)
└── go-sdk/              Go client library, with an on-chain verification helper
    ├── chain/           Chained-mode sequencer: state tree, folds, finalize
    ├── solidity/        simulated.NewBackend verification helper
    └── tests/           Integration tests
```

## Quick start

### Requirements

- Docker + Docker Compose (nothing else on the host)
- NVIDIA GPU with **~30 GB VRAM** (RTX 5090 32 GB and A100 40 GB work;
  RTX 4090 at 24 GB does not). The PLONK aggregation pass is what
  pushes memory usage; first boot allocates the full working set.
- NVIDIA driver 570+ and `nvidia-container-toolkit` on the host. The
  prebuilt `cargo-zisk-gpu` is statically linked against the CUDA
  runtime, so no CUDA toolkit is needed on the host.
- About 100 GB of free disk for the two ZisK proving keys (STARK ~73 GB,
  PLONK ~25 GB).

### Install and run

The Makefile drives Docker Compose end-to-end. A fresh clone goes from
zero to a healthy service with three commands:

```bash
git clone https://github.com/vocdoni/davinci-zkvm.git
cd davinci-zkvm
make install    # downloads both proving keys via ziskup, builds the image
make up         # starts the prover service
make test       # runs the Go integration test suite
```

`make install` runs `ziskup` inside a small container and writes both
keys into `./zisk-keys/` on the host (~100 GB total, 20–60 min depending
on bandwidth). It also patches the PLONK `final.so` to drop its
executable-stack flag, which modern Linux refuses to grant at dlopen
time. The runtime container builds the GPU setup artifacts on first
boot (about a minute) and skips that step on subsequent starts.

Other Make targets: `make logs`, `make status`, `make shell`,
`make down`, `make restart`, `make clean`. Run `make help` for the
full list.

To put the proving keys somewhere other than `./zisk-keys`, set
`ZISK_KEYS_DIR=/path/to/keys` either in `.env` (copy from `.env.example`)
or on the command line.

### Submit a proof from Go

```go
import davinci "github.com/vocdoni/davinci-zkvm/go-sdk"

client := davinci.NewClient("http://localhost:8080")

batch := &davinci.ProveBatch{
    VerificationKey: vk,       // Groth16 BN254 VK shared by all ballot proofs
    Voters:          voters,   // []VoterBallot with proofs + ECDSA sigs
    State:           state,    // SMT chain transitions
    EncryptionKey:   encKey,   // ElGamal re-encryption key
    ReencryptionSeed: seed,    // the seed the voters' re-encryptions were derived from
    KZG:             kzg,      // EIP-4844 blob evaluation
}

result, err := client.Prove(ctx, batch)
// result.Snark holds the four byte strings you pass straight into
// ZiskVerifier.verifySnarkProof on Ethereum.
```

See [go-sdk/README.md](go-sdk/README.md) for the full Go API.

### Verify the SNARK in-process

The repo vendors the Solidity verifier under
[`solidity/`](solidity/README.md). The Go SDK ships a helper that compiles
it (via local `solc` or `docker run ethereum/solc:stable`) and runs it on
`go-ethereum/ethclient/simulated.NewBackend`:

```go
import davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"

err := davinciSolidity.VerifyOnSimulated("./solidity", result.Snark)
```

No Anvil, ganache, or RPC endpoint needed.

### Settle a transition on-chain

`solidity/DavinciSettlement.sol` is the reference per-batch settlement
contract: it verifies the PLONK through `ZiskVerifier`, checks root
continuity, the census root and the occupied-slot count against its own
counters, recomputes the blob digest from the submitted commitments and
evaluations, and checks every blob with the EIP-4844 point-evaluation
precompile against the blob transaction's versioned hashes. The Go helper
deploys it on the simulated backend and submits real blob transactions:

```go
blobs, _ := davinci.BuildTransitionBlobs(numFields, pid, rootBefore, voteIDs, updates, accumulator)
req.KZG = blobs.Request(pidHex, rootBeforeHex)   // commitments only; the guest rebuilds the cells
// ... prove, then:
s, _ := davinciSolidity.DeploySettlement("./solidity", snark.ProgramVK, snark.RootCVadcopFinal)
s.CreateProcess(pid, genesisRoot, censusRoot)
gas, err := s.SubmitTransition(pid, snark, blobs)
```

`TestFullE2E` runs the whole flow, silent refreshes and overwrites
included, and settles every transition this way.

## HTTP API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/prove` | Submit a state-transition batch. `output: "plonk"` (default) or `"stark"` (foldable). Returns a job ID. |
| `POST` | `/fold` | Chained mode: fold batch STARKs into the chain (genesis when `prev_fold_job` is absent). |
| `POST` | `/finalize` | Chained mode: verify the decrypted results and wrap the chain in the final PLONK. |
| `POST` | `/jobs/import` | Chained mode: import a raw STARK `proof.bin` proven on another worker as a local `BatchStark` job (scatter/gather). Body is the raw blob; returns a job ID. |
| `GET` | `/jobs/{id}` | Job status (queued / running / done / failed) and timing. |
| `GET` | `/jobs/{id}/snark` | The Solidity-ready PLONK payload as JSON. |
| `GET` | `/jobs/{id}/snark/raw` | The raw `proof.bin` (bincode), for `cargo-zisk verify`. |
| `GET` | `/jobs/{id}/stark` | The `program_vk` / `zisk_vk` of a STARK job (vk binding). |
| `GET` | `/jobs/{id}/publics` | Just the `publicValues` blob (the digest, for fold/finalize jobs). |
| `GET` | `/jobs/{id}/inputs` | The raw `input.bin` (audit / re-proving). |
| `GET` | `/health` | Service liveness check. |

`/jobs/{id}/snark` payload:

```json
{
  "program_vk":           "0x…32 bytes",
  "root_c_vadcop_final":  "0x…32 bytes",
  "public_values":        "0x…512 bytes",
  "proof_bytes":          "0x…768 bytes (ABI-encoded uint256[24])"
}
```

These four fields map straight onto the arguments of
`ZiskVerifier.verifySnarkProof`.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address. |
| `PROVING_KEY_PATH` | `/proving-key` | ZisK STARK proving key directory. |
| `PROVING_KEY_PLONK_PATH` | `/proving-key-plonk` | ZisK PLONK proving key directory. |
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Pre-built vote-batch circuit ELF. |
| `AGGREGATOR_ELF_PATH` | `/app/aggregator.elf` | Pre-built aggregator ELF (chained mode). |
| `CARGO_ZISK_BIN` | `cargo-zisk` | `cargo-zisk` binary to invoke. |
| `PROOF_OUTPUT_DIR` | `/tmp/proofs` | Per-job artifact directory. |
| `ZISK_MINIMAL_MEMORY` | `0` | Force `cargo-zisk prove --minimal-memory` on every attempt (it is auto-enabled on retries). |
| `ZISK_MINIMAL_MEMORY_FROM` | `512` | Batches with at least this many ballot proofs use `--minimal-memory` from the first attempt: it caps the prover's host RAM (a 1024-vote transition needs ~54 GB without it, ~41 GB with it) at a few percent of speed. |
| `DAVINCI_KEEP_INPUTS` | `0` | Keep each job's `input.bin` and serve `GET /jobs/{id}/inputs`. The input is the private witness (re-encryption seed, overwrite and refresh sets); leave it off outside development. |
| `MAX_QUEUE_SIZE` | `100` | Maximum queued jobs. |
| `ZISK_MPI_PROCS` | `1` | MPI processes for proving (`>1` runs `mpirun`). |
| `ZISK_MPI_THREADS` | `0` | Threads per MPI process (`0` = let MPI decide). |
| `ZISK_MPI_BIND_TO` | `none` | `mpirun --bind-to` policy. |

## Performance

All numbers below are from an NVIDIA RTX 5090 running the
[full pipeline](#what-the-circuit-checks) on ZisK v1.3.0-alpha. Ballot
generation isn't counted; the time column is the service's job time for the
steady state, i.e. a batch that also silently refreshes as many slots as it
writes. `nf` is the election's declared field count.

| batch | PLONK (nf=2) | votes/s | PLONK (nf=16) | votes/s | settlement gas |
|---:|---:|---:|---:|---:|---:|
|   64 |  22.5 s | 2.8 |  30.3 s | 2.1 | ~500 k |
|  128 |  30.1 s | 4.3 |  45.7 s | 2.8 | ~500 k (1 blob) / ~612 k (3 blobs) |
|  256 |  46.2 s | 5.5 |  76.7 s | 3.3 | ~500 k (1) / ~724 k (5) |
|  512 |  84.3 s | 6.1 | 164.3 s | 3.1 | ~554 k (2) / 9 blobs, above the 6-blob per-tx cap |
| 1024 | 171.2 s | 6.0 | 363.9 s | 2.8 | ~612 k (3) / 17 blobs, above the 6-blob per-tx cap |

The fixed cost (recursion, PLONK wrap, verification) is about 16 s; the
batch cap is 1024, set by the prover's host RAM (~41 GB with
`--minimal-memory`, which the service enables from 512 proofs). Gas for more
than one blob is extrapolated at ~56 k per blob. Settlement gas is
for `DavinciSettlement.submitTransition` on the simulated chain, one
point-evaluation check per blob included. Proof size stays at
768 B of proof plus 512 B of public values regardless of batch. See
[`BENCHMARK.md`](BENCHMARK.md) for the chained mode and the full tables.

## Development

```bash
# Rebuild the circuit ELF (needs the +zisk Rust toolchain)
cd circuit && cargo-zisk build --release
cp circuit/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-circuit \
   circuit/elf/circuit.elf

# Rebuild the aggregator ELF (chained mode). Rebuilding either guest
# changes its program_vk; clients read vks from the running service,
# never hardcode them.
cd circuit-aggregator && cargo-zisk build --release
cp circuit-aggregator/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-aggregator \
   circuit-aggregator/elf/aggregator.elf

# Build the service binary
cargo build --release -p davinci-zkvm-service

# Rebuild the runtime Docker image
make build

# Run the integration tests against a running service
make test
```

If you'd rather build and run the service directly on the host without
Docker — useful when iterating on the Rust code — see `make local-setup`,
`make local-run`, `make local-test`. Those drive `scripts/install.sh`, which
also installs `snarkjs`: the prover's own PLONK verification shells out to
it (the Docker image ships it).

## Circuit specification

[CIRCUIT.md](CIRCUIT.md) has the formal constraint spec, the public-output
encoding, the fail-mask bits, and the cross-block binding rules.
