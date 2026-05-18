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

## What the circuit checks

In a single ZisK execution, the circuit verifies:

| Step | Description |
|---|---|
| Groth16 batch verify | BN254 pairing check for every voter ballot proof. |
| ECDSA batch verify | secp256k1 signature recovery for each voter (and for the CSP, in CSP mode). |
| Census membership | Lean-IMT Poseidon BN254 inclusion proofs, or ECDSA CSP authentication. |
| State SMT transitions | Arbo SHA-256 sparse Merkle tree updates for the vote-ID, ballot, results, and process chains. |
| ElGamal re-encryption | BabyJubJub re-encryption verification. |
| KZG blob evaluation | EIP-4844 barycentric evaluation of the encrypted ballot blob. |
| Result accumulation | Homomorphic tally with overwrite support. |
| Cross-block binding | Cryptographic glue between the protocol blocks. |

The circuit's public outputs match
[davinci-node](https://github.com/vocdoni/davinci-node)'s
`StateTransitionCircuit` interface: the two root hashes, the census root,
the voter counts, the KZG blob commitment, and a diagnostic fail-mask.

## Layout

```
davinci-zkvm/
├── circuit/        ZisK RISC-V guest circuit (Rust, +zisk toolchain)
│   ├── elf/        Pre-built circuit ELF (tracked in git)
│   └── src/        groth16, ecdsa, smt, census, csp, results, kzg, …
├── input-gen/      Typed protocol blocks → ZisK binary input
├── service/        HTTP API (axum + tokio)
│   └── src/
│       ├── api/    POST /prove, GET /jobs/*, GET /health
│       └── prover/ Background queue, worker, snark.json extractor
├── solidity/       Vendored Solidity verifier (PlonkVerifier + ZiskVerifier)
└── go-sdk/         Go client library, with an on-chain verification helper
    ├── solidity/   simulated.NewBackend verification helper
    └── tests/      Integration tests
```

## Quick start

### Requirements

- Docker + Docker Compose (nothing else on the host)
- NVIDIA GPU with **~30 GB VRAM** (RTX 5090 32 GB and A100 40 GB work;
  RTX 4090 at 24 GB does not). The PLONK aggregation pass is what
  pushes memory usage; first boot allocates the full working set.
- NVIDIA driver 570+, CUDA 12.8, `nvidia-container-toolkit`
- About 40 GB of free disk for the two ZisK proving keys.

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
keys into `./zisk-keys/` on the host (~37 GB, 10–30 min depending on
bandwidth). It also patches the PLONK `final.so` to drop its
executable-stack flag, which modern Linux refuses to grant at dlopen
time. The runtime container builds the GPU constant trees on first
boot (~10 min) and skips that step on subsequent starts.

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

## HTTP API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/prove` | Submit a state-transition batch. Returns a job ID. |
| `GET` | `/jobs/{id}` | Job status (queued / running / done / failed) and timing. |
| `GET` | `/jobs/{id}/snark` | The Solidity-ready PLONK payload as JSON. |
| `GET` | `/jobs/{id}/snark/raw` | The raw `proof.bin` (bincode), for `cargo-zisk verify`. |
| `GET` | `/jobs/{id}/publics` | Just the 256-byte `publicValues` blob. |
| `GET` | `/jobs/{id}/inputs` | The raw `input.bin` (audit / re-proving). |
| `GET` | `/health` | Service liveness check. |

`/jobs/{id}/snark` payload:

```json
{
  "program_vk":           "0x…32 bytes",
  "root_c_vadcop_final":  "0x…32 bytes",
  "public_values":        "0x…256 bytes",
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
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Pre-built circuit ELF. |
| `CARGO_ZISK_BIN` | `cargo-zisk` | `cargo-zisk` binary to invoke. |
| `PROOF_OUTPUT_DIR` | `/tmp/proofs` | Per-job artifact directory. |
| `MAX_QUEUE_SIZE` | `100` | Maximum queued jobs. |
| `ZISK_MPI_PROCS` | `1` | MPI processes for proving (`>1` runs `mpirun`). |
| `ZISK_MPI_THREADS` | `0` | Threads per MPI process (`0` = let MPI decide). |
| `ZISK_MPI_BIND_TO` | `none` | `mpirun --bind-to` policy. |

## Performance

All numbers below are from an NVIDIA RTX 5090 (driver 580, CUDA 12.8)
running the [full pipeline](#what-the-circuit-checks). Ballot generation
isn't counted; the time column is just SNARK generation.

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |    37 s |  1.7 |  350 ms |
| 128 |    57 s |  2.2 |  340 ms |
| 256 |    97 s |  2.6 |  340 ms |
| 512 |   138 s |  3.7 |  480 ms |

Scaling is sub-linear: per-vote cost roughly halves between batch 64 and
batch 512. Proof size stays at 2.7 KB regardless of batch.

## Development

```bash
# Rebuild the circuit ELF (needs the +zisk Rust toolchain)
cd circuit && cargo-zisk build --release
cp circuit/target/elf/riscv64ima-zisk-zkvm-elf/release/davinci-zkvm-circuit \
   circuit/elf/circuit.elf

# Build the service binary
cargo build --release -p davinci-zkvm-service

# Rebuild the runtime Docker image
make build

# Run the integration tests against a running service
make test
```

If you'd rather build and run the service directly on the host without
Docker — useful when iterating on the Rust code — see `make local-setup`,
`make local-run`, `make local-test`. Those drive `scripts/install.sh`.

## Circuit specification

[CIRCUIT.md](CIRCUIT.md) has the formal constraint spec, the public-output
encoding, the fail-mask bits, and the cross-block binding rules.
