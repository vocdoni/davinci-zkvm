# davinci-zkvm

A ZisK zkVM service that verifies DAVINCI state transitions with the active
`davinci-stark` ballot proof system and ecgfp5-native ballot state.

Current ZisK runtime target: `v0.16.0`

## Active protocol

Each batch is verified inside one guest execution with these components:

- `DSTARKB!`: `davinci-stark` ballot proofs (public values always present; proof bytes present in standalone mode, stripped in aggregated mode)
- ECDSA voter signatures bound to ballot `vote_id`
- `STAG5TX!`: SHA-256 Arbo state-transition proofs plus ecgfp5 ballot payloads
- `CENSUS!!` or `CSPBLK!!`: voter eligibility proofs
- `REG5BLK!`: ecgfp5 re-encryption witnesses
- `KZGBLK!!`: EIP-4844 blob evaluation
- cross-block binding between the ballot statement, state, re-encryption key, and blob context

The public outputs remain compatible with `davinci-node`'s state-transition verifier:
old root, new root, voter counts, census root, blob commitment limbs, and a fail mask.

### Ballot aggregation mode

When `BALLOT_AGGREGATION=1`, the service strips individual ballot STARK proof
bytes from the guest input. The ZisK guest skips STARK verification and runs
only the lightweight checks (ECDSA, census, SMT, binding, re-encryption). This
yields ~3x faster proof times (e.g. ~23s vs ~76s for 4 ballots).

The `recursion-aggregator/` crate provides CPU-side Plonky3-recursion
aggregation that folds N ballot proofs into a single batch-STARK proof. The
outer verifier checks both the aggregated proof and the ZisK proof.

### Benchmarks

ZisK proof times with `BALLOT_AGGREGATION=1` on an RTX 5090 GPU (ZisK v0.16.0).
All times are proof-only (excludes ballot generation and network overhead).
The per-ballot marginal cost is ~1.6s with a ~18s fixed overhead.

| Ballots per job | Proof time (fresh) | Proof time (overwrites) | Throughput |
|----------------:|-------------------:|------------------------:|-----------:|
| 2               | ~20s               | —                       | 0.10 b/s   |
| 4               | ~23s               | —                       | 0.17 b/s   |
| 64              | ~118s              | ~148s                   | 0.54 b/s   |
| 128             | ~222s              | ~278s                   | 0.58 b/s   |
| 256 (2×128)     | ~445s              | —                       | 0.58 b/s   |
| 512 (4×128)     | ~890s              | —                       | 0.58 b/s   |

> **Note**: The current compiled `MAX_BATCH_SIZE=128`, so batches >128 are split
> into sequential 128-ballot jobs. The 256 and 512 rows are measured by summing
> sequential 128-batch jobs from the E2E test suite. Overwrite transitions are
> heavier because they include result-subtraction SMT operations.

## Repository layout

- `circuit/`: ZisK guest circuit
- `input-gen/`: Rust encoder for `DSTARKB!`, `STAG5TX!`, `REG5BLK!`, census, CSP, and KZG blocks
- `service/`: HTTP proving service
- `recursion-aggregator/`: Plonky3-recursion ballot proof aggregation
- `go-sdk/`: typed client SDK and integration tests

## API

`POST /prove` accepts a STARK-only request body with:

- `stark_proofs`
- `sigs`
- optional `state`
- optional `census_proofs` or `csp_data`
- optional `ecgfp5_reencryption`
- optional `kzg`

See `service/src/types.rs` and `go-sdk/types.go` for the exact schema.

## Configuration

Key environment variables for the service:

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `0.0.0.0:8080` | HTTP listen address |
| `PROVING_KEY_PATH` | `/proving-key` | ZisK proving key directory |
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Compiled circuit ELF |
| `BALLOT_AGGREGATION` | `0` | Enable aggregated mode (strip STARK proofs) |
| `ZISK_MPI_PROCS` | `1` | MPI parallel proving processes |
| `ZISK_AGGREGATION` | `0` | ZisK recursive proof aggregation |

## Development

```bash
# Workspace (service + input-gen + recursion-aggregator)
cargo test

# Circuit checks/tests (requires +zisk toolchain for build, host tests only)
cargo test --manifest-path circuit/Cargo.toml

# Go SDK and integration tests
cd go-sdk && go test ./... -count=1

# Docker + full E2E
BALLOT_AGGREGATION=1 docker compose up -d --build
cd go-sdk/tests/integration
VOTES_PER_BATCH=4 DAVINCI_PROOF_TIMEOUT=80m go test -v -run TestFullE2E -timeout 4h
```

## Circuit spec

See `circuit/CIRCUIT.md` for the current STARK/ecgfp5 guest format and checks.
In particular:
- the ballot-proof verifier uses width-8 Goldilocks Poseidon2
  (`default_goldilocks_poseidon2_8()`) for STARK infrastructure hashing
- in aggregated mode, the guest skips STARK verification entirely
- the BN254/iden3 Poseidon implementation is still retained only for Lean-IMT
  census proofs, because the external census format is still BN254 Poseidon based
