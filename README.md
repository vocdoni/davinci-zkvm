# davinci-zkvm

Prover service for the [DAVINCI](https://davinci.vote) voting protocol. It
proves batches of encrypted ballots, the state transitions they cause and the
final tally inside the [ZisK](https://github.com/0xPolygonHermez/zisk) zkVM,
and returns PLONK proofs that Ethereum contracts verify. Sequencer operators
run it on a GPU host; sequencers call it over HTTP or through the Go and Rust
SDKs.

[![Build and Test](https://github.com/vocdoni/davinci-zkvm/actions/workflows/main.yml/badge.svg)](https://github.com/vocdoni/davinci-zkvm/actions/workflows/main.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)

## Overview

A DAVINCI sequencer collects encrypted ballots, groups them into batches and
settles each batch on Ethereum. Before it can settle, it needs a proof that
the batch is valid. It sends the batch to this service, which runs the whole
protocol check as one RISC-V program: every voter's ballot proof, signature
and census membership, the re-encryption of the ballots, the state-tree
updates, the encrypted tally and the layout of the EIP-4844 data blobs. ZisK
proves that execution and wraps it in a PLONK proof of 768 bytes plus 512
bytes of public values, whatever the batch size.

```text
voters --ballots--> sequencer --batch--> davinci-zkvm (GPU)
                        |     <--proof--
                        v
        Ethereum (settlement tx + blobs)
```

The service has two modes. In **per-batch mode** each batch gets its own
PLONK that the settlement contract verifies, and `POST /results` proves the
decrypted tally at the end. In **chained mode** batches are proved as STARKs
and folded recursively, and one final PLONK covers the whole election. See
[docs/architecture.md](docs/architecture.md).

Related repositories:

- [davinci-sequencer](https://github.com/vocdoni/davinci-sequencer): the
  sequencer node, built on this service and its Rust SDK.
- [davinci-contracts](https://github.com/vocdoni/davinci-contracts): the
  process registry and the on-chain verifier.
- [davinci-circom](https://github.com/vocdoni/davinci-circom): the ballot
  proof circuit voters run.
- [davinci-dkg](https://github.com/vocdoni/davinci-dkg): distributed
  generation of the election key.
- [davinci-fold](https://github.com/vocdoni/davinci-fold): chained-mode
  orchestration across several provers.
- [davinci-node](https://github.com/vocdoni/davinci-node): the Go reference
  implementation of the protocol.

## Quick start

You need a Linux host with an NVIDIA GPU with about 30 GB of memory (RTX 5090,
A100 40 GB), driver 570 or newer, Docker with Compose,
`nvidia-container-toolkit`, 64 GB of RAM and about 100 GB of free disk for the
proving keys. [docs/deployment.md](docs/deployment.md) has the details.

```bash
git clone https://github.com/vocdoni/davinci-zkvm.git
cd davinci-zkvm
make install   # download the ZisK proving keys into ./zisk-keys and build the image
make up        # start the prover on port 8080
curl -s localhost:8080/health
```

`make install` downloads about 100 GB and takes 20 to 60 minutes. The first
start builds GPU setup files for about a minute; follow it with `make logs`.

To run the published image instead of building it, set
`DAVINCI_ZKVM_IMAGE=ghcr.io/vocdoni/davinci-zkvm:latest` in `.env`, then run
`make keys`, `docker compose --profile cuda pull` and `make up`.
[docs/deployment.md](docs/deployment.md#automatic-updates) explains how to
follow new releases automatically.

## Usage

### Operating the service

| Command | Action |
|---|---|
| `make install` | Download the proving keys (`make keys`) and build the image (`make build`). |
| `make up` / `make down` / `make restart` | Start, stop or restart the prover. |
| `make logs` / `make status` / `make shell` | Follow the logs, show the container, open a shell in it. |
| `make clean` | Stop and delete the proofs volume. Keeps the proving keys. |
| `make test` | Run the integration suite against the running prover. |

`make help` lists every target, including a host install without Docker.

### Configuration

Set these in `.env` (start from `.env.example`) or on the command line:

| Variable | Default | Description |
|---|---|---|
| `ZISK_KEYS_DIR` | `./zisk-keys` | Directory holding the proving keys. |
| `LISTEN_PORT` | `8080` | Host port of the API. |
| `BIND_ADDR` | `0.0.0.0` | Host address the API binds to. |
| `DAVINCI_ZKVM_IMAGE` | local build | Image to run, for example `ghcr.io/vocdoni/davinci-zkvm:v0.1.0`. |
| `MAX_QUEUE_SIZE` | `100` | Maximum queued jobs. |
| `ZISK_MINIMAL_MEMORY_FROM` | `512` | Batch size from which the prover saves host RAM at a small speed cost. |
| `DAVINCI_KEEP_INPUTS` | `0` | Keep each job's private input for debugging. Leave off in production. |

The API has no authentication. Bind it to a private interface or firewall it
so that only your sequencer can reach it. The full list of variables is in
[docs/deployment.md](docs/deployment.md#configuration).

### HTTP API

Proving is asynchronous: submit a job, poll it, download the result.

```bash
curl -s -X POST localhost:8080/prove -H 'Content-Type: application/json' -d @batch.json
# {"job_id":"3f0c…","status":"queued"}
curl -s localhost:8080/jobs/3f0c…         # queued, running, done or failed
curl -s localhost:8080/jobs/3f0c…/snark   # the proof, once done
```

| Endpoint | Purpose |
|---|---|
| `POST /prove` | Prove a vote batch. |
| `POST /results` | Prove the decrypted tally of an election. |
| `POST /fold`, `POST /finalize`, `POST /jobs/import` | Chained mode. |
| `GET /jobs/{id}` | Job status. |
| `GET /jobs/{id}/snark` | `program_vk`, `root_c_vadcop_final`, `public_values`, `proof_bytes`: the arguments of `ZiskVerifier.verifySnarkProof`. |
| `GET /jobs/{id}/publics` | The guest's public outputs. |
| `GET /health` | Liveness and queue length. |

A finished job is not always an accepted batch: the guest proves invalid
input too, with its `ok` output set to 0. Check the public outputs before
settling. [docs/api.md](docs/api.md) documents every endpoint, the request
bodies and their encodings.

### Go SDK

```bash
go get github.com/vocdoni/davinci-zkvm/go-sdk
```

```go
import davinci "github.com/vocdoni/davinci-zkvm/go-sdk"

client := davinci.NewClient("http://localhost:8080")
result, err := client.Prove(ctx, batch) // batch is a *davinci.ProveBatch
if err != nil {
    return err
}
// result.Snark holds the four ZiskVerifier.verifySnarkProof arguments.
```

The Go SDK also drives chained mode (`go-sdk/chain`) and verifies proofs on
a simulated chain. See [go-sdk/README.md](go-sdk/README.md).

### Rust SDK

The crate `davinci-zkvm-sdk` has the client, the request types, parsers for
the public outputs, the DA blob builder, the pinned release values and the
protocol primitives needed to build a batch. Its `dkg` module converts keys
to the davinci-dkg point format and builds the organizer's proof of
possession for DKG-locked processes.

```toml
[dependencies]
davinci-zkvm-sdk = { git = "https://github.com/vocdoni/davinci-zkvm", tag = "v0.1.0" }
```

```rust
use std::time::Duration;
use davinci_zkvm_sdk::{client::ProverClient, publics::BatchPublics};

let prover = ProverClient::new("http://localhost:8080");
let id = prover.prove(&request).await?;
prover.wait(&id, Duration::from_secs(2), Duration::from_secs(1800)).await?;
let snark = prover.snark(&id).await?;
let publics = BatchPublics::from_public_values(&snark.public_values)?;
if !publics.passed() {
    // the guest rejected the batch; do not settle it
}
```

### On-chain verification

[`solidity/`](solidity/README.md) holds the ZisK PLONK verifier and a
reference per-batch settlement contract. Compare `program_vk` and
`root_c_vadcop_final` against the values pinned in `rust-sdk/src/release.rs`
rather than trusting the service.

## Documentation

- [docs/architecture.md](docs/architecture.md): the guests, the two modes and
  what a verifier must check.
- [docs/api.md](docs/api.md): HTTP API reference.
- [docs/deployment.md](docs/deployment.md): hardware, configuration,
  operation and troubleshooting.
- [docs/testing.md](docs/testing.md): unit, emulator, integration and
  benchmark suites.
- [circuit/CIRCUIT.md](circuit/CIRCUIT.md): specification of the vote-batch
  guest.
- [circuit-results/RESULTS.md](circuit-results/RESULTS.md): specification of
  the results guest.
- [BENCHMARK.md](BENCHMARK.md): measured proving times.
- [go-sdk/README.md](go-sdk/README.md) and
  [solidity/README.md](solidity/README.md).

## Development

```bash
cargo build --release -p davinci-zkvm-service
cargo test -p davinci-zkvm-service -p davinci-zkvm-sdk -p davinci-zkvm-input-gen
scripts/build-guests.sh   # rebuild the guest ELFs (needs the ZisK toolchain)
```

A guest change also changes its verification key, which the SDKs pin. Read
[CONTRIBUTING.md](CONTRIBUTING.md) before changing a guest or a wire format.

## License

GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE).
