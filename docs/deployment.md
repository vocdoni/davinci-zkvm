# Running a prover

This guide covers hardware, installation, configuration and operation of the
prover service. The [README](../README.md#quick-start) has the short version.

## Requirements

| Resource | Needed |
|---|---|
| GPU | NVIDIA with about 30 GB of memory: RTX 5090 (32 GB) or A100 (40 GB) work, 24 GB cards do not. Driver 570 or newer. |
| Host RAM | 64 GB for the largest batches. A 1024-ballot batch with 1024 silent refreshes peaks at about 41 GB with `--minimal-memory` and 54 GB without. |
| Disk | About 100 GB for the ZisK proving keys (STARK about 73 GB, PLONK about 25 GB), plus room for proofs. |
| Software | Linux x86_64, Docker with Compose, `nvidia-container-toolkit`. No CUDA toolkit: the ZisK GPU binaries are statically linked against the CUDA runtime. |

A prover works on one job at a time and keeps the GPU busy for the whole
job, so throughput scales with the number of provers, not with the size of
one host. [BENCHMARK.md](../BENCHMARK.md) has measured proving times per
batch size.

## Install with Docker

```bash
git clone https://github.com/vocdoni/davinci-zkvm.git
cd davinci-zkvm
make install
make up
```

`make install` runs two steps you can also run separately:

- `make keys` runs the official `ziskup` in a helper container and writes
  both proving keys to `./zisk-keys` (`ZISK_KEYS_DIR` to change it). It takes
  20 to 60 minutes depending on bandwidth and is idempotent. It also clears
  the executable-stack flag of the PLONK key's `final.so`, which current Linux
  kernels refuse to load otherwise.
- `make build` builds the prover image (`Dockerfile.cuda`) from the checkout.

On its first start the container builds the GPU setup files into the key
directory (about a minute), so the key directory must be writable. Later
starts skip this. Check the service with `make status`, `make logs` and
`curl localhost:8080/health`.

### Published images

Images are published to `ghcr.io/vocdoni/davinci-zkvm` and
`vocdoni/davinci-zkvm` on Docker Hub. Release tags (`v0.1.0`) publish the
same tag and move `latest`; branch pushes publish under the branch name
(`main`). To run a published image instead of building one:

```bash
make keys
echo 'DAVINCI_ZKVM_IMAGE=ghcr.io/vocdoni/davinci-zkvm:latest' >> .env
docker compose --profile cuda pull
make up
```

A release that changes a guest also changes its program vk, which the
contracts and the sequencers pin, so provers, contracts and sequencers move
to such a release together.

### Automatic updates

The `watchtower` Compose profile follows the image tag the prover runs and
restarts it when a new image is published:

```bash
docker compose --profile cuda --profile watchtower up -d
```

Watchtower checks every five minutes. A restart drops the job in progress
and the in-memory job list, so sequencers must resubmit unfinished jobs.

## Configuration

With Docker Compose, set these in `.env` (copy `.env.example`) or on the
command line:

| Variable | Default | Description |
|---|---|---|
| `ZISK_KEYS_DIR` | `./zisk-keys` | Host directory holding `provingKey/` and `provingKeySnark/`. |
| `LISTEN_PORT` | `8080` | Host port of the API. |
| `BIND_ADDR` | `0.0.0.0` | Host address the port binds to. Set a private address to keep the API off public interfaces. |
| `DAVINCI_ZKVM_IMAGE` | `davinci-zkvm-cuda:latest` | Image to run. The default is the one `make build` produces. |
| `ZISK_TAG`, `ZISK_VERSION` | `v1.3.0-alpha`, `1.3.0-alpha` | ZisK release for the image and the keys. Keep them in sync and matching the guests. |
| `MAX_QUEUE_SIZE` | `100` | Jobs waiting at most; further submits get `503`. |
| `ZISK_MINIMAL_MEMORY_FROM` | `512` | Batches with at least this many ballots prove with `--minimal-memory` from the first attempt. |
| `ZISK_MINIMAL_MEMORY` | `0` | `1` uses `--minimal-memory` for every job. |
| `ZISK_MPI_PROCS` | `1` | MPI processes per proof; above 1 the prover runs under `mpirun`. |
| `ZISK_MPI_THREADS` | `0` | Threads per MPI process (`0` lets MPI decide). |
| `ZISK_MPI_BIND_TO` | `none` | `mpirun --bind-to` policy. |
| `DAVINCI_KEEP_INPUTS` | `0` | `1` keeps each job's `input.bin` and serves it on `GET /jobs/{id}/inputs`. |

The service itself reads these variables; the image sets the paths:

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `0.0.0.0:8080` | Listen address. |
| `PROVING_KEY_PATH` | `/proving-key` | STARK proving key directory. Required at startup. |
| `PROVING_KEY_PLONK_PATH` | `/proving-key-plonk` | PLONK proving key directory. Required at startup. |
| `CIRCUIT_ELF_PATH` | `/app/circuit.elf` | Vote-batch guest ELF. Required at startup. |
| `RESULTS_ELF_PATH` | `circuit-results/elf/results.elf` | Results guest ELF (the image sets `/app/results.elf`). Required at startup. |
| `AGGREGATOR_ELF_PATH` | `/app/aggregator.elf` | Aggregator guest ELF, used by chained mode. |
| `CARGO_ZISK_BIN` | `cargo-zisk` | Prover binary. |
| `PROOF_OUTPUT_DIR` | `/tmp/proofs` | Per-job working directories (`/proofs` volume in the image). |
| `RUST_LOG` | `davinci_zkvm=info,tower_http=info` | Log filter. |

## Operating notes

**Protect the API.** It has no authentication, and every job costs minutes
of GPU time. Bind it to a private interface (`BIND_ADDR`) or put it behind
a firewall or an authenticating proxy, and let only your sequencer reach it.

**Keep the witness private.** A job's `input.bin` holds the batch
re-encryption seed and which ballot slots were overwritten or refreshed; with
it, anyone can tell overwrites from refreshes. The service deletes it after
proving. Leave `DAVINCI_KEEP_INPUTS` off outside development.

**Memory.** Host RAM, not the GPU, limits the batch size. The service turns
on `--minimal-memory` from `ZISK_MINIMAL_MEMORY_FROM` ballots; it proves the
same statement a few percent slower. Give the container a memory limit (or run
a host install under `systemd-run --user -p MemoryMax=...`) so that an
overflow kills the prover and not the host. The kernel OOM kill of the prover
(`signal: 9`) is retried with `--minimal-memory`.

**Retries.** Some ZisK failures are transient: a destroyed CUDA context on
the first proof after start, a Fiat-Shamir challenge mismatch, witness
failures inside the recursion stage, an internal counter timeout, an OOM
kill, and a rejected PLONK self-check. The worker retries these up to three
times, from the second attempt with `--minimal-memory`. Failures that repeat
on every attempt are real, for example a stale proving key.

**Job storage.** Each job writes to `PROOF_OUTPUT_DIR/<job_id>/`. The service
does not delete finished jobs; clean old directories up if disk space
matters.

## Install without Docker

For development on a GPU host the Makefile also drives a host install:

```bash
make local-setup   # install ZisK, the proving keys and snarkjs, build the service
make local-run     # run it on 127.0.0.1:8080
make local-test    # start it and run the integration suite
```

`make local-setup` runs `scripts/install.sh`. It needs `rustc`, `cargo`,
`go`, `git`, `make`, `curl` and `npm`, and on apt-based systems installs the
remaining system packages (`INSTALL_SYSTEM_DEPS=0` to skip). It installs ZisK
with `ziskup` under `~/.zisk` (`ZISK_HOME`), including the proving keys and
the guest toolchain, patches `final.so`, builds the GPU setup files
(`RUN_SETUP_TREES=0` to skip), builds `target/release/davinci-zkvm` and writes
the runtime environment to `.env.local.nodocker`. It also appends a loader
for that file to `~/.bashrc` unless `ADD_TO_SHELL_RC=0`.

The prover's own PLONK check runs `snarkjs plonk verify`, so `snarkjs` must be
on the `PATH` of the service; the image and the install script provide
version 0.7.6.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `make up` says the proving keys are missing | Run `make keys`, or point `ZISK_KEYS_DIR` at the directory holding `provingKey/` and `provingKeySnark/`. |
| The service exits at start with "proving key not found" or "ELF not found" | A path variable is wrong or a volume is not mounted. |
| PLONK jobs fail with "cannot enable executable stack" | `final.so` was not patched. Run `make keys` again (it is idempotent), or make the key directory writable so the container patches it at start. |
| PLONK jobs fail with `Failed to execute snarkjs` | `snarkjs` is not on the `PATH` (host installs only). Install `snarkjs@0.7.6`. |
| `/health` answers `503` | The prover worker stopped. Check the logs and restart the service. |
| Every job of a given size is OOM-killed | Lower `ZISK_MINIMAL_MEMORY_FROM`, submit smaller batches, or add RAM. |
