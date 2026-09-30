# Benchmarks

Measured proving times. The first two sections are for the current guests on
ZisK 1.3.0-alpha; the chained-mode and older per-batch figures were taken on
ZisK 0.18 with earlier guests and are kept for comparison. Reproduce the
prover sweeps with `make benchmark` ([benchmark/](benchmark/README.md)) and
`TestPlonkBenchmark` ([docs/testing.md](docs/testing.md#benchmarks)).

## End-to-end throughput with two provers

**12.07 votes/s sustained (724 votes/min), 12.45 votes/s in steady state:
8192 votes proved and settled on-chain in 678.7 s on two RTX 5090 provers.**

Measured on 2026-09-28 with the davinci-sequencer throughput benchmark
(`e2e/tests/throughput.rs`, run through `e2e/bench.sh`, all in Docker):

- **Chain.** A fresh anvil chain (Osaka rules, 1 s blocks) with the
  `ProcessRegistry` and `ZiskVerifier`.
- **Provers.** Two provers, each serving one sequencer node. Each node
  sequences two Merkle-census processes of 2048 voters (nf=2,
  `--batch-max 512`), so its prover always has the next batch queued, and the
  two provers never share a process.
- **Ballots.** All 8192 circom ballot proofs are made before the clock
  starts (1326 s at about 6.2 proofs/s on one 16-core CPU). On a real network
  voters make them on their own devices.
- **Clock.** From the first vote submitted to the last transition settled
  on-chain. Every vote was accepted within 5 s and settled, and the four
  processes were then ended and tallied on-chain as cast.

| prover | host RAM | batches | first batch (512 votes) | steady batch (512 votes + 512 refreshes) | GPU busy | votes/s |
|---|---:|---:|---:|---:|---:|---:|
| host A (also runs anvil, the nodes and the harness) | 64 GB | 8 | 75.5–80.5 s | 84.5–87.1 s | 99% of wall | 6.03 |
| host B (remote) | 128 GB | 8 | 71.1–71.7 s | 78.3–83.0 s | 93% of wall | 6.44 |
| **total** | | **16** | | | | **12.07** |

- The GPUs are the bottleneck: each prover was busy for the whole span
  between its first and last job, with the next batch queued for about 70 s
  on average. Throughput scales with the number of provers; one RTX 5090
  settles about 6 votes/s at nf=2.
- A steady batch carries as many silent refreshes as votes. Batches of 512
  prove as fast per vote as 1024, need half the host RAM and settle twice as
  often.
- Settlement took 16 transactions and 28 blobs (one blob for a first batch,
  two for a steady one): 7.29 M gas in total, about 460 k per steady
  transition.
- Host A is about 7% slower per batch because it shares its CPU with the
  nodes, anvil and the harness.

| component | version |
|---|---|
| prover | `ghcr.io/vocdoni/davinci-zkvm:main`, image `sha256:8983782369e5c5070b2b1fb72442c1ca341ebb8db37b8114a40eaf86bc4a358a`, davinci-zkvm `0ccfae9`: ZisK 1.3.0-alpha GPU release binaries, CUDA 12.8 base, snarkjs 0.7.6 (batch vk `0x6cfc89d5…7a10`) |
| sequencer nodes | `ghcr.io/vocdoni/davinci-sequencer:main`, image `sha256:5e7e331422bd9ff2e1781d90a56fb8bd9585b2a7a81577538e305c2acf4bb6b6` (davinci-sequencer `8e54dba`) |
| harness | davinci-sequencer `e2e/Dockerfile.bench`: Rust 1.95, foundry v1.8.3 (anvil, forge) |
| contracts | davinci-contracts `zkvm` branch, `8dbaa20` |
| ballot circuit | davinci-circom `a39a9f9` artifacts |

Hardware: two hosts, each an AMD Ryzen 9 9950X3D (16 cores, 32 threads) and
one NVIDIA RTX 5090 (32 GB, driver 580.178.04, 575 W power limit), Ubuntu
26.04 with kernel 7.0 and Docker 29. Host A has 64 GB of RAM (the prover was
capped at 56 GB), host B 128 GB. Both provers ran with
`ZISK_MINIMAL_MEMORY_FROM=2048`, so no batch used `--minimal-memory`.

Reproduce:

```bash
# on each GPU host:
DAVINCI_ZKVM_IMAGE=ghcr.io/vocdoni/davinci-zkvm:main docker compose --profile cuda up -d
# on the driver host, from davinci-sequencer:
DAVINCI_E2E_BENCH_PROVERS=http://<prover-a>:8080,http://<prover-b>:8080 \
DAVINCI_E2E_BENCH_VOTES=2048 DAVINCI_E2E_BENCH_PROCS=2 \
DAVINCI_E2E_BENCH_BATCH=512 DAVINCI_E2E_BENCH_NF=2 e2e/bench.sh
```

## Per-batch mode

One RTX 5090, ZisK 1.3.0-alpha release binaries, measured 2026-09-23 with
`TestPlonkBenchmark`, which asserts that the guest accepted every batch.
Times are the service's job time: witness generation, STARK, recursion,
PLONK wrap and ZisK's own check of the result. "first" is the first batch of
an election, which has nothing to refresh; "steady" is the second, which
refreshes as many slots as it writes and is the number that matters for
throughput. `nf` is the election's ballot field count; votes/min is batch
size over the steady time.

| batch | first (nf=2) | steady (nf=2) | votes/min | blobs | first (nf=16) | steady (nf=16) | votes/min | blobs |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|    2 |  15.5 s |  15.6 s |   8 | 1 |  16.3 s |  15.7 s |   8 | 1 |
|   64 |  22.0 s |  22.5 s | 171 | 1 |  27.4 s |  30.3 s | 127 | 2 |
|  128 |  28.5 s |  30.1 s | 255 | 1 |  40.7 s |  45.7 s | 168 | 3 |
|  256 |  42.6 s |  46.2 s | 332 | 1 |  66.3 s |  76.7 s | 200 | 5 |
|  512 |  76.6 s |  84.3 s | 364 | 2 | 139.4 s | 164.3 s | 187 | 9 |
| 1024 | 154.5 s | 171.2 s | 359 | 3 | 311.0 s | 363.9 s | 169 | 17 |

- The fixed cost (recursion, PLONK wrap, verification) is about 15.5 s. A
  refresh costs about 13 ms at 2 fields and 40 ms at 16 (re-encryption, one
  SMT update, two leaf hashes and its share of the blob evaluation).
- The per-vote cost grows slowly with the batch (deeper census proofs,
  `--minimal-memory` from 512), so throughput peaks around 512 votes at 2
  fields and 256 at 16.
- Host RAM, not the GPU, bounds the batch size. The GPU peaks at about
  30.4 GB for every size from 128 up, while the prover needs about 54 GB of
  host RAM for the 1024-vote steady batch without `--minimal-memory` and
  41.5 GB with it. The service uses the flag from 512 ballots, so those rows
  include it (a few percent; matched runs on ZisK 0.18 measured +0.7% to
  +2.7%).
- A transaction carries at most 6 blobs (EIP-7594), and the settlement
  contract reads all of a transition's blobs from one transaction, so rows
  above 6 blobs are proving figures only. `davinci.MaxSingleTxBatch(nf)`
  gives the largest settleable batch (1024 up to 5 fields, 366 at 16).
- The proof is 768 bytes plus 512 bytes of public values at every size.

Settling a transition with `solidity/DavinciSettlement.sol` on the simulated
chain (PLONK verification, root, census and occupied-slot checks, the blob
digest and one point evaluation per blob):

| blobs | gas |
|---:|---:|
| 1 (128 votes at nf=2, or up to about 120 updates at nf=16) | ~498 k |
| 2 | ~554 k |
| 3 (128 votes + 128 refreshes at nf=16) | ~612 k |
| 4 (128 overwrites + 256 refreshes at nf=16) | ~667 k |

## Chained mode (ZisK 0.18)

1024-vote elections, one final PLONK. These predate the BabyJubJub
precompile, silent refreshes and the 64-level state tree, and used 8-field
ballots and a batch cap of 256. Ballot inputs are generated before the clock
starts; the clock covers batch STARKs, folds and finalize (decryption-proof
checks, results inclusion and the PLONK wrap).

| batch | fold every | folds | stark avg / batch | fold avg | finalize | total | votes/s | on-chain verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|  64 | 4 | 4 | 35.3 s | 23.9 s | 25.2 s | 11m26s | 1.49 | 0.51 s |
| 128 | 4 | 2 | 55.5 s | 27.6 s | 25.2 s |  8m45s | 1.95 | 0.37 s |
| 256 | 2 | 2 | 1m35s | 25.1 s | 25.2 s |  7m34s | 2.25 | 0.51 s |

- One on-chain verification per election, whatever the vote count.
- The first fold includes a bootstrap fold that learns the aggregator vk
  (about 35 s against 20 s for a steady fold).
- Finalize is a per-election constant of about 25 s.
- Batches and folds share one GPU; folds are 5–7% of the total.

With 16-field ballots through the davinci-fold orchestrator (single worker,
including the export and import of proofs between workers), 1024 votes at
batch 128 and fold every 4 took 14m39s (1.17 votes/s): 1m40s per batch
STARK, 27.5 s per fold, 25.4 s finalize.

At 5120 votes (batch 256, fold every 4) the run took 36m25s (2.34 votes/s),
with the batch STARK average 8% above the 1024-vote run because the GPU
throttled over the longer run. Extrapolating that sustained rate, a
20000-vote election at batch 250 and fold every 8 would take about 2h18m
(2.41 votes/s), 96% of it batch proving.

## Earlier per-batch measurements

ZisK 0.18, one PLONK per batch, before silent refreshes and DA binding:

| batch | PLONK (nf=2) | PLONK (nf=16) | on-chain verify |
|---:|---:|---:|---:|
|  64 |  38 s |  83 s | ~0.3–0.5 s |
| 128 |  73 s | 164 s | ~0.5 s |
| 256 | 102 s | 289 s (`--minimal-memory`) | ~0.3 s |

At 16 fields, batch 256 overflowed the 32 GB GPU under the default schedule
and fit only with `--minimal-memory` (31.3 GB peak), which kept the batch cap
at 128 on that release. ZisK 1.3 reserves its GPU memory up front and the
overflow does not occur.

ZisK 1.3.0-alpha with the BabyJubJub precompile, before silent refreshes and
DA binding (256 and 512 measured on a test build with a raised batch cap):

| batch | proof (nf=2) | votes/min | proof (nf=16) | votes/min |
|---:|---:|---:|---:|---:|
|  64 |  22.6 s | 170 |  28.2 s | 136 |
| 128 |  29.9 s | 257 |  40.3 s | 190 |
| 256 |  51.1 s | 300 |  73.8 s | 208 |
| 512 |  71.3 s | 431 | 123.5 s | 249 |

STARK only, 6 fields, same inputs on both releases:

| batch | ZisK 0.18 | ZisK 1.3 + precompile | speedup |
|---:|---:|---:|---:|
|  64 | 61.2 s | 22.6 s | 2.71x |
| 128 | 94.0 s | 32.8 s | 2.87x |

The speedup combines the ZisK upgrade and the precompile.

## Comparing the modes

On ZisK 0.18, per-batch mode had the higher prover throughput (2.9 votes/s
against 2.25 for chained mode at batch 256), but it costs one Ethereum
verification per batch, while chained mode lands a whole election on-chain
as one proof, however many votes it has. Past a handful of batches chained
mode is cheaper on-chain; per-batch mode settles every batch, with its data
availability, on Ethereum as it happens.
