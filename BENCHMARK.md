# Benchmarks

The first section is the current end-to-end figure: the whole DAVINCI stack,
ballots in and settled state transitions out, on two GPU provers. The
per-batch sections below measure the prover alone on one RTX 5090. The
chained-mode and older per-batch tables are ZisK v0.18.0 and kept as history;
the numbers on ZisK 1.3.0-alpha with the BabyJubJub precompile are in
"Per-batch mode on ZisK 1.3" and "Per-batch mode with silent refreshes and DA
binding". Reproduce the prover sweeps with `make benchmark` (see
`benchmark/README.md`); raw logs and the generated table land in
`benchmark/results/`.

## End-to-end throughput with two provers

**12.07 votes/s sustained (724 votes/min), 12.45 votes/s in steady state:
8192 votes proved and settled on-chain in 678.7 s on two RTX 5090 provers.**

Measured on 2026-09-28 with the davinci-sequencer throughput benchmark
(`e2e/tests/throughput.rs`, run through `e2e/bench.sh`, which runs everything
in Docker). The setup:

- **Chain.** A fresh anvil chain (Osaka rules, 1 s blocks) with the
  `ProcessRegistry` and `ZiskVerifier`.
- **Provers.** Two provers, each serving one sequencer node. Each node
  sequences two origin-1 processes of 2048 voters (nf=2, `--batch-max 512`),
  so its prover always has the next batch queued. The two provers never race
  on one process's root chain.
- **Ballots.** All 8192 circom ballot proofs are made before the clock starts:
  1326 s at about 6.2 proofs/s on one 16-core CPU. On a real network voters
  make them on their own devices.
- **The clock.** It runs from the first vote submitted to the last transition
  settled on-chain. Every vote was accepted within 5 s. Every one settled, and
  all four processes were then ended and tallied on-chain: [6144, 6144] each,
  as cast.

| prover | host RAM | batches | first batch (512 votes) | steady batch (512 votes + 512 refreshes) | GPU busy | votes/s |
|---|---:|---:|---:|---:|---:|---:|
| z6 (local, also runs anvil, the nodes and the harness) | 64 GB | 8 | 75.5–80.5 s | 84.5–87.1 s | 99% of wall | 6.03 |
| z7 (over WireGuard, 10.200.0.0/24) | 128 GB | 8 | 71.1–71.7 s | 78.3–83.0 s | 93% of wall | 6.44 |
| **total** | | **16** | | | | **12.07** |

- The GPUs are the bottleneck: each prover was busy 100% of the span between
  its first and last job, and the queue held the next batch for about 70 s on
  average. Throughput therefore scales with the number of provers. One RTX
  5090 settles about 6 votes/s at nf=2, the same rate the single-prover sweep
  below measures for 512- and 1024-vote batches.
- **Batch sizes.** A steady batch carries as many silent refreshes as votes,
  so a vote costs one ballot write plus one re-randomized slot. Batches of 512
  prove as fast per vote as 1024, need half the host RAM, and settle twice as
  often.
- **Settlement.** It took 16 transactions and 28 blobs: one blob for a first
  batch, two for a steady one. That is 7.29 M gas in total, about 460 k per
  steady transition.
- **z6 vs z7.** z6 is about 7% slower per batch because it shares its CPU with
  the nodes, anvil and the harness. An earlier run with z6 in
  `--minimal-memory` mode (the default from 512 proofs) and z7 at its 500 W
  default gave 11.43 votes/s overall and 12.01 steady. Turning minimal-memory
  off on z6 and running z7 at 575 W gave the numbers above.

Software, all from the CI images:

| component | version |
|---|---|
| prover | `ghcr.io/vocdoni/davinci-zkvm:main`, image `sha256:8983782369e5c5070b2b1fb72442c1ca341ebb8db37b8114a40eaf86bc4a358a`, built from davinci-zkvm `0ccfae9`: ZisK 1.3.0-alpha GPU release binaries, CUDA 12.8 base, snarkjs 0.7.6, the guest ELFs of this repo (batch vk `0x6cfc89d5…7a10`) |
| sequencer nodes | `ghcr.io/vocdoni/davinci-sequencer:main` at `sha256:5e7e331422bd9ff2e1781d90a56fb8bd9585b2a7a81577538e305c2acf4bb6b6` (davinci-sequencer `8e54dba`) |
| harness | davinci-sequencer `e2e/Dockerfile.bench`: Rust 1.95, foundry v1.8.3 (anvil, forge) |
| contracts | davinci-contracts `zkvm` branch, `8dbaa20` |
| ballot circuit | davinci-circom `a39a9f9` artifacts |

Hardware: two identical hosts, each an AMD Ryzen 9 9950X3D (16 cores, 32
threads) and one NVIDIA RTX 5090 (32 GB, driver 580.178.04, 575 W power
limit), Ubuntu 26.04 with kernel 7.0 and Docker 29. They differ only in RAM:
z6 has 64 GB and z7 128 GB. The z6 prover was capped at 56 GB. Each prover ran
with `ZISK_MINIMAL_MEMORY_FROM=2048`, so no batch used `--minimal-memory`.

Reproduce:

```bash
# on each GPU host (see the README's Docker section):
DAVINCI_ZKVM_IMAGE=ghcr.io/vocdoni/davinci-zkvm:main docker compose --profile cuda up -d
# on the driver host, from davinci-sequencer:
DAVINCI_E2E_BENCH_PROVERS=http://127.0.0.1:8080,http://10.200.0.27:8080 \
DAVINCI_E2E_BENCH_VOTES=2048 DAVINCI_E2E_BENCH_PROCS=2 \
DAVINCI_E2E_BENCH_BATCH=512 DAVINCI_E2E_BENCH_NF=2 e2e/bench.sh
```

## Chained mode — 1024-vote election, one final PLONK

Ballot inputs (Groth16 proofs, signatures, census proofs) are generated
on voters' devices, so they are pre-generated and cached before the
clock starts. The timed section is the sequencer's critical path: batch
STARK proves, recursive folds, and the finalize step (Chaum-Pedersen
decryption verification + results inclusion + PLONK wrap).

| batch | fold every | folds | stark avg / batch | fold avg | finalize | total | votes/s | on-chain verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|  64 | 4 | 4 | 35.3s | 23.9s | 25.2s | 11m26s | 1.49 | 0.51 s |
| 128 | 4 | 2 | 55.5s | 27.6s | 25.2s |  8m45s | 1.95 | 0.37 s |
| 256 | 2 | 2 | 1m35s | 25.1s | 25.2s |  7m34s | 2.25 | 0.51 s |

- One on-chain verification per **election**, regardless of vote count.
  The final 2.7 KB PLONK attests genesis-state correctness, every batch
  transition (recursive STARK verification), and the decrypted results.
- The first fold includes a one-off bootstrap fold that teaches the
  sequencer the aggregator program_vk (~2x a steady-state fold, ~35s vs
  ~20s); amortized to zero over an election.
- Finalize is a per-election constant (~25s), independent of vote count.
- Batches and folds serialize on the single GPU; fold overhead is ~5–7%
  of total time. A second service instance would pipeline batching and
  folding.
- All rows are on the v0.18 batch circuit of the time: SMT node-hash skip
  on padding levels, lazy SMT leaf hashing, and projective re-encryption
  equality (fixed-base windowed scalar mul + projective accumulators, no
  per-point inversion). The ZisK 1.3 guest replaces the last with the
  BabyJubJub precompile (`circuit/CIRCUIT.md` §15). These lifted
  throughput ~12–25% over the previous sweep (64: 1.33→1.49, 128:
  1.68→1.95, 256: 1.80→2.25 v/s) even with the added process-config
  inclusion-proof verification now in-circuit.
- **The batch cap was 128 at the time** (`MAX_BATCH_SIZE`); it is 1024
  on ZisK 1.3, see the per-batch sections below. It had been **lowered
  from 256 to 128 for GPU-memory safety** (see the per-batch section below): batch 256 at full
  ballot capacity peaks ~31.3 GB even under `--minimal-memory`, leaving no
  headroom on the 32 GB GPU. The chained-mode tables above (and the 5120 /
  20000 rows below) were measured under the previous 256 cap and at the
  8-field era; they are retained as historical references. A 16-field
  measurement is below.

### 16-field refresh — 1024 votes through the davinci-fold orchestrator

Same GPU, measured end-to-end through the davinci-fold orchestrator
(ingest → seal → scatter batch STARKs → import onto the fold worker →
fold chain → keywarden handshake → finalize PLONK, verified on a
simulated on-chain verifier) with a single worker. The clock runs from
vote submission to published verified results; ballot pre-generation is
excluded as above.

| votes | batch | fold every | folds | stark avg / batch | fold avg | finalize | total | votes/s |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1024 | 128 | 4 | 2 | 1m40s | 27.5s | 25.4s | 14m39s | 1.17 |

- The 16-field ballot (vs 8 at the historical rows) puts the batch STARK
  at ~1.7x the old 128 row (95s steady; 1m40s avg includes the
  scatter/import round-trip). Folds and finalize are unchanged:
  bootstrap fold 35.0s, steady fold 20.0s, finalize 25.4s.
- Orchestrator overhead (HTTP, proof export/import between workers) is
  included, so this is the deliverable pipeline number, not a
  raw-sequencer bound.

## Scaling — 5120 votes measured, 20000 projected

Larger elections amortize the per-election finalize constant toward zero
and let folds use a wider fan-in, so throughput rises slightly above the
1024-vote rows. Measured at 5120 votes (batch 256, fold every 4):

| votes | batch | fold every | folds | stark avg / batch | steady fold | finalize | total | votes/s | on-chain verify |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 5120 | 256 | 4 | 5 | 1m42s | 20.0s | 25.1s | 36m25s | 2.34 | 0.50 s |

The batch STARK average is ~8% above the 1024-vote rows (1m42s vs 1m35s):
over a 34-min continuous batch-proving stretch the GPU thermally
throttles, where the short 1024-vote run stayed cool. The steady fold
holds dead flat at 20.0s across all four steady folds; the first fold is
the usual ~35s bootstrap.

**Projected 20000 votes**, best config (batch 250 → 80 batches, fold
every 8 → 10 folds), using the sustained 5120 rates:

| term | basis | time |
|---|---|---|
| batch proving | 20000 × 0.399 s/vote (sustained) | ~7990 s |
| folds | 1 bootstrap (~41s) + 9 steady 9-inner (~26s) | ~275 s |
| finalize | per-election constant | 25 s |
| **total** | | **~2h18m** |
| **throughput** | | **~2.41 votes/s** |

One on-chain verification (~0.5 s) for the whole 20000-vote election. The
projection rests on the sustained (already-throttled) batch rate, so the
real 80-batch run should land close rather than degrade further. Batch
proving is ~96% of the time; fold cadence moves the total by ~1–2%.

## Per-batch mode — one PLONK + one on-chain verification per batch

Ballot capacity is 16 fields; the guest skips per-field EC work on padded
slots, so PLONK time scales with the election's declared `num_fields`, not
the 16-field max (sweep with `BALLOT_NUM_FIELDS`):

| batch | PLONK (num_fields=2) | PLONK (num_fields=16) | on-chain verify |
|---:|---:|---:|---:|
|  64 |  38 s |    83 s | ~0.3–0.5 s |
| 128 |  73 s |   164 s | ~0.5 s |
| ~~256~~ | 102 s | 289 s (min-mem) | ~0.3 s |

128 was the `MAX_BATCH_SIZE` cap on v0.18; the 256 row is retained as the
corner that motivated it. On ZisK 1.3 the cap is 1024. `proofBytes` is 768 B / `publicValues` 256 B (512 B on ZisK 1.3) regardless of
batch or field count.

**Why the cap was 128 on v0.18.** At num_fields=16 the per-field chained reencryption
makes the `ArithEq` trace large enough that batch 256 overflows the 32 GB GPU
under the default schedule (deterministic SIGKILL during inner-proof
generation). `cargo-zisk prove --minimal-memory` reschedules witness storage
and holds the footprint at a ~31.3 GB peak, proving+verifying in ~289 s — but
that is within ~0.7 GB of the ceiling with no softer knob left, so any future
circuit growth would push batch 256 over with no recovery path. We capped
`MAX_BATCH_SIZE` at 128, which proves comfortably. `--minimal-memory` stays
wired as a backstop (auto-escalated on retry; force from the first attempt
with `ZISK_MINIMAL_MEMORY=1`): it only reschedules witness storage — it
doesn't change the circuit, constraints, or the proven statement, so the
result still verifies and soundness is unaffected. The speed cost is small: a
matched A/B on one batch-128 num_fields=16 input measured 138.4 s plain vs
142.1 s with `--minimal-memory` (+2.7%); on a lighter input it was +0.7%.

## Per-batch mode on ZisK v1.3.0-alpha + BabyJubJub precompile

Same GPU, release binaries via ziskup (64 and 128; the starred rows were
measured on the pre-release build of the same version), measured with
`TestPlonkBenchmark` (`BENCH_SIZES`, `BALLOT_NUM_FIELDS`). "proof" is the
service's job time for one batch: witness generation, STARK, recursion, PLONK
wrap and ZisK's own verification of the result. The sequencer's per-batch
throughput is batch / proof; nothing else sits on that path. Ballot generation
(voter side, ~1.4 s per vote on this CPU) is excluded, as is the on-chain
verify (0.3–0.7 s on the simulated chain).

| batch | proof (num_fields=2) | votes/min | proof (num_fields=16) | votes/min |
|---:|---:|---:|---:|---:|
|  64 |  22.6 s | 170 |  28.2 s | 136 |
| 128 |  29.9 s | 257 |  40.3 s | 190 |
| 256* |  51.1 s | 300 |  73.8 s | 208 |
| 512* |  71.3 s | 431 | 123.5 s | 249 |

\* Above the production `MAX_BATCH_SIZE` (128). Measured on a scratch guest
with the cap raised to 512 (the three mirrored constants, nothing else); the
tracked ELF and vks are unchanged. Both sizes proved on the first attempt
with no `--minimal-memory` fallback: 1.3 reserves its ~28 GiB unified GPU
buffer up front and schedules inside it, so the v0.18 batch-256 OOM does not
reproduce. Raising the cap for production is a rebuild of both guests (new
program vks, `CircuitRelease` refreeze).

Against the v0.18 table above, batch 128 at 16 fields went from 164 s to
40.3 s (4.1x) and batch 64 at 2 fields from 38 s to 22.6 s. The fixed
per-proof cost (recursion + PLONK wrap, ~15 s) now dominates small batches,
which is why votes/min keeps climbing with batch size: the marginal cost is
~0.11 s per vote at 2 fields and ~0.19 s at 16.

STARK only, num_fields=6, same input files on both stacks (the 1.3 column
on the pre-release build of the same version), both verified:

| batch | v0.18.0 | 1.3 + precompile | speedup | votes/min |
|---:|---:|---:|---:|---:|
|  64 | 61.2 s | 22.6 s | 2.71x | 63 -> 170 |
| 128 | 94.0 s | 32.8 s | 2.87x | 82 -> 234 |

Two variables move at once there (ZisK version and the precompile), so treat
the speedup as the combination, not the precompile alone.

## Per-batch mode with silent refreshes and DA binding

Same GPU and release binaries, after the guest gained the silent-refresh
chain, the in-guest DA blob construction and the results pin (all on by
default; `TestPlonkBenchmark` now proves two batches per size on one
election). "first" is the first batch of an election, which has nothing to
refresh; "steady" is the second, which refreshes `RefreshTarget(size, 0,
size) = size` slots on top of its own votes and is the number that matters
for throughput. Both include ZisK's own verification of the result.

| batch | first (nf=2) | steady (nf=2) | votes/min | blobs | first (nf=16) | steady (nf=16) | votes/min | blobs |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
|    2 |  15.5 s |  15.6 s |   8 | 1 |  16.3 s |  15.7 s |   8 | 1 |
|   64 |  22.0 s |  22.5 s | 171 | 1 |  27.4 s |  30.3 s | 127 | 2 |
|  128 |  28.5 s |  30.1 s | 255 | 1 |  40.7 s |  45.7 s | 168 | 3 |
|  256 |  42.6 s |  46.2 s | 332 | 1 |  66.3 s |  76.7 s | 200 | 5 |
|  512 |  76.6 s |  84.3 s | 364 | 2 | 139.4 s | 164.3 s | 187 | 9 |
| 1024 | 154.5 s | 171.2 s | 359 | 3 | 311.0 s | 363.9 s | 169 | 17 |

Measured 2026-09-23 on the 64-level state tree with slot binding. The
earlier table's 512 and 1024 rows were proved on batches the guest had
rejected with FAIL_CENSUS (the harness repeated voter addresses every 256
voters), so they skipped the census Merkle verification and were 25-35% too
optimistic; `TestPlonkBenchmark` now asserts the guest's ok flag.

A refresh costs about 13 ms at 2 fields and 40 ms at 16 fields (the
re-encryption, one SMT update, two leaf hashes and its share of the blob
evaluation); at `KAPPA = 1` that is +6% and +12% on a 128-vote batch. The
fixed cost is 15.5 s. The per-vote cost grows slowly with the batch (deeper
census proofs, `--minimal-memory` from 512), so throughput peaks around 512
votes at 2 fields (~360 votes/min) and 256 at 16 fields (~200 votes/min)
and eases off at 1024.

`MAX_BATCH_SIZE` is 1024. The limit is host RAM, not the GPU: the GPU peaks
at ~30.4 GiB for every size from 128 up, while the prover's resident memory
for the 1024-vote steady transition is ~54 GB without `--minimal-memory`
(OOM-killed on this 64 GB machine) and 41.5 GB with it. The service therefore
uses the flag from 512 proofs up (`ZISK_MINIMAL_MEMORY_FROM`), so the >= 512
rows carry it (a few percent). EIP-7594 caps a transaction at 6 blobs and the
settlement contract reads all of a transition's blobs from one transaction,
so the rows above 6 blobs are proving figures only; a per-batch sequencer
sizes its batches with `davinci.MaxSingleTxBatch(nf)` (366 at 16 fields, 1024
up to 5 fields), which costs no throughput since the fastest batches fit.

Settling a transition through `solidity/DavinciSettlement.sol` on the
simulated chain (PLONK verification, root and census checks, the
occupied-slot check, the blob digest and one point evaluation per blob):

| blobs | gas |
|---:|---:|
| 1 (128 votes at nf=2, or up to ~120 updates at nf=16) | ~498 k |
| 2 | ~554 k |
| 3 (128 votes + 128 refreshes at nf=16) | ~612 k |
| 4 (128 overwrites + 256 refreshes at nf=16) | ~667 k |

## Comparing the modes

Per-batch mode has higher raw throughput — chained-mode batches do more
work in-circuit (ballot re-encryption into the homomorphic accumulators
replaces the KZG block) — but it costs one Ethereum verification per
batch: 1024 votes at batch 256 is 4 on-chain transactions vs 1.

Chained mode trades ~1.3x prover throughput (at batch 256: 2.9 v/s
per-batch vs 2.25 v/s chained) for a constant on-chain footprint: a
1024-vote election lands on-chain as a single proof, and a 1M-vote
election would too. Past a handful of batches, chained mode is strictly
cheaper on-chain and the only mode that scales to large elections.
