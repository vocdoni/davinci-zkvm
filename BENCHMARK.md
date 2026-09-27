# Benchmarks

Measured on a single NVIDIA RTX 5090 (59 GB host RAM). The chained-mode
and historical per-batch tables are ZisK v0.18.0; the current per-batch
numbers on ZisK 1.3.0-alpha with the BabyJubJub precompile are in the
"Per-batch mode on ZisK 1.3" section.
Reproduce with `make benchmark` (see `benchmark/README.md`); raw logs and
the auto-generated table land in `benchmark/results/`.

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
- All rows are on the fully-optimized batch circuit: SMT node-hash skip
  on padding levels, lazy SMT leaf hashing, and projective re-encryption
  equality (fixed-base windowed scalar mul + projective accumulators, no
  per-point inversion). See `circuit/CIRCUIT.md` §15. These lifted
  throughput ~12–25% over the previous sweep (64: 1.33→1.49, 128:
  1.68→1.95, 256: 1.80→2.25 v/s) even with the added process-config
  inclusion-proof verification now in-circuit.
- **128 is the maximum batch size** (`MAX_BATCH_SIZE`): the circuit
  rejects any batch with more than 128 proofs. Pick a batch ≤ 128 and
  fold more often for larger elections. **Lowered from 256 to 128 for
  GPU-memory safety** (see the per-batch section below): batch 256 at full
  ballot capacity peaks ~31.3 GB even under `--minimal-memory`, leaving no
  headroom on the 32 GB GPU. The chained-mode tables above (and the 5120 /
  20000 rows below) were measured under the previous 256 cap and at the
  8-field era; they are retained as historical references — production now
  caps at 128. A current 16-field measurement is below.

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

128 is the `MAX_BATCH_SIZE` cap; the 256 row is retained as the corner that
motivated it. `proofBytes` is 768 B / `publicValues` 256 B (512 B on ZisK 1.3) regardless of
batch or field count.

**Why the cap is 128.** At num_fields=16 the per-field chained reencryption
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
