# Benchmarks

Measured on a single NVIDIA RTX 5090 (59 GB host RAM), ZisK v0.18.0.
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
|  64 | 4 | 4 | 1m15s | 23.8s | 30.2s | 22m13s | 0.77 | 0.49 s |
| 128 | 4 | 2 | 2m47s | 30.2s | 35.3s | 23m54s | 0.71 | 0.40 s |
| 256 | 2 | 2 | 4m36s | 25.1s | 30.2s | 19m43s | 0.87 | 1.13 s |

- One on-chain verification per **election**, regardless of vote count.
  The final 2.7 KB PLONK attests genesis-state correctness, every batch
  transition (recursive STARK verification), and the decrypted results.
- The first fold includes a one-off bootstrap fold that teaches the
  sequencer the aggregator program_vk (~2x a steady-state fold, ~35s vs
  ~20s); amortized to zero over an election.
- Finalize is a per-election constant (~30s), independent of vote count.
- Batches and folds serialize on the single GPU; fold overhead is ~5–7%
  of total time. A second service instance would pipeline batching and
  folding.
- **batch 512 does not fit**: the chained-mode 512-vote STARK prove
  peaks at ~57 GB anon RSS and is OOM-killed on this 59 GB host (twice,
  deterministically). Use batch ≤ 256, or a host with more RAM.

## Per-batch mode — one PLONK + one on-chain verification per batch

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |  37 s | 1.7 | 350 ms |
| 128 |  57 s | 2.2 | 340 ms |
| 256 |  97 s | 2.6 | 340 ms |
| 512 | 138 s | 3.7 | 480 ms |

SNARK size is 2.7 KB regardless of batch size.

## Comparing the modes

Per-batch mode has higher raw throughput — chained-mode batches do more
work in-circuit (ballot re-encryption into the homomorphic accumulators
replaces the KZG block) — but it costs one Ethereum verification per
batch: 1024 votes at batch 256 is 4 on-chain transactions vs 1.

Chained mode trades ~2–3x prover throughput for a constant on-chain
footprint: a 1024-vote election lands on-chain as a single proof, and a
1M-vote election would too. Past a handful of batches, chained mode is
strictly cheaper on-chain and the only mode that scales to large
elections.
