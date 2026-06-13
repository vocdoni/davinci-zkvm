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
|  64 | 4 | 4 | 35.3s | 23.9s | 30.2s | 11m31s | 1.48 | 0.37 s |
| 128 | 4 | 2 | 55.6s | 27.6s | 25.2s |  8m45s | 1.95 | 0.47 s |
| 256 | 2 | 2 | 1m37s | 22.6s | 25.1s |  7m40s | 2.23 | 0.52 s |

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
- All rows are on the fully-optimized batch circuit: SMT node-hash skip
  on padding levels, lazy SMT leaf hashing, and projective re-encryption
  equality (fixed-base windowed scalar mul + projective accumulators, no
  per-point inversion). See `circuit/CIRCUIT.md` §15. These lifted
  throughput ~11–24% over the previous sweep (64: 1.33→1.48, 128:
  1.68→1.95, 256: 1.80→2.23 v/s) even with the added process-config
  inclusion-proof verification now in-circuit.
- **batch 512 does not work in chained mode here**: with the lower-RSS
  optimized path it no longer OOMs (peak stays under the 59 GB host), but
  the 512-vote batch circuit commits `ok=0`, so the fold rejects it
  (`batch 0: circuit reported failure`). Use batch ≤ 256. (The same ELF
  proves 512 fine in per-batch mode, so this is a chained-512 edge, not a
  general 512 failure.)

## Per-batch mode — one PLONK + one on-chain verification per batch

| batch | PLONK SNARK | votes/s | on-chain verify |
|---:|---:|---:|---:|
|  64 |  34 s | 1.9 | 315 ms |
| 128 |  52 s | 2.4 | 349 ms |
| 256 |  89 s | 2.9 | 309 ms |
| 512 | 118 s | 4.3 | 505 ms |

SNARK size is 2.7 KB regardless of batch size.

## Comparing the modes

Per-batch mode has higher raw throughput — chained-mode batches do more
work in-circuit (ballot re-encryption into the homomorphic accumulators
replaces the KZG block) — but it costs one Ethereum verification per
batch: 1024 votes at batch 256 is 4 on-chain transactions vs 1.

Chained mode trades ~1.3x prover throughput (at batch 256: 2.9 v/s
per-batch vs 2.23 v/s chained) for a constant on-chain footprint: a
1024-vote election lands on-chain as a single proof, and a 1M-vote
election would too. Past a handful of batches, chained mode is strictly
cheaper on-chain and the only mode that scales to large elections.
