#!/usr/bin/env bash
# Chained-mode benchmark sweep. Proves BENCH_VOTES votes per setup
# through TestChainBenchmark (go-sdk/tests/integration/chain_bench_test.go),
# one setup at a time (single GPU), then writes a markdown report.
#
# Usage:
#   ./benchmark/run.sh            # run the sweep, then the report
#   ./benchmark/run.sh report     # only regenerate the report from existing logs
#
# Env:
#   DAVINCI_API_URL        service URL          (default http://127.0.0.1:8080)
#   BENCH_VOTES            votes per setup      (default 1024)
#   BENCH_SETUPS           "batch:fold_every"   (default "64:4 128:4 256:2")
#   DAVINCI_PROOF_TIMEOUT  per-job timeout      (default 60m)
#   OUT_DIR                logs + report dir    (default benchmark/results)
#   BENCH_CACHE_DIR        ballot cache dir     (default benchmark/cache)
#
# Ballot inputs (Groth16 proofs, signatures, census proofs) are generated
# once per vote count, cached in BENCH_CACHE_DIR and reused across runs
# and batch sizes. Generation happens before the timed section: the
# benchmark measures proving the election once the votes exist.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_URL="${DAVINCI_API_URL:-http://127.0.0.1:8080}"
VOTES="${BENCH_VOTES:-1024}"
SETUPS="${BENCH_SETUPS:-64:4 128:4 256:2}"
TIMEOUT="${DAVINCI_PROOF_TIMEOUT:-60m}"
OUT_DIR="${OUT_DIR:-$REPO_ROOT/benchmark/results}"
CACHE_DIR="${BENCH_CACHE_DIR:-$REPO_ROOT/benchmark/cache}"

mkdir -p "$OUT_DIR"

if [ "${1:-}" = "report" ]; then
  exec "$REPO_ROOT/benchmark/report.sh" "$OUT_DIR"
fi

if ! curl -sf "$API_URL/health" >/dev/null 2>&1; then
  echo "service not reachable at $API_URL" >&2
  exit 1
fi

echo "sweep: $VOTES votes per setup, setups: $SETUPS"
echo "logs:  $OUT_DIR"

failed=0
for setup in $SETUPS; do
  batch="${setup%%:*}"
  fold="${setup##*:}"
  log="$OUT_DIR/chain-bench-${batch}x${fold}.log"
  echo "=== setup batch_size=$batch fold_every=$fold start=$(date +%T) ==="
  if (cd "$REPO_ROOT/go-sdk/tests" && \
      CHAIN_BENCH=1 DAVINCI_API_URL="$API_URL" DAVINCI_PROOF_TIMEOUT="$TIMEOUT" \
      BENCH_VOTES="$VOTES" BENCH_BATCH_SIZE="$batch" BENCH_FOLD_EVERY="$fold" \
      BENCH_CACHE_DIR="$CACHE_DIR" \
      go test ./integration -run TestChainBenchmark -v -timeout 150m) \
      > "$log" 2>&1; then
    echo "SETUP ${batch}x${fold} OK"
  else
    echo "SETUP ${batch}x${fold} FAILED (see $log)"
    failed=1
  fi
done

"$REPO_ROOT/benchmark/report.sh" "$OUT_DIR"
echo "SWEEP DONE (report: $OUT_DIR/RESULTS.md)"
exit $failed
