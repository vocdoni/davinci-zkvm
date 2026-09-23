package integration

// TestPlonkBenchmark measures PLONK SNARK proof time for the davinci
// state-transition circuit at a sweep of batch sizes. For each size it:
//
//  1. Generates ballot proofs (CPU; not counted in the benchmark).
//  2. Submits a state-transition prove request to the davinci-zkvm service.
//  3. Waits for the service to return a done job; records proof_ms.
//  4. Fetches the SNARK payload via the new `/jobs/:id/snark` endpoint.
//  5. Verifies the PLONK SNARK with the bundled Solidity verifier on a
//     `go-ethereum/ethclient/simulated.NewBackend` — same code path that
//     would run on Ethereum.
//
// The Solidity verification confirms the proof end-to-end: prover output
// matches verifier expectation, no intermediate STARK/VADCOP knowledge
// leaks into the SDK or the consumer.
//
// Run:
//
//	DAVINCI_PROOF_TIMEOUT=30m go test -run TestPlonkBenchmark -v -timeout 60m
//
// Requires the davinci-zkvm service to be running with PLONK enabled
// (`ENABLE_PLONK=1 docker compose --profile cuda up -d`).

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"
)

// solidityDir returns the absolute path to the davinci-zkvm Solidity verifier
// directory, computed relative to the source file at test compile time.
func solidityDir() string {
	_, thisFile, _, _ := runtime.Caller(0)
	// .../go-sdk/tests/integration/bench_test.go → repo root → /solidity
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "solidity"))
}

func TestPlonkBenchmark(t *testing.T) {
	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v", apiURL, err)
	}

	sizes := []int{64, 128, 256}
	if v := os.Getenv("BENCH_SIZES"); v != "" {
		sizes = nil
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n <= 0 {
				t.Fatalf("bad BENCH_SIZES entry %q: %v", s, err)
			}
			sizes = append(sizes, n)
		}
	}

	type result struct {
		size      int
		proofMs   int64 // first batch: empty tree, no refreshes
		refreshMs int64 // second batch: size votes + size silent refreshes
		wallMs    int64
		verifyMs  int64
	}
	// Seed the election so ballots are cached across runs (CachedBallotBatch).
	if os.Getenv("DAVINCI_TEST_ELECTION_SEED") == "" {
		t.Setenv("DAVINCI_TEST_ELECTION_SEED", "plonk-bench")
	}
	results := make([]result, 0, len(sizes))

	t.Log("=== TestPlonkBenchmark: PLONK SNARK time vs batch size ===")

	for _, size := range sizes {
		t.Logf("--- batch size %d ---", size)
		// Two batches on one election. The first fills an empty tree, so it
		// carries no silent refreshes; the second is the steady state and
		// refreshes RefreshTarget(size, 0, size) = size slots on top of its
		// own votes. The verified proof is the second one.
		election, err := NewElection(2 * size)
		if err != nil {
			t.Fatalf("size=%d: NewElection: %v", size, err)
		}
		first := proveBench(t, client, election, election.Voters[:size], 42)
		second := proveBench(t, client, election, election.Voters[size:2*size], 43)
		t.Logf("  size=%d: proof=%dms (no refresh) / %dms (%d refreshes)",
			size, first.proofMs, second.proofMs, size)
		snark, err := client.FetchSnark(second.jobID)
		if err != nil {
			t.Fatalf("size=%d: FetchSnark: %v", size, err)
		}
		verifyStart := time.Now()
		if err := davinciSolidity.VerifyOnSimulated(solidityDir(), snark); err != nil {
			t.Fatalf("size=%d: Solidity verification failed: %v", size, err)
		}
		verifyMs := time.Since(verifyStart).Milliseconds()
		t.Logf("  size=%d: ✓ Solidity verification succeeded in %dms", size, verifyMs)
		results = append(results, result{size: size, proofMs: first.proofMs, refreshMs: second.proofMs,
			wallMs: second.wallMs, verifyMs: verifyMs})
	}
	t.Log("")
	t.Log("=== PLONK SNARK Performance Summary ===")
	t.Logf("%-10s  %12s  %12s  %12s  %12s", "batch_size", "proof_ms", "refresh_ms", "wall_ms", "verify_ms")
	t.Logf("%-10s  %12s  %12s  %12s  %12s", "----------", "--------", "----------", "-------", "---------")
	for _, r := range results {
		t.Logf("%-10d  %12d  %12d  %12d  %12d", r.size, r.proofMs, r.refreshMs, r.wallMs, r.verifyMs)
	}
	t.Log("")
	t.Log("CSV: batch_size,proof_ms,wall_ms,verify_ms,refresh_ms")
	for _, r := range results {
		t.Log(fmt.Sprintf("CSV: %d,%d,%d,%d,%d", r.size, r.proofMs, r.wallMs, r.verifyMs, r.refreshMs))
	}
}

type benchRun struct {
	jobID   string
	proofMs int64
	wallMs  int64
}

// proveBench proves one batch of voters on election through the service
// and returns the job id and its timings.
func proveBench(t *testing.T, client *davinci.Client, election *Election, voters []*Voter, seedBase int64) benchRun {
	t.Helper()
	size := len(voters)
	wallStart := time.Now()
	batch, err := CachedBallotBatch(election, voters, seedBase)
	if err != nil {
		t.Fatalf("size=%d: CachedBallotBatch: %v", size, err)
	}
	t.Logf("  size=%d: ballot proofs ready in %.1fs", size, time.Since(wallStart).Seconds())
	oldRoot := election.OldRoot
	reencBlock, reencBallots, err := election.BuildReencBlock(oldRoot, batch.Results)
	if err != nil {
		t.Fatalf("size=%d: BuildReencBlock: %v", size, err)
	}
	stateBlock, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("size=%d: BuildStateBlock: %v", size, err)
	}
	kzgBlock, _, err := election.BuildKZGBlock(oldRoot)
	if err != nil {
		t.Fatalf("size=%d: BuildKZGBlock: %v", size, err)
	}
	censusProofs, err := election.BuildCensusProofs(voters)
	if err != nil {
		t.Fatalf("size=%d: BuildCensusProofs: %v", size, err)
	}
	req := batch.ToProveRequest()
	req.State = stateBlock
	req.CensusProofs = censusProofs
	req.Reencryption = reencBlock
	req.KZG = kzgBlock
	submitTime := time.Now()
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("size=%d: SubmitProve: %v", size, err)
	}
	t.Logf("  size=%d: job %s submitted", size, jobID)
	job, err := client.WaitForJob(jobID, proofTimeout())
	if err != nil {
		t.Fatalf("size=%d: WaitForJob: %v", size, err)
	}
	if job.Status != "done" {
		errMsg := "<no error>"
		if job.Error != nil {
			errMsg = *job.Error
		}
		t.Fatalf("size=%d: job %s failed: %s", size, jobID, errMsg)
	}
	run := benchRun{jobID: jobID, wallMs: time.Since(submitTime).Milliseconds()}
	if job.ElapsedMs != nil {
		run.proofMs = *job.ElapsedMs
	}
	// A PLONK of a rejected batch verifies just as well on-chain, so the
	// guest's own verdict is what makes the timing meaningful.
	publics, err := client.FetchPublics(jobID)
	if err != nil {
		t.Fatalf("size=%d: FetchPublics: %v", size, err)
	}
	if len(publics) < 8 {
		t.Fatalf("size=%d: publics too short (%d bytes)", size, len(publics))
	}
	ok, failMask := binary.LittleEndian.Uint32(publics[0:]), binary.LittleEndian.Uint32(publics[4:])
	if ok != 1 {
		t.Fatalf("size=%d: guest rejected job %s: fail_mask=%#x", size, jobID, failMask)
	}
	return run
}

// TestGenerateBenchBallots only fills the ballot cache TestPlonkBenchmark
// reads, so the slow part can run ahead of (and in parallel with) the
// proving sweep. Gated by BENCH_PREGEN=1; honours BENCH_SIZES,
// BALLOT_NUM_FIELDS and DAVINCI_TEST_ELECTION_SEED like the benchmark.
func TestGenerateBenchBallots(t *testing.T) {
	if os.Getenv("BENCH_PREGEN") == "" {
		t.Skip("set BENCH_PREGEN=1 to pre-generate benchmark ballots")
	}
	if os.Getenv("DAVINCI_TEST_ELECTION_SEED") == "" {
		t.Setenv("DAVINCI_TEST_ELECTION_SEED", "plonk-bench")
	}
	sizes := []int{64, 128, 256}
	if v := os.Getenv("BENCH_SIZES"); v != "" {
		sizes = nil
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n <= 0 {
				t.Fatalf("bad BENCH_SIZES entry %q: %v", s, err)
			}
			sizes = append(sizes, n)
		}
	}
	for _, size := range sizes {
		election, err := NewElection(2 * size)
		if err != nil {
			t.Fatalf("size=%d: NewElection: %v", size, err)
		}
		for i, seedBase := range []int64{42, 43} {
			start := time.Now()
			voters := election.Voters[i*size : (i+1)*size]
			if _, err := CachedBallotBatch(election, voters, seedBase); err != nil {
				t.Fatalf("size=%d: CachedBallotBatch: %v", size, err)
			}
			t.Logf("size=%d batch %d: %d ballots ready in %.0fs", size, i+1, size, time.Since(start).Seconds())
		}
	}
}
