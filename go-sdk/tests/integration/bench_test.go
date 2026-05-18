package integration

// TestStarkBenchmark measures STARK aggregated proof time at each supported
// batch size (2, 4, 8, 16, 32, 64, 128).  Each iteration creates a fresh
// election, runs exactly one state-transition, and records the elapsed proof
// time as reported by the service.  The test is self-contained and does not
// depend on VOTES_PER_BATCH.
//
// Run:
//
//	DAVINCI_PROOF_TIMEOUT=30m go test -run TestStarkBenchmark -v -timeout 60m

import (
	"fmt"
	"testing"
	"time"
)

func TestStarkBenchmark(t *testing.T) {
	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v", apiURL, err)
	}

	sizes := []int{128, 256, 512}

	type result struct {
		size       int
		proofMs    int64
		wallMs     int64
	}
	results := make([]result, 0, len(sizes))

	t.Log("=== TestStarkBenchmark: STARK proof time vs batch size ===")
	t.Log("size | proof_ms | wall_ms | proof_s | wall_s")
	t.Log("-----|----------|---------|---------|-------")

	for _, size := range sizes {
		t.Logf("--- batch size %d ---", size)

		election, err := NewElection(size)
		if err != nil {
			t.Fatalf("size=%d: NewElection: %v", size, err)
		}

		voters := election.Voters[:size]
		seedBase := int64(42)

		wallStart := time.Now()

		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, seedBase)
		if err != nil {
			t.Fatalf("size=%d: GenerateBallotBatch: %v", size, err)
		}
		t.Logf("  size=%d: ballot proofs generated in %.1fs", size, time.Since(wallStart).Seconds())

		oldRoot := election.OldRoot

		kzgBlock, err := election.BuildKZGBlock(0, oldRoot)
		if err != nil {
			t.Fatalf("size=%d: BuildKZGBlock: %v", size, err)
		}
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("size=%d: BuildReencBlock: %v", size, err)
		}
		stateBlock, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("size=%d: BuildStateBlock: %v", size, err)
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

		wallMs := time.Since(submitTime).Milliseconds()
		var proofMs int64
		if job.ElapsedMs != nil {
			proofMs = *job.ElapsedMs
		}

		r := result{size: size, proofMs: proofMs, wallMs: wallMs}
		results = append(results, r)

		t.Logf("  size=%d: proof=%dms wall=%dms", size, proofMs, wallMs)
		t.Logf("%4d | %8d | %7d | %7.1f | %6.1f",
			size, proofMs, wallMs,
			float64(proofMs)/1000, float64(wallMs)/1000)
	}

	// Summary table
	t.Log("")
	t.Log("=== STARK Proof Performance Summary ===")
	t.Log("")
	t.Logf("%-10s  %12s  %10s  %12s  %10s", "batch_size", "proof_ms", "proof_s", "wall_ms", "wall_s")
	t.Logf("%-10s  %12s  %10s  %12s  %10s", "----------", "--------", "-------", "-------", "------")
	for _, r := range results {
		t.Logf("%-10d  %12d  %10.1f  %12d  %10.1f",
			r.size, r.proofMs, float64(r.proofMs)/1000,
			r.wallMs, float64(r.wallMs)/1000)
	}

	// Also emit as a machine-readable CSV for easy graphing
	t.Log("")
	t.Log("CSV: batch_size,proof_ms,wall_ms")
	for _, r := range results {
		t.Log(fmt.Sprintf("CSV: %d,%d,%d", r.size, r.proofMs, r.wallMs))
	}
}
