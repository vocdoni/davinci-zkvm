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
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

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

	type result struct {
		size      int
		proofMs   int64
		wallMs    int64
		verifyMs  int64
	}
	results := make([]result, 0, len(sizes))

	t.Log("=== TestPlonkBenchmark: PLONK SNARK time vs batch size ===")

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
		t.Logf("  size=%d: proof=%dms wall=%dms", size, proofMs, wallMs)

		// Fetch the SNARK payload and verify it with the Solidity verifier.
		snark, err := client.FetchSnark(jobID)
		if err != nil {
			t.Fatalf("size=%d: FetchSnark: %v", size, err)
		}
		t.Logf("  size=%d: snark fetched (proof_bytes=%dB, publicValues=%dB)",
			size, len(snark.ProofBytes), len(snark.PublicValues))

		verifyStart := time.Now()
		if err := davinciSolidity.VerifyOnSimulated(solidityDir(), snark); err != nil {
			t.Fatalf("size=%d: Solidity verification failed: %v", size, err)
		}
		verifyMs := time.Since(verifyStart).Milliseconds()
		t.Logf("  size=%d: ✓ Solidity verification succeeded in %dms", size, verifyMs)

		results = append(results, result{size: size, proofMs: proofMs, wallMs: wallMs, verifyMs: verifyMs})
	}

	t.Log("")
	t.Log("=== PLONK SNARK Performance Summary ===")
	t.Logf("%-10s  %12s  %10s  %12s  %12s", "batch_size", "proof_ms", "proof_s", "wall_ms", "verify_ms")
	t.Logf("%-10s  %12s  %10s  %12s  %12s", "----------", "--------", "-------", "-------", "---------")
	for _, r := range results {
		t.Logf("%-10d  %12d  %10.1f  %12d  %12d",
			r.size, r.proofMs, float64(r.proofMs)/1000, r.wallMs, r.verifyMs)
	}

	t.Log("")
	t.Log("CSV: batch_size,proof_ms,wall_ms,verify_ms")
	for _, r := range results {
		t.Log(fmt.Sprintf("CSV: %d,%d,%d,%d", r.size, r.proofMs, r.wallMs, r.verifyMs))
	}
}
