// csp_test.go is the CSP ECDSA census integration test.
//
// It creates a CSP-mode election (censusOrigin=4), generates ballot proofs,
// signs each voter with the CSP key, and submits 4 chained state transitions
// (with overwrites in the last batch) to the running davinci-zkvm service.
//
// Prerequisites:
//   - docker compose up -d --build (starts davinci-zkvm service)
//   - DAVINCI_API_URL (default: http://localhost:8080)
package integration

import (
	"testing"
	"time"
)

// TestCSPChainedStateTransitions runs 4 state transitions using CSP census mode.
// Batches 1-3: fresh voters (2 each). Batch 4: overwrites voters from batch 1.
func TestCSPChainedStateTransitions(t *testing.T) {
	cspBatches := []batchSpec{
		{2, -1, 0},  // batch 1: 2 fresh voters
		{2, -1, 0},  // batch 2: 2 fresh voters
		{2, -1, 0},  // batch 3: 2 fresh voters
		{2, 0, 7},   // batch 4: overwrite voters 0,1 from batch 1
	}

	nFresh := freshVoterCount(cspBatches)
	t.Logf("=== TestCSPChainedStateTransitions: %d transitions, %d fresh voters ===",
		len(cspBatches), nFresh)

	// ── 1. Create CSP election ──────────────────────────────────────────────
	election, err := NewCSPElection(nFresh)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	t.Logf("CSP election created; initial state root: %s", election.OldRoot)
	t.Logf("CSP address: 0x%040x", election.CspKey.PublicKey.X)

	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}

	// ── 2. Tally accumulator ────────────────────────────────────────────────
	tally := NewTallyAccumulator()

	// ── 3. Run CSP transitions ──────────────────────────────────────────────
	voterOffset := 0
	for txIdx, spec := range cspBatches {
		batchSize := spec.Size
		isOverwrite := spec.VoterStart >= 0
		var batchVoters []*Voter
		if isOverwrite {
			batchVoters = election.Voters[spec.VoterStart : spec.VoterStart+batchSize]
		} else {
			batchVoters = election.Voters[voterOffset : voterOffset+batchSize]
			voterOffset += batchSize
		}
		seedBase := int64(txIdx*1000 + 1 + spec.SeedOffset)
		t.Logf("--- CSP Transition %d/%d: batch_size=%d overwrite=%v seed_base=%d ---",
			txIdx+1, len(cspBatches), batchSize, isOverwrite, seedBase)

		start := time.Now()

		// Generate ballot proofs (same as Merkle mode).
		t.Logf("  Generating %d ballot proofs...", batchSize)
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, batchVoters, seedBase)
		if err != nil {
			t.Fatalf("transition %d: GenerateBallotBatch: %v", txIdx, err)
		}
		t.Logf("  Ballot proofs generated in %.1fs", time.Since(start).Seconds())

		oldRoot := election.OldRoot

		// Build KZG block.
		kzgBlock, err := election.BuildKZGBlock(txIdx, oldRoot)
		if err != nil {
			t.Fatalf("transition %d: BuildKZGBlock: %v", txIdx, err)
		}

		// Build re-encryption block.
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("transition %d: BuildReencBlock: %v", txIdx, err)
		}

		// Build state-transition block (advances election.OldRoot).
		stateBlock, overwrittenBallots, err := election.BuildStateBlock(batchVoters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("transition %d: BuildStateBlock: %v", txIdx, err)
		}

		// Build CSP proofs (instead of census membership proofs).
		cspData, err := election.BuildCspData(batchVoters)
		if err != nil {
			t.Fatalf("transition %d: BuildCspData: %v", txIdx, err)
		}

		// Accumulate tally.
		tally.Add(reencBallots)
		if len(overwrittenBallots) > 0 {
			tally.Subtract(overwrittenBallots)
			t.Logf("  %d overwrite(s) detected; subtracted from tally", len(overwrittenBallots))
		}

		// Assemble the full ProveRequest.
		req := batch.ToProveRequest()
		req.State = stateBlock
		req.CspData = cspData
		req.Reencryption = reencBlock
		req.KZG = kzgBlock

		// Submit to the service.
		t.Logf("  Submitting CSP job to %s...", apiURL)
		jobID, err := client.SubmitProve(req)
		if err != nil {
			t.Fatalf("transition %d: SubmitProve: %v", txIdx, err)
		}
		t.Logf("  Job %s submitted (transition %d/%d)", jobID, txIdx+1, len(cspBatches))

		job, err := client.WaitForJob(jobID, proofTimeout())
		if err != nil {
			t.Fatalf("transition %d: WaitForJob %s: %v", txIdx, jobID, err)
		}
		elapsed := time.Since(start)
		if job.ElapsedMs != nil {
			t.Logf("  Transition %d done in %dms (%.1fs), total wall time %.1fs",
				txIdx+1, *job.ElapsedMs, float64(*job.ElapsedMs)/1000, elapsed.Seconds())
		} else {
			t.Logf("  Transition %d done (wall time %.1fs)", txIdx+1, elapsed.Seconds())
		}
		if job.Status != "done" {
			errMsg := "<no error>"
			if job.Error != nil {
				errMsg = *job.Error
			}
			t.Fatalf("transition %d: job %s failed with status %q: %s",
				txIdx, jobID, job.Status, errMsg)
		}
		t.Logf("  New state root: %s", election.OldRoot)
	}

	// ── 4. Verify tally ─────────────────────────────────────────────────────
	t.Logf("=== All %d CSP transitions done; decrypting tally (%d net ballots) ===",
		len(cspBatches), tally.count)

	fieldTotals, err := tally.DecryptTally(election.EncPrivKey)
	if err != nil {
		t.Fatalf("DecryptTally: %v", err)
	}

	expected := expectedTally(cspBatches)

	t.Logf("Vote tally (field totals vs expected):")
	for i, v := range fieldTotals {
		t.Logf("  field[%d] = %s (expected %d)", i, v.String(), expected[i])
	}

	for i := 0; i < 6; i++ {
		if fieldTotals[i].Int64() != expected[i] {
			t.Errorf("field[%d]: got %s, want %d", i, fieldTotals[i].String(), expected[i])
		}
	}
	for i := 6; i < 8; i++ {
		if fieldTotals[i].Sign() != 0 {
			t.Errorf("field[%d] (padding): got %s, want 0", i, fieldTotals[i].String())
		}
	}
	t.Logf("Final state root: %s", election.OldRoot)
	t.Logf("=== TestCSPChainedStateTransitions PASSED ===")
}
