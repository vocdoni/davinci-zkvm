package integration

// TestFullE2E is the comprehensive end-to-end integration test for the DAVINCI
// zkVM circuit using Merkle-proof census (censusOrigin=1).
//
// It exercises all six DAVINCI protocol phases in a realistic multi-transition
// scenario with interleaved fresh votes, first-time overwrites, and double
// overwrites (same voter votes three times).
//
// Phases verified per transition:
//   1. Groth16 batch proof verification (ballot proofs + VK)
//   2. ECDSA signature verification (one per ballot)
//   3. STATETX state transition (voteID / ballot / ResultsAdd / ResultsSub SMT ops)
//   4. CENSUS lean-IMT Poseidon membership proofs
//   5. REENCBLK BabyJubJub ElGamal re-encryption verification
//   6. KZGBLK EIP-4844 blob barycentric evaluation
//
// Scenario (8 transitions, 14 fresh voters):
//   Batch 1:  2 fresh voters   (idx 0-1)
//   Batch 2:  4 fresh voters   (idx 2-5)
//   Batch 3:  2 overwrites     (idx 0-1 vote again — 1st overwrite)
//   Batch 4:  2 fresh voters   (idx 6-7)
//   Batch 5:  4 fresh voters   (idx 8-11)
//   Batch 6:  4 overwrites     (idx 2-5 vote again — 1st overwrite)
//   Batch 7:  2 overwrites     (idx 0-1 vote a 3rd time — 2nd overwrite)
//   Batch 8:  2 fresh voters   (idx 12-13)
//
// After all transitions the test decrypts the ElGamal-accumulated tally and
// verifies that each vote field matches the analytically expected total.
//
// Prerequisites:
//   - docker compose up -d --build (starts davinci-zkvm service)
//   - DAVINCI_API_URL (default: http://localhost:8080)
//   - DAVINCI_PROOF_TIMEOUT (default: 5m per ZisK proof)

import (
	"testing"
	"time"
)

func TestFullE2E(t *testing.T) {
	// ── Batch layout ────────────────────────────────────────────────────────
	// Size: voters in this batch (must be power of two ≥ 2).
	// VoterStart: -1 → fresh voters; ≥ 0 → overwrite voters at that index.
	// SeedOffset: shifts the deterministic ballot‐field seed so overwrite
	//   values differ from the originals, making the tally verifiable.
	batches := []batchSpec{
		// Phase A: initial fresh votes
		{Size: 2, VoterStart: -1, SeedOffset: 0},   // batch 1: fresh 0-1
		{Size: 4, VoterStart: -1, SeedOffset: 0},   // batch 2: fresh 2-5

		// Phase B: first round of overwrites (interleaved with fresh)
		{Size: 2, VoterStart: 0, SeedOffset: 7},    // batch 3: overwrite 0-1 (1st time)
		{Size: 2, VoterStart: -1, SeedOffset: 0},   // batch 4: fresh 6-7
		{Size: 4, VoterStart: -1, SeedOffset: 0},   // batch 5: fresh 8-11

		// Phase C: more overwrites and double overwrite
		{Size: 4, VoterStart: 2, SeedOffset: 7},    // batch 6: overwrite 2-5 (1st time)
		{Size: 2, VoterStart: 0, SeedOffset: 13},   // batch 7: overwrite 0-1 (2nd time = 3rd vote)

		// Phase D: final fresh votes after all overwrites
		{Size: 2, VoterStart: -1, SeedOffset: 0},   // batch 8: fresh 12-13
	}

	nFresh := freshVoterCount(batches)
	nTransitions := len(batches)
	nOverwrites := 0
	for _, b := range batches {
		if b.VoterStart >= 0 {
			nOverwrites += b.Size
		}
	}
	t.Logf("=== TestFullE2E: %d transitions, %d fresh voters, %d overwrites ===",
		nTransitions, nFresh, nOverwrites)

	// ── 1. Create election ──────────────────────────────────────────────────
	election, err := NewElection(nFresh)
	if err != nil {
		t.Fatalf("NewElection(%d): %v", nFresh, err)
	}
	t.Logf("Election created with %d voters", nFresh)
	t.Logf("  ProcessID:    %s", election.ProcessIDHex())
	t.Logf("  Initial root: %s", election.OldRoot)

	// ── 2. Service check ────────────────────────────────────────────────────
	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v "+
			"(start with 'docker compose up -d --build')", apiURL, err)
	}
	t.Logf("Service reachable at %s", apiURL)

	// ── 3. Run transitions ──────────────────────────────────────────────────
	tally := NewTallyAccumulator()
	voterOffset := 0
	prevRoot := election.OldRoot
	totalWall := time.Now()

	for txIdx, spec := range batches {
		isOverwrite := spec.VoterStart >= 0
		var batchVoters []*Voter
		if isOverwrite {
			batchVoters = election.Voters[spec.VoterStart : spec.VoterStart+spec.Size]
		} else {
			batchVoters = election.Voters[voterOffset : voterOffset+spec.Size]
			voterOffset += spec.Size
		}
		seedBase := int64(txIdx*1000 + 1 + spec.SeedOffset)

		kind := "FRESH"
		if isOverwrite {
			kind = "OVERWRITE"
		}
		t.Logf("─── Transition %d/%d [%s]: %d voters, seed=%d ───",
			txIdx+1, nTransitions, kind, spec.Size, seedBase)

		start := time.Now()

		// (a) Generate ballot proofs.
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, batchVoters, seedBase)
		if err != nil {
			t.Fatalf("tx %d: GenerateBallotBatch: %v", txIdx+1, err)
		}
		t.Logf("  Ballot proofs generated (%d) in %.1fs", spec.Size, time.Since(start).Seconds())

		// (b) Save old root for KZG derivation.
		oldRoot := election.OldRoot

		// Verify state root continuity: the current root must equal the
		// previous transition's new root (or the initial root for tx 1).
		if oldRoot != prevRoot {
			t.Fatalf("tx %d: root discontinuity: expected %s, got %s", txIdx+1, prevRoot, oldRoot)
		}

		// (c) Build protocol blocks.
		kzgBlock, err := election.BuildKZGBlock(txIdx, oldRoot)
		if err != nil {
			t.Fatalf("tx %d: BuildKZGBlock: %v", txIdx+1, err)
		}
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("tx %d: BuildReencBlock: %v", txIdx+1, err)
		}
		stateBlock, overwrittenBallots, err := election.BuildStateBlock(batchVoters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("tx %d: BuildStateBlock: %v", txIdx+1, err)
		}
		censusProofs, err := election.BuildCensusProofs(batchVoters)
		if err != nil {
			t.Fatalf("tx %d: BuildCensusProofs: %v", txIdx+1, err)
		}

		// (d) Accumulate tally (add new, subtract old overwritten).
		tally.Add(reencBallots)
		if len(overwrittenBallots) > 0 {
			tally.Subtract(overwrittenBallots)
			t.Logf("  %d overwrite(s): subtracted old ballots from tally", len(overwrittenBallots))
		}

		// (e) Assemble and submit.
		req := batch.ToProveRequest()
		req.State = stateBlock
		req.CensusProofs = censusProofs
		req.Reencryption = reencBlock
		req.KZG = kzgBlock

		t.Logf("  Submitting to %s …", apiURL)
		jobID, err := client.SubmitProve(req)
		if err != nil {
			t.Fatalf("tx %d: SubmitProve: %v", txIdx+1, err)
		}
		t.Logf("  Job %s submitted", jobID)

		job, err := client.WaitForJob(jobID, proofTimeout())
		if err != nil {
			t.Fatalf("tx %d: WaitForJob %s: %v", txIdx+1, jobID, err)
		}
		elapsed := time.Since(start)
		if job.ElapsedMs != nil {
			t.Logf("  Done in %dms (proof) / %.1fs (wall)", *job.ElapsedMs, elapsed.Seconds())
		} else {
			t.Logf("  Done in %.1fs (wall)", elapsed.Seconds())
		}
		if job.Status != "done" {
			errMsg := "<no error>"
			if job.Error != nil {
				errMsg = *job.Error
			}
			t.Fatalf("tx %d: job %s status=%q: %s", txIdx+1, jobID, job.Status, errMsg)
		}

		prevRoot = election.OldRoot
		t.Logf("  New root: %s", prevRoot)
	}

	t.Logf("=== All %d transitions done in %.1fs; decrypting tally (%d net ballots) ===",
		nTransitions, time.Since(totalWall).Seconds(), tally.count)

	// ── 4. Verify tally ─────────────────────────────────────────────────────
	fieldTotals, err := tally.DecryptTally(election.EncPrivKey)
	if err != nil {
		t.Fatalf("DecryptTally: %v", err)
	}

	expected := expectedTally(batches)
	t.Logf("Tally results (actual vs expected):")
	allOK := true
	for i, v := range fieldTotals {
		marker := "✓"
		if v.Int64() != expected[i] {
			marker = "✗"
			allOK = false
		}
		t.Logf("  field[%d] = %3s (expected %3d) %s", i, v.String(), expected[i], marker)
	}

	// Fields 0-5: deterministic ballot values (must match exactly).
	for i := 0; i < 6; i++ {
		if fieldTotals[i].Int64() != expected[i] {
			t.Errorf("field[%d]: got %s, want %d", i, fieldTotals[i].String(), expected[i])
		}
	}
	// Fields 6-7: padding (must be zero).
	for i := 6; i < 8; i++ {
		if fieldTotals[i].Sign() != 0 {
			t.Errorf("field[%d] (padding): got %s, want 0", i, fieldTotals[i].String())
		}
	}

	if !allOK {
		t.Fatal("tally mismatch detected")
	}

	t.Logf("Final state root: %s", election.OldRoot)
	t.Logf("=== TestFullE2E PASSED ===")
}
