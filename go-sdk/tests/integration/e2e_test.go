package integration

// TestFullE2E is the comprehensive end-to-end integration test for the DAVINCI
// zkVM circuit using Merkle-proof census (censusOrigin=1).
// It exercises all six DAVINCI protocol phases in a realistic multi-transition
// scenario with interleaved fresh votes, first-time overwrites, and double
// overwrites (same voter votes three times).
// Phases verified per transition:
//   1. davinci-stark ballot proof verification
//   2. ECDSA signature verification (one per ballot)
//   3. STATETX state transition (voteID / ballot / ResultsAdd / ResultsSub SMT ops)
//   4. CENSUS lean-IMT Poseidon membership proofs
//   5. REG5BLK ecgfp5 ElGamal re-encryption verification
//   6. KZGBLK EIP-4844 blob barycentric evaluation
//
// Batch layout (8 transitions): scale = VOTES_PER_BATCH / 4 (rounded down to a power of 2).
// Default VOTES_PER_BATCH=4 gives the historic layout (max 4 voters per batch).
// The effective cap comes from DAVINCI_MAX_BATCH_SIZE, which must match the
// input-gen/service/circuit build configuration.
//   Batch 1:  2*scale fresh voters   (idx 0 .. 2s-1)
//   Batch 2:  4*scale fresh voters   (idx 2s .. 6s-1)
//   Batch 3:  2*scale overwrites     (idx 0 .. 2s-1 => 1st overwrite)
//   Batch 4:  2*scale fresh voters   (idx 6s .. 8s-1)
//   Batch 5:  4*scale fresh voters   (idx 8s .. 12s-1)
//   Batch 6:  4*scale overwrites     (idx 2s .. 6s-1 => 1st overwrite)
//   Batch 7:  2*scale overwrites     (idx 0 .. 2s-1 => 2nd overwrite)
//   Batch 8:  2*scale fresh voters   (idx 12s .. 14s-1)
// After all transitions the test decrypts the ElGamal-accumulated tally and
// verifies that each vote field matches the analytically expected total.
// Prerequisites:
//   - docker compose up -d --build (starts davinci-zkvm service)
//   - DAVINCI_API_URL (default: http://localhost:8080)
//   - DAVINCI_PROOF_TIMEOUT (default: 5m per ZisK proof)
//   - VOTES_PER_BATCH (default: 4, capped by DAVINCI_MAX_BATCH_SIZE)
//   - DAVINCI_MAX_BATCH_SIZE (default: 128, power of two)
//   - DAVINCI_STARK_MAX_CONCURRENCY (default: 8)

import (
	"testing"
	"time"
)

func TestFullE2E(t *testing.T) {
	// Scale all batch sizes by VOTES_PER_BATCH / 4.
	// With the default VOTES_PER_BATCH=4, scale=1 and sizes are unchanged.
	// Larger values are capped to the configured max batch size.
	votesPerBatch := votesPerBatchFromEnv()
	scale := votesPerBatch / 4
	if scale < 1 {
		scale = 1
	}
	t.Logf("VOTES_PER_BATCH=%d => scale=%d (max batch size=%d)", votesPerBatch, scale, 4*scale)
	t.Logf("max proofs per zkVM job=%d", maxProofsPerJobFromEnv())

	// Batch layout
	// Size: voters in this batch (must be power of two >= 2).
	// VoterStart: -1 => fresh voters; >= 0 => overwrite voters at that index.
	// SeedOffset: shifts the deterministic ballot-field seed so overwrite
	//   values differ from the originals, making the tally verifiable.
	batches := []batchSpec{
		// Phase A: initial fresh votes
		{Size: 2 * scale, VoterStart: -1, SeedOffset: 0}, // batch 1: fresh
		{Size: 4 * scale, VoterStart: -1, SeedOffset: 0}, // batch 2: fresh

		// Phase B: first round of overwrites (interleaved with fresh)
		{Size: 2 * scale, VoterStart: 0, SeedOffset: 7},  // batch 3: overwrite batch-1 voters (1st time)
		{Size: 2 * scale, VoterStart: -1, SeedOffset: 0}, // batch 4: fresh
		{Size: 4 * scale, VoterStart: -1, SeedOffset: 0}, // batch 5: fresh

		// Phase C: more overwrites and double overwrite
		{Size: 4 * scale, VoterStart: 2 * scale, SeedOffset: 7}, // batch 6: overwrite batch-2 voters (1st time)
		{Size: 2 * scale, VoterStart: 0, SeedOffset: 13},        // batch 7: overwrite batch-1 voters (2nd time = 3rd vote)

		// Phase D: final fresh votes after all overwrites
		{Size: 2 * scale, VoterStart: -1, SeedOffset: 0}, // batch 8: fresh
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

	// 1. Create election
	election, err := NewElection(nFresh)
	if err != nil {
		t.Fatalf("NewElection(%d): %v", nFresh, err)
	}
	if err := election.ConfigureForStark(); err != nil {
		t.Fatalf("ConfigureForStark: %v", err)
	}
	t.Logf("Election created with %d voters", nFresh)
	t.Logf("  ProcessID:    %s", election.ProcessIDHex())
	t.Logf("  Initial root: %s", election.OldRoot)

	// 2. Service check
	client := requireCompatibleService(t)
	t.Logf("Service compatible at %s", apiURL)

	// 3. Run transitions
	voterOffset := 0
	prevRoot := election.OldRoot
	totalWall := time.Now()
	overwritesSeen := 0
	proofStepIdx := 0

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
		progress := batchProgressSummary(
			spec,
			voterOffset,
			nFresh,
			len(election.VotedBallotsG5),
			overwritesSeen,
		)
		t.Logf("Transition %d/%d [%s]: batch=%d seed=%d created=%d overwrites=%d freshAssigned=%d/%d freshRemaining=%d netBallots=%d",
			txIdx+1, nTransitions, kind, spec.Size, seedBase,
			progress.Created, progress.Overwrites,
			progress.FreshAssigned, nFresh, progress.FreshRemaining, progress.NetBallots)

		chunks := chunkBatchSize(len(batchVoters))
		totalChunkWall := time.Now()
		totalProofInputs := 0

		chunkStart := 0
		for chunkIdx, chunkSize := range chunks {
			chunkEnd := chunkStart + chunkSize
			chunkVoters := batchVoters[chunkStart:chunkEnd]
			chunkSeedBase := seedBase + int64(chunkStart)
			start := time.Now()

			t.Logf("  Chunk %d/%d: proofs=%d seed=%d", chunkIdx+1, len(chunks), chunkSize, chunkSeedBase)

			batch, err := GenerateStarkBallotBatch(election.ProcessID, election.StarkEncKeyHex, chunkVoters, chunkSeedBase)
			if err != nil {
				t.Fatalf("tx %d chunk %d: GenerateStarkBallotBatch: %v", txIdx+1, chunkIdx+1, err)
			}
			totalProofInputs += len(batch.StarkProofs)
			t.Logf("    Ballot proofs generated (%d) in %.1fs", chunkSize, time.Since(start).Seconds())

			oldRoot := election.OldRoot
			if oldRoot != prevRoot {
				t.Fatalf("tx %d chunk %d: root discontinuity: expected %s, got %s", txIdx+1, chunkIdx+1, prevRoot, oldRoot)
			}

			kzgBlock, err := election.BuildKZGBlock(proofStepIdx, oldRoot)
			if err != nil {
				t.Fatalf("tx %d chunk %d: BuildKZGBlock: %v", txIdx+1, chunkIdx+1, err)
			}
			reencBlock, reencBallots, err := election.BuildStarkReencBlock(batch.Results)
			if err != nil {
				t.Fatalf("tx %d chunk %d: BuildStarkReencBlock: %v", txIdx+1, chunkIdx+1, err)
			}
			stateBlock, overwrittenBallots, err := election.BuildStarkStateBlock(chunkVoters, batch.Results, reencBallots)
			if err != nil {
				t.Fatalf("tx %d chunk %d: BuildStarkStateBlock: %v", txIdx+1, chunkIdx+1, err)
			}
			censusProofs, err := election.BuildCensusProofs(chunkVoters)
			if err != nil {
				t.Fatalf("tx %d chunk %d: BuildCensusProofs: %v", txIdx+1, chunkIdx+1, err)
			}

			if len(overwrittenBallots) > 0 {
				t.Logf("    %d overwrite(s): subtracted old ballots from tally", len(overwrittenBallots))
			}
			overwritesSeen += len(overwrittenBallots)
			t.Logf("    State summary: distinctVotersCreated=%d overwrittenVotes=%d netBallots=%d proofInputs=%d",
				voterOffset, overwritesSeen, len(election.VotedBallotsG5), len(batch.StarkProofs))

			req := batch.ToProveRequest()
			req.State = stateBlock
			req.CensusProofs = censusProofs
			req.Ecgfp5Reencryption = reencBlock
			req.KZG = kzgBlock

			t.Logf("    Submitting to %s …", apiURL)
			jobID, err := client.SubmitProve(req)
			if err != nil {
				t.Fatalf("tx %d chunk %d: SubmitProve: %v", txIdx+1, chunkIdx+1, err)
			}
			t.Logf("    Job %s submitted", jobID)

			job, err := client.WaitForJob(jobID, proofTimeout())
			if err != nil {
				t.Fatalf("tx %d chunk %d: WaitForJob %s: %v", txIdx+1, chunkIdx+1, jobID, err)
			}
			elapsed := time.Since(start)
			if job.ElapsedMs != nil {
				t.Logf("    Done in %dms (proof) / %.1fs (wall)", *job.ElapsedMs, elapsed.Seconds())
			} else {
				t.Logf("    Done in %.1fs (wall)", elapsed.Seconds())
			}
			if job.Status != "done" {
				errMsg := "<no error>"
				if job.Error != nil {
					errMsg = *job.Error
				}
				t.Fatalf("tx %d chunk %d: job %s status=%q: %s", txIdx+1, chunkIdx+1, jobID, job.Status, errMsg)
			}

			prevRoot = election.OldRoot
			t.Logf("    New root: %s", prevRoot)
			proofStepIdx++
			chunkStart = chunkEnd
		}

		t.Logf("  Logical transition completed in %.1fs across %d proof job(s) and %d proof inputs",
			time.Since(totalChunkWall).Seconds(), len(chunks), totalProofInputs)
	}

	t.Logf("=== All %d transitions done in %.1fs; decrypting tally (%d net ballots) ===",
		nTransitions, time.Since(totalWall).Seconds(), len(election.VotedBallotsG5))

	// 4. Verify tally
	fieldTotals, err := election.DecryptStarkTally(4096)
	if err != nil {
		t.Fatalf("DecryptStarkTally: %v", err)
	}

	expected := expectedTally(batches)
	t.Logf("Tally results (actual vs expected):")
	allOK := true
	for i, v := range fieldTotals {
		marker := "✓"
		if int64(v) != expected[i] {
			marker = "✗"
			allOK = false
		}
		t.Logf("  field[%d] = %3d (expected %3d) %s", i, v, expected[i], marker)
	}

	// Fields 0-5: deterministic ballot values (must match exactly).
	for i := 0; i < 6; i++ {
		if int64(fieldTotals[i]) != expected[i] {
			t.Errorf("field[%d]: got %d, want %d", i, fieldTotals[i], expected[i])
		}
	}
	// Fields 6-7: padding (must be zero).
	for i := 6; i < 8; i++ {
		if fieldTotals[i] != 0 {
			t.Errorf("field[%d] (padding): got %d, want 0", i, fieldTotals[i])
		}
	}

	if !allOK {
		t.Fatal("tally mismatch detected")
	}

	t.Logf("Final state root: %s", election.OldRoot)
	t.Logf("=== TestFullE2E PASSED ===")
}
