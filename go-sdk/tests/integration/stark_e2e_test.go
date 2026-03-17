package integration

import (
	"testing"
)

func TestDavinciStarkServiceE2E(t *testing.T) {
	client := requireCompatibleService(t)

	election, err := NewElection(4)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	if err := election.ConfigureForStark(); err != nil {
		t.Fatalf("ConfigureForStark: %v", err)
	}

	batches := []struct {
		voterStart int
		size       int
		seedOffset int
	}{
		{voterStart: 0, size: 2, seedOffset: 0},
		{voterStart: 1, size: 2, seedOffset: 10},
	}

	for txIdx, spec := range batches {
		batchVoters := election.Voters[spec.voterStart : spec.voterStart+spec.size]
		seedBase := int64(txIdx*1000 + 1 + spec.seedOffset)

		batch, err := GenerateStarkBallotBatch(election.ProcessID, election.StarkEncKeyHex, batchVoters, seedBase)
		if err != nil {
			t.Fatalf("tx %d GenerateStarkBallotBatch: %v", txIdx+1, err)
		}

		oldRoot := election.OldRoot
		kzgBlock, err := election.BuildKZGBlock(txIdx, oldRoot)
		if err != nil {
			t.Fatalf("tx %d BuildKZGBlock: %v", txIdx+1, err)
		}
		reencBlock, reencBallots, err := election.BuildStarkReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("tx %d BuildStarkReencBlock: %v", txIdx+1, err)
		}
		stateBlock, _, err := election.BuildStarkStateBlock(batchVoters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("tx %d BuildStarkStateBlock: %v", txIdx+1, err)
		}
		censusProofs, err := election.BuildCensusProofs(batchVoters)
		if err != nil {
			t.Fatalf("tx %d BuildCensusProofs: %v", txIdx+1, err)
		}

		req := batch.ToProveRequest()
		req.State = stateBlock
		req.CensusProofs = censusProofs
		req.Ecgfp5Reencryption = reencBlock
		req.KZG = kzgBlock

		jobID, err := client.SubmitProve(req)
		if err != nil {
			t.Fatalf("tx %d SubmitProve: %v", txIdx+1, err)
		}
		job, err := client.WaitForJob(jobID, proofTimeout())
		if err != nil {
			t.Fatalf("tx %d WaitForJob: %v", txIdx+1, err)
		}
		if job.Status != "done" {
			t.Fatalf("tx %d job %s failed: status=%s err=%v", txIdx+1, jobID, job.Status, job.Error)
		}
	}

	totals, err := election.DecryptStarkTally(128)
	if err != nil {
		t.Fatalf("DecryptStarkTally: %v", err)
	}
	expected := expectedTally([]batchSpec{
		{Size: 2, SeedOffset: 0},
		{Size: 2, SeedOffset: 10, VoterStart: 1},
	})
	for i := 0; i < 6; i++ {
		if totals[i] != uint64(expected[i]) {
			t.Fatalf("field[%d] = %d, want %d", i, totals[i], expected[i])
		}
	}
}
