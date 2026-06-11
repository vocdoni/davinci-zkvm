// chain_orch_test.go drives a chained-mode election through the
// go-sdk/chain orchestrator: the Sequencer owns the state tree, fold
// cadence and finalize; the test only simulates voters (ballot proofs,
// census) and checks the final result. Needs a running service with a
// GPU; gated by CHAIN_ORCH_TEST=1.
//
//	CHAIN_ORCH_TEST=1 DAVINCI_API_URL=http://127.0.0.1:8090 \
//	  CHAIN_BATCHES=2 CHAIN_BATCH_SIZE=2 CHAIN_FOLD_EVERY=1 \
//	  go test ./integration -run TestChainOrchestrator -v
package integration

import (
	"math/big"
	"os"
	"testing"

	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/chain"
	davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"
)

// chainVotes converts a generated ballot batch to chain.Vote values,
// rebuilding each elgamal.Ballot from the raw RTE ciphertext data.
func chainVotes(voters []*Voter, results []*BallotResult) []chain.Vote {
	votes := make([]chain.Vote, len(results))
	for idx, res := range results {
		ballot := elgamal.NewBallot(bjjgnark.New())
		for i := 0; i < 8; i++ {
			c1 := bjjgnark.New().SetPoint(res.RawBallot.C1X[i], res.RawBallot.C1Y[i])
			c2 := bjjgnark.New().SetPoint(res.RawBallot.C2X[i], res.RawBallot.C2Y[i])
			ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
		}
		votes[idx] = chain.Vote{
			CensusIdx:   voters[idx].CensusIdx,
			VoteID:      res.VoteID,
			AddressLo16: res.AddressLo16,
			Ballot:      ballot,
		}
	}
	return votes
}

func TestChainOrchestrator(t *testing.T) {
	if os.Getenv("CHAIN_ORCH_TEST") == "" {
		t.Skip("set CHAIN_ORCH_TEST=1 to run the chain orchestrator test")
	}
	nBatches := envInt("CHAIN_BATCHES", 2)
	batchSize := envInt("CHAIN_BATCH_SIZE", 2)
	foldEvery := envInt("CHAIN_FOLD_EVERY", 1)

	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v", apiURL, err)
	}

	// Voter simulation side: keys, census and ballot proofs.
	election, err := NewElection(nBatches * batchSize)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	censusRoot, ok := election.Census.Root()
	if !ok {
		t.Fatal("census tree has no root")
	}

	seq, err := chain.NewSequencer(client, chain.Config{
		ProcessID:    new(big.Int).SetBytes(election.ProcessID[:]),
		BallotMode:   big.NewInt(0x01),
		EncKey:       election.EncKey,
		CensusOrigin: uint64(election.CensusOrigin),
		CensusRoot:   censusRoot,
	}, foldEvery, proofTimeout())
	if err != nil {
		t.Fatalf("NewSequencer: %v", err)
	}
	// The sequencer's genesis root must equal the test election's
	// independently built genesis root.
	if seq.State().Root() != election.OldRoot {
		t.Fatalf("genesis root mismatch: chain %s, election %s", seq.State().Root(), election.OldRoot)
	}
	t.Logf("genesis root: %s", seq.State().Root())

	for b := 0; b < nBatches; b++ {
		voters := election.Voters[b*batchSize : (b+1)*batchSize]
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, int64(42+100*b))
		if err != nil {
			t.Fatalf("batch %d: GenerateBallotBatch: %v", b, err)
		}
		censusProofs, err := election.BuildCensusProofs(voters)
		if err != nil {
			t.Fatalf("batch %d: BuildCensusProofs: %v", b, err)
		}
		req := batch.ToProveRequest()
		req.CensusProofs = censusProofs

		jobID, err := seq.ProveBatch(chainVotes(voters, batch.Results), req)
		if err != nil {
			t.Fatalf("batch %d: ProveBatch: %v", b, err)
		}
		t.Logf("batch %d: job %s  root -> %s  fold -> %s",
			b, jobID, seq.State().Root(), seq.LastFoldJob())
	}

	final, err := seq.Finalize(election.EncPrivKey)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	t.Logf("finalize: job %s  results=%v", final.JobID, final.Results)

	d := final.Digest
	if d.StepCount != seq.FoldCount() {
		t.Errorf("step_count = %d, want %d folds", d.StepCount, seq.FoldCount())
	}
	if int(d.TotalVoters) != nBatches*batchSize {
		t.Errorf("total_voters = %d, want %d", d.TotalVoters, nBatches*batchSize)
	}
	if d.BatchVK != seq.BatchVK() {
		t.Errorf("digest batch_vk = %s, want %s", d.BatchVK, seq.BatchVK())
	}
	if d.FoldVK != seq.AggregatorVK() {
		t.Errorf("digest fold_vk = %s, want %s", d.FoldVK, seq.AggregatorVK())
	}

	if err := davinciSolidity.VerifyOnSimulated(solidityDir(), final.Snark); err != nil {
		t.Errorf("on-chain verification of final PLONK failed: %v", err)
	} else {
		t.Logf("final PLONK verified on simulated chain; results=%v", final.Results)
	}
}
