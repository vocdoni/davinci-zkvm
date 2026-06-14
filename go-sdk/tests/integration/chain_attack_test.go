// chain_attack_test.go mounts adversarial attacks on the chained-mode fold
// pipeline that the circuit-level cheat tests can't reach: it tries to
// reorder, skip and replay batch proofs in the fold chain. The aggregator
// guest enforces state-root continuity in-circuit (pubs[2..10] ==
// chain state_root), so every one of these must fail to PROVE — the fold
// job ends "failed", never "done". A fold that succeeds here would be a
// soundness break (the chain could be reordered or have votes dropped).
// Needs a running service with a GPU; gated by CHAIN_ATTACK_TEST=1.
//
//	CHAIN_ATTACK_TEST=1 DAVINCI_API_URL=http://127.0.0.1:8080 \
//	  go test ./integration -run TestChainAttackFoldChain -v -timeout 40m
package integration

import (
	"os"
	"testing"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func TestChainAttackFoldChain(t *testing.T) {
	if os.Getenv("CHAIN_ATTACK_TEST") == "" {
		t.Skip("set CHAIN_ATTACK_TEST=1 to run the chained-mode fold attack test")
	}
	const nBatches = 3
	const batchSize = 2

	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v", apiURL, err)
	}

	election, err := NewElection(nBatches * batchSize)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	cfg, err := buildChainConfig(election)
	if err != nil {
		t.Fatalf("buildChainConfig: %v", err)
	}

	// Prove all batches honestly (output=stark). Record the chain root before
	// and after each batch so we know which continuity each fold expects.
	batchJobs := make([]string, nBatches)
	rootBefore := make([]string, nBatches)
	for b := 0; b < nBatches; b++ {
		voters := election.Voters[b*batchSize : (b+1)*batchSize]
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, int64(42+100*b))
		if err != nil {
			t.Fatalf("batch %d: GenerateBallotBatch: %v", b, err)
		}
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("batch %d: BuildReencBlock: %v", b, err)
		}
		rootBefore[b] = election.OldRoot
		stateBlock, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("batch %d: BuildStateBlock: %v", b, err)
		}
		censusProofs, err := election.BuildCensusProofs(voters)
		if err != nil {
			t.Fatalf("batch %d: BuildCensusProofs: %v", b, err)
		}
		req := batch.ToProveRequest()
		req.State = stateBlock
		req.CensusProofs = censusProofs
		req.Reencryption = reencBlock
		req.Output = "stark"

		jobID, err := client.SubmitProve(req)
		if err != nil {
			t.Fatalf("batch %d: SubmitProve: %v", b, err)
		}
		if _, err := client.WaitForJob(jobID, proofTimeout()); err != nil {
			t.Fatalf("batch %d: WaitForJob: %v", b, err)
		}
		batchJobs[b] = jobID
		t.Logf("batch %d proved: job %s  root %s -> %s", b, jobID, rootBefore[b], election.OldRoot)
	}

	// Bootstrap fold to learn the aggregator program_vk, then a real genesis
	// fold of batch 0. After this, the chain state_root = root after batch 0.
	bootID, err := client.SubmitFold(&davinci.FoldRequest{Config: *cfg, BatchJobs: batchJobs[:1]})
	if err != nil {
		t.Fatalf("bootstrap fold: %v", err)
	}
	if _, err := client.WaitForJob(bootID, proofTimeout()); err != nil {
		t.Fatalf("bootstrap fold WaitForJob: %v", err)
	}
	bootInfo, err := client.FetchStarkInfo(bootID)
	if err != nil {
		t.Fatalf("bootstrap FetchStarkInfo: %v", err)
	}
	aggVK := bootInfo.ProgramVK

	genID, err := client.SubmitFold(&davinci.FoldRequest{Config: *cfg, BatchJobs: batchJobs[:1], FoldVK: aggVK})
	if err != nil {
		t.Fatalf("genesis fold: %v", err)
	}
	if _, err := client.WaitForJob(genID, proofTimeout()); err != nil {
		t.Fatalf("genesis fold WaitForJob: %v", err)
	}
	t.Logf("genesis fold %s done; chain root now = root after batch 0", genID)

	// mustFail submits a fold that should violate the in-guest continuity
	// check and asserts it does NOT complete successfully.
	mustFail := func(name string, req *davinci.FoldRequest) {
		t.Run(name, func(t *testing.T) {
			jobID, err := client.SubmitFold(req)
			if err != nil {
				// Rejected synchronously at submit — also an acceptable rejection.
				t.Logf("[%s] rejected at submit (acceptable): %v", name, err)
				return
			}
			job, err := client.WaitForJob(jobID, proofTimeout())
			if err != nil {
				t.Logf("[%s] correctly failed to prove: %v", name, err)
				return
			}
			if job.Status == "done" {
				t.Fatalf("[%s] SOUNDNESS BREAK: forged fold %s completed with status=done", name, jobID)
			}
			t.Logf("[%s] correctly rejected: status=%s", name, job.Status)
		})
	}

	// Attack 1: skip a batch. Fold batch 2 directly onto the genesis fold
	// (which expects batch 1's root). batch 2's root_before != chain root.
	mustFail("skip_batch1", &davinci.FoldRequest{
		Config:      *cfg,
		PrevFoldJob: genID,
		BatchJobs:   batchJobs[2:3],
	})

	// Attack 2: replay batch 0. Its root_before is the genesis root, but the
	// chain root has already advanced past it after the genesis fold.
	mustFail("replay_batch0", &davinci.FoldRequest{
		Config:      *cfg,
		PrevFoldJob: genID,
		BatchJobs:   batchJobs[0:1],
	})

	// Attack 3: forged fold_vk binding on a chained fold. The committed
	// fold_vk must equal the prev fold proof's program_vk; a bogus value
	// trips the in-guest assert_eq!(pvk, fold_vk).
	mustFail("wrong_fold_vk", &davinci.FoldRequest{
		Config:      *cfg,
		PrevFoldJob: genID,
		BatchJobs:   batchJobs[1:2],
		FoldVK:      "0x1100000000000000000000000000000000000000000000000000000000000000",
	})

	// Control: the honest next fold (batch 1) must still succeed, proving the
	// chain itself is healthy and only the forged variants are rejected.
	t.Run("honest_batch1_ok", func(t *testing.T) {
		jobID, err := client.SubmitFold(&davinci.FoldRequest{
			Config:      *cfg,
			PrevFoldJob: genID,
			BatchJobs:   batchJobs[1:2],
		})
		if err != nil {
			t.Fatalf("honest fold submit: %v", err)
		}
		if _, err := client.WaitForJob(jobID, proofTimeout()); err != nil {
			t.Fatalf("honest fold should succeed but failed: %v", err)
		}
		t.Logf("honest batch-1 fold %s succeeded", jobID)
	})
}
