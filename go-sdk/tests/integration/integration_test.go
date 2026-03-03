// integration_test.go is the main integration test for chained DAVINCI protocol
// state-transitions.
// It creates a real election, generates BN254 Groth16 ballot proofs dynamically,
// submits multiple chained state-transitions to the running davinci-zkvm service,
// accumulates the ElGamal ciphertexts homomorphically, and verifies the final
// vote tally by decrypting with the election private key.
// Prerequisites:
//   - docker compose up -d --build (starts davinci-zkvm service)
//   - DAVINCI_API_URL (default: http://localhost:8080)
//   - DAVINCI_PROOF_TIMEOUT (default: 5m per ZisK proof)
package integration

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// batchSpec describes one state-transition batch: how many voters, which
// slot in election.Voters they come from, and an optional seed offset.
// VoterStart=-1 means "take the next block of fresh voters (advancing the
// running voterOffset)"; a non-negative VoterStart re-uses voters starting at
// that index to simulate overwrites.  SeedOffset is added to txIdx*1000+1 so
// overwrite seeds differ mod 16 from any fresh-vote seed residue.
type batchSpec struct {
	Size       int
	VoterStart int // -1 = fresh voters; ≥0 = overwrite voters at this index
	SeedOffset int // added to (txIdx*1000+1) to shift ballot field values
}

// defaultBatches defines how many ballots are in each state-transition batch.
// The first 20 entries use fresh voters (60 total); the last 2 re-use voters
// 0-1 and 2-5 to exercise the overwrite (ResultsSub) code path.
// SeedOffset=7 shifts overwrite seeds to residue 8 mod 16, distinct from the
// residues (1 or 9) produced by the fresh-vote formula.
var defaultBatches = []batchSpec{
	{2, -1, 0}, {4, -1, 0}, {2, -1, 0}, {4, -1, 0}, {2, -1, 0},
	{4, -1, 0}, {2, -1, 0}, {4, -1, 0}, {2, -1, 0}, {4, -1, 0},
	{2, -1, 0}, {4, -1, 0}, {2, -1, 0}, {4, -1, 0}, {2, -1, 0},
	{4, -1, 0}, {2, -1, 0}, {4, -1, 0}, {2, -1, 0}, {4, -1, 0},
	// Overwrite transitions: voters 0-1 and 2-5 cast replacement ballots.
	{2, 0, 7},
	{4, 2, 7},
}

// freshVoterCount returns the total number of distinct (fresh) voters needed.
func freshVoterCount(batches []batchSpec) int {
	n := 0
	for _, b := range batches {
		if b.VoterStart < 0 {
			n += b.Size
		}
	}
	return n
}

// batchesFromEnv returns the batch specs from DAVINCI_INTEGRATION_BATCH_SIZES
// (overwrite batches are always appended) or the default if not set.
func batchesFromEnv() []batchSpec {
	if s := os.Getenv("DAVINCI_INTEGRATION_BATCH_SIZES"); s != "" {
		parts := strings.Split(s, ",")
		specs := make([]batchSpec, 0, len(parts))
		for _, p := range parts {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil && n >= 2 {
				specs = append(specs, batchSpec{n, -1, 0})
			}
		}
		if len(specs) > 0 {
			// Append overwrite batches when there are enough fresh voters.
			total := freshVoterCount(specs)
			if total >= 6 {
				specs = append(specs, batchSpec{2, 0, 7}, batchSpec{4, 2, 7})
			}
			return specs
		}
	}
	return defaultBatches
}

// TestChainedStateTransitions is the main multi-transition integration test.
// It runs ~20 chained DAVINCI state-transitions against the running
// davinci-zkvm service. Each transition uses a fresh batch of ballot proofs,
// and the old-root from one transition is the new-root for the next.
// After all transitions, it decrypts the accumulated tally and verifies
// that the vote counts are consistent with the generated ballots.
func TestChainedStateTransitions(t *testing.T) {
	batches := batchesFromEnv()
	nFresh := freshVoterCount(batches)
	nTransitions := len(batches)

	t.Logf("=== TestChainedStateTransitions: %d transitions, %d fresh voters ===",
		nTransitions, nFresh)

	// 1. Create election
	t.Logf("Creating election with %d voters...", nFresh)
	election, err := NewElection(nFresh)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	t.Logf("Election created; initial state root: %s", election.OldRoot)

	client := newClient()

	// Verify service is reachable.
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}

	// 2. Tally accumulator
	tally := NewTallyAccumulator()

	// 3. Run transitions
	voterOffset := 0
	for txIdx, spec := range batches {
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
		t.Logf("--- Transition %d/%d: batch_size=%d overwrite=%v seed_base=%d ---",
			txIdx+1, nTransitions, batchSize, isOverwrite, seedBase)

		start := time.Now()

		// Generate ballot proofs.
		t.Logf("  Generating %d ballot proofs (seed base=%d)...", batchSize, seedBase)
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, batchVoters, seedBase)
		if err != nil {
			t.Fatalf("transition %d: GenerateBallotBatch: %v", txIdx, err)
		}
		t.Logf("  Ballot proofs generated in %.1fs", time.Since(start).Seconds())

		// Save old root before building state block (KZG needs it).
		oldRoot := election.OldRoot

		// Build KZG block first (uses oldRoot before it's advanced).
		kzgBlock, err := election.BuildKZGBlock(txIdx, oldRoot)
		if err != nil {
			t.Fatalf("transition %d: BuildKZGBlock: %v", txIdx, err)
		}

		// Build re-encryption block before building the state block so the
		// re-encrypted ballots can be accumulated into ResultsAdd.
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("transition %d: BuildReencBlock: %v", txIdx, err)
		}

		// Build state-transition block (advances election.OldRoot).
		// Returns overwritten old ballots (non-empty only for overwrite batches).
		stateBlock, overwrittenBallots, err := election.BuildStateBlock(batchVoters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("transition %d: BuildStateBlock: %v", txIdx, err)
		}

		// Build census membership proofs.
		censusProofs, err := election.BuildCensusProofs(batchVoters)
		if err != nil {
			t.Fatalf("transition %d: BuildCensusProofs: %v", txIdx, err)
		}

		// Accumulate re-encrypted ballots; subtract any overwritten old ones so
		// the tally reflects only the latest ballot per voter.
		tally.Add(reencBallots)
		if len(overwrittenBallots) > 0 {
			tally.Subtract(overwrittenBallots)
			t.Logf("  %d overwrite(s) detected; subtracted from tally", len(overwrittenBallots))
		}

		// Assemble the full ProveRequest.
		req := batch.ToProveRequest()
		req.State = stateBlock
		req.CensusProofs = censusProofs
		req.Reencryption = reencBlock
		req.KZG = kzgBlock

		// Submit to the service.
		t.Logf("  Submitting job to %s...", apiURL)
		jobID, err := client.SubmitProve(req)
		if err != nil {
			t.Fatalf("transition %d: SubmitProve: %v", txIdx, err)
		}
		t.Logf("  Job %s submitted (transition %d/%d)", jobID, txIdx+1, nTransitions)

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

	// 4. Verify tally
	t.Logf("=== All %d transitions done; decrypting tally (%d net ballots) ===",
		nTransitions, tally.count)

	fieldTotals, err := tally.DecryptTally(election.EncPrivKey)
	if err != nil {
		t.Fatalf("DecryptTally: %v", err)
	}

	// Compute expected totals from the known ballot field generation formula.
	expected := expectedTally(batches)

	t.Logf("Vote tally (field totals vs expected):")
	for i, v := range fieldTotals {
		t.Logf("  field[%d] = %s (expected %d)", i, v.String(), expected[i])
	}

	// Fields 0-5 must exactly match the analytically computed expected totals.
	for i := 0; i < 6; i++ {
		if fieldTotals[i].Int64() != expected[i] {
			t.Errorf("field[%d]: got %s, want %d", i, fieldTotals[i].String(), expected[i])
		}
	}
	// Fields 6-7 are always zero (padding slots).
	for i := 6; i < 8; i++ {
		if fieldTotals[i].Sign() != 0 {
			t.Errorf("field[%d] (padding): got %s, want 0", i, fieldTotals[i].String())
		}
	}
	t.Logf("Final state root: %s", election.OldRoot)
	t.Logf("=== TestChainedStateTransitions PASSED ===")
}

// expectedTally computes the analytically expected vote totals for the given
// batch sequence.  It mirrors GenDeterministicBallotFields from davinci-node:
//   - spec.Size voters; seeds = txIdx*1000+1 … +Size
//   - overwrite specs (VoterStart≥0) replace earlier votes for those voter indices
//   - each ballot has 6 non-zero fields; values are unique within a ballot
//   - field f, voter seed s: first (s+f*1000+attempt)%16 not already used in that ballot
// Only the LAST ballot cast by each voter is counted.
func expectedTally(batches []batchSpec) [8]int64 {
	// lastFields maps voter index → their most recently cast ballot fields.
	lastFields := make(map[int][8]int64)
	voterOffset := 0

	for txIdx, spec := range batches {
		seedBase := int64(txIdx*1000 + 1 + spec.SeedOffset)
		startIdx := voterOffset
		if spec.VoterStart >= 0 {
			startIdx = spec.VoterStart
		} else {
			voterOffset += spec.Size
		}

		for v := 0; v < spec.Size; v++ {
			voterIdx := startIdx + v
			seed := seedBase + int64(v)
			stored := map[int64]bool{}
			var fields [8]int64
			for f := int64(0); f < 6; f++ {
				for attempt := int64(0); ; attempt++ {
					val := (seed + f*1000 + attempt) % 16
					if !stored[val] {
						fields[f] = val
						stored[val] = true
						break
					}
				}
			}
			lastFields[voterIdx] = fields
		}
	}

	// Sum only the last ballot per voter.
	var totals [8]int64
	for _, fields := range lastFields {
		for f := 0; f < 8; f++ {
			totals[f] += fields[f]
		}
	}
	return totals
}

// checkServiceURL pings a URL and returns an error if unreachable.
func checkServiceURL(url string) error {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
