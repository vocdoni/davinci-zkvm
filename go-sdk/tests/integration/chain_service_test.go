// chain_service_test.go drives the chained-mode service pipeline end to
// end over HTTP: N stark batch proves, a bootstrap fold to learn the
// aggregator vk, a genesis fold bound to that vk, then chained folds.
// Asserts digest continuity and the external vk-binding checks on the
// final fold's publics. Needs a running service with a GPU; gated by
// CHAIN_SERVICE_TEST=1.
//
//	CHAIN_SERVICE_TEST=1 DAVINCI_API_URL=http://127.0.0.1:8090 \
//	  CHAIN_BATCHES=2 CHAIN_BATCH_SIZE=2 \
//	  go test ./integration -run TestChainServiceFlow -v
package integration

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"testing"

	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"
)

// buildChainConfig assembles the aggregator ChainConfig for an election.
// All 32-byte fields are arbo little-endian hex, matching the guest's
// config frame and the in-guest genesis root computation.
func buildChainConfig(e *Election) (*davinci.ChainConfig, error) {
	bLen := arbo.HashFunctionSha256.Len()
	le32 := func(bi *big.Int) string {
		return hex.EncodeToString(arbo.BigIntToBytes(bLen, bi))
	}
	rx, ry := e.EncKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	censusRoot, ok := e.Census.Root()
	if !ok {
		return nil, fmt.Errorf("census tree has no root")
	}
	return &davinci.ChainConfig{
		ProcessID:    le32(new(big.Int).SetBytes(e.ProcessID[:])),
		BallotMode:   le32(big.NewInt(0x01)),
		EncX:         le32(tx),
		EncY:         le32(ty),
		CensusOrigin: uint64(e.CensusOrigin),
		CensusRoot:   le32(censusRoot),
	}, nil
}

// buildResultsPayload decrypts the single net Results accumulator with the
// election private key and assembles the finalize payload: TE ballot
// coordinates, plaintexts, 8 Chaum-Pedersen proofs and the SMT inclusion
// siblings of the Results leaf. Returns the payload and the plaintext tally.
func buildResultsPayload(e *Election) (*davinci.ResultsPayload, []uint64, error) {
	le32 := func(v *big.Int) string {
		return hex.EncodeToString(arbo.BigIntToBytes(32, v))
	}
	const maxMsg = uint64(1) << 20

	decryptAcc := func(acc frAccumBallot) ([]string, []uint64, []davinci.CpProof, error) {
		coords := make([]string, 32)
		for i, v := range acc {
			coords[i] = le32(v)
		}
		msgs := make([]uint64, 8)
		proofs := make([]davinci.CpProof, 8)
		for i := 0; i < 8; i++ {
			c1rx, c1ry := format.FromTEtoRTE(acc[i*4], acc[i*4+1])
			c2rx, c2ry := format.FromTEtoRTE(acc[i*4+2], acc[i*4+3])
			c1 := e.EncKey.New().SetPoint(c1rx, c1ry)
			c2 := e.EncKey.New().SetPoint(c2rx, c2ry)
			_, msg, err := elgamal.Decrypt(e.EncKey, e.EncPrivKey, c1, c2, maxMsg)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("decrypt ciphertext %d: %w", i, err)
			}
			proof, err := elgamal.BuildDecryptionProof(
				e.EncPrivKey, e.EncKey, c1, c2, new(big.Int).Set(msg))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("decryption proof %d: %w", i, err)
			}
			a1rx, a1ry := proof.A1.Point()
			a1x, a1y := format.FromRTEtoTE(a1rx, a1ry)
			a2rx, a2ry := proof.A2.Point()
			a2x, a2y := format.FromRTEtoTE(a2rx, a2ry)
			proofs[i] = davinci.CpProof{
				A1X: le32(a1x), A1Y: le32(a1y),
				A2X: le32(a2x), A2Y: le32(a2y),
				Z: le32(proof.Z),
			}
			msgs[i] = msg.Uint64()
		}
		return coords, msgs, proofs, nil
	}

	coords, msgs, proofs, err := decryptAcc(e.Results)
	if err != nil {
		return nil, nil, fmt.Errorf("Results: %w", err)
	}

	siblings := func(key uint64) ([]string, error) {
		bLen := arbo.HashFunctionSha256.Len()
		keyBytes := arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(key))
		_, _, packedSibs, exists, err := e.ProcTree.GenProof(keyBytes)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("results key 0x%02x not in state tree", key)
		}
		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSibs)
		if err != nil {
			return nil, err
		}
		zero := make([]byte, bLen)
		for len(sibs) < procLevels {
			sibs = append(sibs, zero)
		}
		out := make([]string, procLevels)
		for i, s := range sibs[:procLevels] {
			out[i] = hex.EncodeToString(pad32(s))
		}
		return out, nil
	}
	sibs, err := siblings(keyResults)
	if err != nil {
		return nil, nil, err
	}

	results := make([]uint64, 8)
	copy(results, msgs)
	return &davinci.ResultsPayload{
		Ballot:   coords,
		Results:  msgs,
		CpProofs: proofs,
		Siblings: sibs,
	}, results, nil
}

// aggDigest is the parsed aggregator public digest (53 u32 LE words).
type aggDigest struct {
	mode, stepCount, totalVoters, totalOverwrites uint32
	configCommitment                              []byte // 32 bytes
	stateRoot                                     []byte // 32 bytes (arbo LE)
	batchVK, foldVK                               string // 0x-prefixed BE hex
	results                                       [8]uint64
}

func parseAggDigest(t *testing.T, publics []byte) *aggDigest {
	t.Helper()
	if len(publics) < 53*4 {
		t.Fatalf("publics too short: %d bytes", len(publics))
	}
	if string(publics[0:4]) != "DAG1" {
		t.Fatalf("bad digest magic: %x", publics[0:4])
	}
	w := func(i int) uint32 { return binary.LittleEndian.Uint32(publics[i*4:]) }
	vkHex := func(off int) string {
		b := make([]byte, 32)
		for i := 0; i < 4; i++ {
			v := uint64(w(off+i*2)) | uint64(w(off+i*2+1))<<32
			binary.BigEndian.PutUint64(b[i*8:], v)
		}
		return "0x" + hex.EncodeToString(b)
	}
	d := &aggDigest{
		mode:             w(1),
		stepCount:        w(2),
		totalVoters:      w(3),
		totalOverwrites:  w(4),
		configCommitment: publics[5*4 : 13*4],
		stateRoot:        publics[13*4 : 21*4],
		batchVK:          vkHex(21),
		foldVK:           vkHex(29),
	}
	for i := 0; i < 8; i++ {
		d.results[i] = uint64(w(37+i*2)) | uint64(w(37+i*2+1))<<32
	}
	return d
}

func TestChainServiceFlow(t *testing.T) {
	if os.Getenv("CHAIN_SERVICE_TEST") == "" {
		t.Skip("set CHAIN_SERVICE_TEST=1 to run the chained-mode service test")
	}
	nBatches := envInt("CHAIN_BATCHES", 2)
	batchSize := envInt("CHAIN_BATCH_SIZE", 2)
	// The last `overwriteBatches` batches re-vote earlier batches' voters, so the
	// net Results accumulator subtracts the overwritten ballots. Batch
	// (nBatches-overwriteBatches+j) re-uses batch j's voters with a fresh seed
	// (distinct voteIDs => ballot UPDATE + voteID INSERT). CHAIN_OVERWRITE=1 is a
	// shorthand for a single overwrite batch.
	overwriteBatches := envInt("CHAIN_OVERWRITE_BATCHES", 0)
	if os.Getenv("CHAIN_OVERWRITE") != "" && overwriteBatches == 0 {
		overwriteBatches = 1
	}
	if overwriteBatches >= nBatches {
		overwriteBatches = nBatches - 1 // keep at least one fresh batch to overwrite
	}
	if overwriteBatches < 0 {
		overwriteBatches = 0
	}

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
	t.Logf("genesis root (LE): %s", election.OldRoot)

	// 1. Prove each batch with output=stark (no KZG in chained mode).
	batchJobs := make([]string, nBatches)
	roots := []string{election.OldRoot}
	wantOverwrites := 0
	for b := 0; b < nBatches; b++ {
		voterStart := b * batchSize
		// The last `overwriteBatches` batches re-vote an earlier batch's voters.
		if overwriteBatches > 0 && b >= nBatches-overwriteBatches {
			j := b - (nBatches - overwriteBatches)
			voterStart = j * batchSize
			wantOverwrites += batchSize
		}
		voters := election.Voters[voterStart : voterStart+batchSize]
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, int64(42+100*b))
		if err != nil {
			t.Fatalf("batch %d: GenerateBallotBatch: %v", b, err)
		}
		reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("batch %d: BuildReencBlock: %v", b, err)
		}
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
			t.Fatalf("batch %d: WaitForJob %s: %v", b, jobID, err)
		}
		batchJobs[b] = jobID
		roots = append(roots, election.OldRoot)
		t.Logf("batch %d: job %s  root -> %s", b, jobID, election.OldRoot)
	}

	batchInfo, err := client.FetchStarkInfo(batchJobs[0])
	if err != nil {
		t.Fatalf("FetchStarkInfo batch 0: %v", err)
	}
	t.Logf("batch program_vk: %s", batchInfo.ProgramVK)

	// 2. Bootstrap fold (fold_vk = 0) to learn the aggregator program_vk.
	bootID, err := client.SubmitFold(&davinci.FoldRequest{
		Config:    *cfg,
		BatchJobs: batchJobs[:1],
	})
	if err != nil {
		t.Fatalf("bootstrap fold: SubmitFold: %v", err)
	}
	if _, err := client.WaitForJob(bootID, proofTimeout()); err != nil {
		t.Fatalf("bootstrap fold: WaitForJob %s: %v", bootID, err)
	}
	bootInfo, err := client.FetchStarkInfo(bootID)
	if err != nil {
		t.Fatalf("bootstrap fold: FetchStarkInfo: %v", err)
	}
	aggVK := bootInfo.ProgramVK
	t.Logf("aggregator program_vk: %s", aggVK)

	// 3. Genesis fold bound to the real aggregator vk.
	prevID, err := client.SubmitFold(&davinci.FoldRequest{
		Config:    *cfg,
		BatchJobs: batchJobs[:1],
		FoldVK:    aggVK,
	})
	if err != nil {
		t.Fatalf("genesis fold: SubmitFold: %v", err)
	}
	if _, err := client.WaitForJob(prevID, proofTimeout()); err != nil {
		t.Fatalf("genesis fold: WaitForJob %s: %v", prevID, err)
	}
	t.Logf("genesis fold: job %s", prevID)

	// 4. Chained folds over the remaining batches.
	for b := 1; b < nBatches; b++ {
		foldID, err := client.SubmitFold(&davinci.FoldRequest{
			Config:      *cfg,
			PrevFoldJob: prevID,
			BatchJobs:   batchJobs[b : b+1],
		})
		if err != nil {
			t.Fatalf("fold %d: SubmitFold: %v", b, err)
		}
		if _, err := client.WaitForJob(foldID, proofTimeout()); err != nil {
			t.Fatalf("fold %d: WaitForJob %s: %v", b, foldID, err)
		}
		t.Logf("fold %d: job %s", b, foldID)
		prevID = foldID
	}

	// 5. Verify the final fold's digest and external vk binding.
	publics, err := client.FetchPublics(prevID)
	if err != nil {
		t.Fatalf("FetchPublics %s: %v", prevID, err)
	}
	d := parseAggDigest(t, publics)
	finalInfo, err := client.FetchStarkInfo(prevID)
	if err != nil {
		t.Fatalf("FetchStarkInfo final fold: %v", err)
	}

	if d.mode != 1 {
		t.Errorf("digest mode = %d, want 1 (fold)", d.mode)
	}
	if int(d.stepCount) != nBatches {
		t.Errorf("step_count = %d, want %d", d.stepCount, nBatches)
	}
	if int(d.totalVoters) != nBatches*batchSize {
		t.Errorf("total_voters = %d, want %d", d.totalVoters, nBatches*batchSize)
	}
	if int(d.totalOverwrites) != wantOverwrites {
		t.Errorf("total_overwrites = %d, want %d", d.totalOverwrites, wantOverwrites)
	}
	wantRoot := "0x" + hex.EncodeToString(d.stateRoot)
	if wantRoot != election.OldRoot {
		t.Errorf("digest state_root = %s, want %s", wantRoot, election.OldRoot)
	}
	if d.batchVK != batchInfo.ProgramVK {
		t.Errorf("digest batch_vk = %s, want %s", d.batchVK, batchInfo.ProgramVK)
	}
	// External vk-binding check: the committed fold_vk must equal the
	// program_vk the fold proof itself verifies under.
	if d.foldVK != finalInfo.ProgramVK {
		t.Errorf("digest fold_vk = %s, want fold proof program_vk %s", d.foldVK, finalInfo.ProgramVK)
	}
	t.Logf("final digest: step=%d voters=%d root=%s config_commitment=%s",
		d.stepCount, d.totalVoters, wantRoot, hex.EncodeToString(d.configCommitment))

	// 6. Finalize: decrypt the accumulators, prove the results in-guest,
	// wrap in a PLONK and check it on the local Solidity verifier.
	payload, wantResults, err := buildResultsPayload(election)
	if err != nil {
		t.Fatalf("buildResultsPayload: %v", err)
	}
	t.Logf("decrypted tally: %v", wantResults)
	finID, err := client.SubmitFinalize(&davinci.FinalizeRequest{
		Config:  *cfg,
		FoldJob: prevID,
		FoldVK:  aggVK,
		Results: *payload,
	})
	if err != nil {
		t.Fatalf("SubmitFinalize: %v", err)
	}
	if _, err := client.WaitForJob(finID, proofTimeout()); err != nil {
		t.Fatalf("finalize: WaitForJob %s: %v", finID, err)
	}
	t.Logf("finalize: job %s", finID)

	finPublics, err := client.FetchPublics(finID)
	if err != nil {
		t.Fatalf("FetchPublics finalize: %v", err)
	}
	fd := parseAggDigest(t, finPublics)
	if fd.mode != 2 {
		t.Errorf("finalize digest mode = %d, want 2", fd.mode)
	}
	if int(fd.stepCount) != nBatches {
		t.Errorf("finalize step_count = %d, want %d", fd.stepCount, nBatches)
	}
	if "0x"+hex.EncodeToString(fd.stateRoot) != election.OldRoot {
		t.Errorf("finalize state_root = 0x%x, want %s", fd.stateRoot, election.OldRoot)
	}
	if fd.batchVK != batchInfo.ProgramVK {
		t.Errorf("finalize batch_vk = %s, want %s", fd.batchVK, batchInfo.ProgramVK)
	}
	if fd.foldVK != aggVK {
		t.Errorf("finalize fold_vk = %s, want %s", fd.foldVK, aggVK)
	}
	for i := range wantResults {
		if fd.results[i] != wantResults[i] {
			t.Errorf("result[%d] = %d, want %d", i, fd.results[i], wantResults[i])
		}
	}

	snark, err := client.FetchSnark(finID)
	if err != nil {
		t.Fatalf("FetchSnark finalize: %v", err)
	}
	if err := davinciSolidity.VerifyOnSimulated(solidityDir(), snark); err != nil {
		t.Errorf("on-chain verification of final PLONK failed: %v", err)
	} else {
		t.Logf("final PLONK verified on simulated chain; results=%v", fd.results)
	}

	// Independent soundness check: compute the expected net tally directly from
	// the deterministic ballot-field formula (last ballot per voter wins) and
	// compare it to the results committed in the finalize proof. This does not
	// reuse the Go accumulator (election.Results), so a divergence between the
	// circuit's in-guest net computation and the intended tally would surface
	// here even if both Go accumulator and circuit agreed on a wrong value.
	expTally := expectedChainTally(nBatches, batchSize, overwriteBatches)
	for i := 0; i < 8; i++ {
		if fd.results[i] != expTally[i] {
			t.Errorf("analytic tally field[%d]: proof committed %d, expected %d",
				i, fd.results[i], expTally[i])
		}
	}
	t.Logf("analytic net tally verified against finalize proof: %v", expTally)
}

// expectedChainTally analytically computes the net vote tally for the chained
// service test: `overwriteBatches` of the final batches re-vote earlier
// batches' voters, and only the last ballot per voter counts. It mirrors
// BallotProofForTestDeterministic's field formula (field f, seed s: first
// (s+f*1000+attempt)%16 not already used in that ballot; 6 non-zero fields,
// slots 6-7 always zero) with the chained test's seed scheme (seedBase =
// 42+100*b, voter i in a batch uses seedBase+i).
func expectedChainTally(nBatches, batchSize, overwriteBatches int) [8]uint64 {
	lastFields := make(map[int][8]int64)
	for b := 0; b < nBatches; b++ {
		voterStart := b * batchSize
		if overwriteBatches > 0 && b >= nBatches-overwriteBatches {
			voterStart = (b - (nBatches - overwriteBatches)) * batchSize
		}
		seedBase := int64(42 + 100*b)
		for i := 0; i < batchSize; i++ {
			seed := seedBase + int64(i)
			var fields [8]int64
			stored := map[int64]bool{}
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
			lastFields[voterStart+i] = fields
		}
	}
	var totals [8]uint64
	for _, fields := range lastFields {
		for f := 0; f < 8; f++ {
			totals[f] += uint64(fields[f])
		}
	}
	return totals
}
