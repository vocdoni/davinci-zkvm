// cheat_test.go tests that the davinci-zkvm circuit correctly rejects tampered
// protocol inputs by verifying specific fail_mask bits are set.
// These tests use ziskemu directly and do NOT require the davinci-zkvm API
// service. They exercise circuit constraint violations to verify the circuit
// correctly rejects malformed inputs.
// Each test:
//  1. Generates a self-contained valid circuit input (2 ballot proofs on-the-fly)
//  2. Verifies the valid input is accepted (overall_ok = 1)
//  3. Tampers one field and verifies the corresponding fail_mask bit is set
// Prerequisites:
//   - ziskemu in PATH
//   - gen-input binary in PATH or at target/release/gen-input
//   - CIRCUIT_ELF_PATH or the default circuit.elf location
package integration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/vocdoni/davinci-node/circuits/ballotproof"
	"github.com/vocdoni/davinci-node/crypto/blobs"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// Fail-mask bit constants => must match circuit/src/types.rs.
const (
	failCurve       = uint32(1 << 1)  // proof point not on curve
	failPairing     = uint32(1 << 2)  // batch pairing check failed
	failECDSA       = uint32(1 << 3)  // ECDSA signature or address binding failed
	failSMTVoteID   = uint32(1 << 10) // voteID insertion chain invalid
	failSMTBallot   = uint32(1 << 11) // ballot insertion chain invalid
	failSMTResults  = uint32(1 << 12) // resultsAdd/Sub transition invalid
	failSMTProcess  = uint32(1 << 13) // process read-proof invalid
	failConsistency = uint32(1 << 14) // voteID namespace / proof binding mismatch
	failBallotNS    = uint32(1 << 15) // ballot namespace / address binding mismatch
	failCensus      = uint32(1 << 16) // census membership proof failed
	failReenc       = uint32(1 << 17) // re-encryption verification failed
	failKZG         = uint32(1 << 18) // KZG barycentric evaluation mismatch

	// failSMTAny covers any SMT-related failure (bits 10–13).
	failSMTAny = failSMTVoteID | failSMTBallot | failSMTResults | failSMTProcess
)

// cheatElectionInput holds a fully encoded, valid circuit input for 2 voters
// plus references to all intermediate encoded blocks for tampering.
type cheatElectionInput struct {
	// baseBin is the Groth16+ECDSA section from gen-input (covers all 2 proofs).
	baseBin []byte
	// stateData is the decoded state block (for tampering before re-encoding).
	stateData *davinci.StateTransitionData
	// stateBlock is the encoded STATETX block bytes.
	stateBlock []byte
	// censusBlock is the encoded CENSUS block bytes.
	censusBlock []byte
	// reencBlock is the encoded REENCBLK block bytes.
	reencBlock []byte
	// kzgBlock is the encoded KZGBLK block bytes.
	kzgBlock []byte
	// oldRoot is the state root BEFORE the state transition (for KZG Z derivation).
	oldRoot string
}

// fullInput concatenates all blocks into a single binary.
func (c *cheatElectionInput) fullInput() []byte {
	var buf []byte
	buf = append(buf, c.baseBin...)
	buf = append(buf, c.stateBlock...)
	buf = append(buf, c.censusBlock...)
	buf = append(buf, c.reencBlock...)
	buf = append(buf, c.kzgBlock...)
	return buf
}

// buildCheatInput generates a complete, valid circuit input for 2 voters
// using the BallotProofForTestDeterministic helper and gen-input.
// Returns the assembled input ready for ziskemu.
func buildCheatInput(t *testing.T) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()

	// Create election with exactly 2 voters.
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}

	// Generate 2 ballot proofs.
	batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, election.Voters, 42)
	if err != nil {
		t.Fatalf("GenerateBallotBatch: %v", err)
	}

	// Write proofs to a temp directory so gen-input can read them.
	tmpDir := t.TempDir()

	// Write the VK.
	vkPath := filepath.Join(tmpDir, "verification_key.json")
	if err := os.WriteFile(vkPath, ballotproof.CircomVerificationKey, 0600); err != nil {
		t.Fatalf("write vk: %v", err)
	}

	// Write proof_N.json, public_N.json, sig_N.json (1-indexed).
	for i, res := range batch.Results {
		idx := i + 1

		proofPath := filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", idx))
		if err := os.WriteFile(proofPath, res.ProofJSON, 0600); err != nil {
			t.Fatalf("write proof_%d: %v", idx, err)
		}

		pubBytes, err := json.Marshal(res.PublicInputs)
		if err != nil {
			t.Fatalf("marshal public_%d: %v", idx, err)
		}
		pubPath := filepath.Join(tmpDir, fmt.Sprintf("public_%d.json", idx))
		if err := os.WriteFile(pubPath, pubBytes, 0600); err != nil {
			t.Fatalf("write public_%d: %v", idx, err)
		}

		sigPath := filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", idx))
		if err := os.WriteFile(sigPath, res.SigJSON, 0600); err != nil {
			t.Fatalf("write sig_%d: %v", idx, err)
		}
	}

	// Run gen-input.
	genInputBin := findGenInputBin(t)
	outBin := filepath.Join(tmpDir, "input.bin")
	cmd := exec.Command(genInputBin, "--proofs-dir", tmpDir, "--output", outBin, "--nproofs", "2")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-input: %v\n%s", err, out)
	}
	baseBin, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatalf("read base bin: %v", err)
	}
	t.Logf("gen-input produced %d bytes", len(baseBin))

	// Save oldRoot before BuildStateBlock advances it.
	oldRoot := election.OldRoot

	// Build KZG block (needs oldRoot before state update).
	kzgBlock, err := election.BuildKZGBlock(0, oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
	}

	// Build re-encryption block before the state block so that re-encrypted
	// ballots are available for ResultsAdd accumulation.
	reencData, reencBallots, err := election.BuildReencBlock(batch.Results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}

	// Build state block (advances election.OldRoot, accumulates ResultsAdd).
	stateData, _, err := election.BuildStateBlock(election.Voters, batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock: %v", err)
	}
	stateBlockBytes, err := davinci.EncodeStateBlock(stateData)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	// Build census block.
	censusProofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	censusBlockBytes, err := davinci.EncodeCensusBlock(censusProofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}

	reencBlockBytes, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	// Encode KZG block.
	kzgBlockBytes, err := encodeKZGRequest(kzgBlock)
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}

	return &cheatElectionInput{
		baseBin:     baseBin,
		stateData:   stateData,
		stateBlock:  stateBlockBytes,
		censusBlock: censusBlockBytes,
		reencBlock:  reencBlockBytes,
		kzgBlock:    kzgBlockBytes,
		oldRoot:     oldRoot,
	}, election, batch.Results
}

// encodeKZGRequest converts a *davinci.KZGRequest (service format) to circuit binary.
func encodeKZGRequest(req *davinci.KZGRequest) ([]byte, error) {
	if req == nil {
		return nil, nil
	}
	processIDBytes, err := hex.DecodeString(trimHex(req.ProcessID))
	if err != nil {
		return nil, fmt.Errorf("processID: %w", err)
	}
	rootBytes, err := hex.DecodeString(trimHex(req.RootHashBefore))
	if err != nil {
		return nil, fmt.Errorf("rootHashBefore: %w", err)
	}
	commBytes, err := hex.DecodeString(trimHex(req.Commitment))
	if err != nil {
		return nil, fmt.Errorf("commitment: %w", err)
	}
	blobBytes, err := hex.DecodeString(trimHex(req.Blob))
	if err != nil {
		return nil, fmt.Errorf("blob: %w", err)
	}
	yBytes, err := hex.DecodeString(trimHex(req.YClaimed))
	if err != nil {
		return nil, fmt.Errorf("yClaimed: %w", err)
	}

	var comm48 [48]byte
	copy(comm48[:], commBytes)
	var yClaimed [32]byte
	copy(yClaimed[:], yBytes)

	blob := new(types.Blob)
	copy(blob[:], blobBytes)

	return davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      processIDBytes,
		RootHashBefore: rootBytes,
		Commitment:     comm48,
		YClaimed:       yClaimed,
		Blob:           blob[:],
	})
}

// trimHex removes a leading "0x" prefix.
func trimHex(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// findGenInputBin locates the gen-input binary.
func findGenInputBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GEN_INPUT_BIN"); p != "" {
		return p
	}
	// Try $REPO_ROOT/target/release/gen-input.
	if p, err := exec.LookPath("gen-input"); err == nil {
		return p
	}
	// Derive from ELF path or cwd.
	candidates := []string{
		"/home/p4u/davinci-zkvm/target/release/gen-input",
		"../../../../target/release/gen-input",
		"../../../target/release/gen-input",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("gen-input not found — build with 'cargo build --release -p davinci-zkvm-input-gen'")
	return ""
}

// assertCircuitValid runs ziskemu on input and fails if overall_ok != 1.
func assertCircuitValid(t *testing.T, input []byte, label string) {
	t.Helper()
	outputs, err := runZiskEmu(input)
	if err != nil {
		t.Fatalf("[%s] ziskemu failed: %v", label, err)
	}
	if len(outputs) == 0 {
		t.Fatalf("[%s] no outputs from ziskemu", label)
	}
	if outputs[davinci.OutputOverallOk] != 1 {
		t.Errorf("[%s] expected overall_ok=1, got %d; fail_mask=0x%08x",
			label, outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
	}
}

// assertCircuitFails runs ziskemu on input and checks that the expected fail_mask
// bits are all set and overall_ok == 0.
func assertCircuitFails(t *testing.T, input []byte, wantBits uint32, label string) {
	t.Helper()
	outputs, err := runZiskEmu(input)
	if err != nil {
		t.Fatalf("[%s] ziskemu failed: %v", label, err)
	}
	if len(outputs) < 2 {
		t.Fatalf("[%s] too few outputs: %d", label, len(outputs))
	}
	if outputs[davinci.OutputOverallOk] != 0 {
		t.Errorf("[%s] expected overall_ok=0, got %d", label, outputs[davinci.OutputOverallOk])
	}
	mask := outputs[davinci.OutputFailMask]
	if mask&wantBits == 0 {
		t.Errorf("[%s] expected fail_mask bits 0x%08x set, got fail_mask=0x%08x", label, wantBits, mask)
	} else {
		t.Logf("[%s] correctly rejected: fail_mask=0x%08x (expected bits 0x%08x)", label, mask, wantBits)
	}
}

// Cheat Tests

// TestCheatSanity verifies that the self-generated input is accepted by the circuit.
// This is a prerequisite for all other cheat tests.
func TestCheatSanity(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	assertCircuitValid(t, base.fullInput(), "sanity")
}

// TestCheatWrongKZG verifies that a tampered KZG Y value causes FAIL_KZG.
func TestCheatWrongKZG(t *testing.T) {
	base, election, _ := buildCheatInput(t)

	// Build a KZG block with a wrong Y value (all-0xff).
	var wrongY [32]byte
	for i := range wrongY {
		wrongY[i] = 0xff
	}

	// Recreate a valid blob for the same commitment.
	var blob types.Blob
	big.NewInt(99).FillBytes(blob[0:32])
	commitment, err := blob.ComputeCommitment()
	if err != nil {
		t.Fatalf("ComputeCommitment: %v", err)
	}
	comm48 := [48]byte(commitment)

	// Use the election's correct processID (BE hex) and the OLD root (before
	// state transition) so only FAIL_KZG is triggered (not FAIL_BINDING).
	pidBE, _ := hex.DecodeString(trimHex(election.ProcessIDHex()))
	rootBE, _ := hex.DecodeString(trimHex(arboHexToBEHex(base.oldRoot)))

	wrongKZG, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      pidBE,
		RootHashBefore: rootBE,
		Commitment:     comm48,
		YClaimed:       wrongY,
		Blob:           blob[:],
	})
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}

	tampered := append(append(append(base.baseBin, base.stateBlock...), base.censusBlock...), base.reencBlock...)
	tampered = append(tampered, wrongKZG...)
	assertCircuitFails(t, tampered, failKZG, "wrong_kzg_y")
}

// TestCheatWrongCensusRoot verifies that a wrong census root causes FAIL_CENSUS.
func TestCheatWrongCensusRoot(t *testing.T) {
	base, election, _ := buildCheatInput(t)

	// Build census proofs but swap the root to an arbitrary wrong value.
	censusProofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	// Corrupt the root in all proofs.
	wrongRoot := bigIntToFr32(big.NewInt(0xDEADBEEF))
	for i := range censusProofs {
		censusProofs[i].Root = wrongRoot
	}

	tamperedCensus, err := davinci.EncodeCensusBlock(censusProofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}

	tampered := append(append(base.baseBin, base.stateBlock...), tamperedCensus...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failCensus, "wrong_census_root")
}

// TestCheatWrongReencKey verifies that a wrong re-encryption public key causes FAIL_REENC.
func TestCheatWrongReencKey(t *testing.T) {
	base, election, results := buildCheatInput(t)

	// Build a reenc block with the correct entries but a wrong public key.
	reencData, _, err := election.BuildReencBlock(results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	// Swap the encryption key to an obviously wrong value.
	reencData.EncryptionKeyX = bigIntToFr32(big.NewInt(0x12345678))
	reencData.EncryptionKeyY = bigIntToFr32(big.NewInt(0x87654321))

	tamperedReenc, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	tampered := append(append(base.baseBin, base.stateBlock...), base.censusBlock...)
	tampered = append(tampered, tamperedReenc...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failReenc, "wrong_reenc_key")
}

// TestCheatWrongStateRoot verifies that an incorrect old state root in STATETX causes
// at least one FAIL_SMT_* bit in the fail_mask.
func TestCheatWrongStateRoot(t *testing.T) {
	base, _, _ := buildCheatInput(t)

	// Shallow-copy the stateData and corrupt the old root.
	sd := *base.stateData
	sd.OldStateRoot = "0x" + hex.EncodeToString(make([]byte, 32)) // all-zeros
	sd.ProcessID = sd.OldStateRoot                                 // processID = hash of old state

	tamperedState, err := davinci.EncodeStateBlock(&sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	tampered := append(base.baseBin, tamperedState...)
	tampered = append(tampered, base.censusBlock...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	// Expect at least one FAIL_SMT_* bit set.
	assertCircuitFails(t, tampered, failSMTAny, "wrong_state_root")
}

// TestCheatMismatchedVoteID verifies that a voteID SMT entry whose key doesn't
// match the ballot proof's voteID causes FAIL_CONSISTENCY or FAIL_SMT_VOTEID.
func TestCheatMismatchedVoteID(t *testing.T) {
	base, _, _ := buildCheatInput(t)

	// Shallow-copy the stateData and tamper the first voteID SMT entry's key.
	sd := *base.stateData
	if len(sd.VoteIDSmt) > 0 {
		// Replace the new key with an obviously wrong value (no bit 63).
		sd.VoteIDSmt[0].NewKey = bigIntToFr32(big.NewInt(0x1234567890ABCDEF))
	}

	tamperedState, err := davinci.EncodeStateBlock(&sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	tampered := append(base.baseBin, tamperedState...)
	tampered = append(tampered, base.censusBlock...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failConsistency|failSMTAny, "mismatched_vote_id")
}

// TestCheatValidKZGRoundTrip verifies the KZG evaluation against multiple blob types
// to ensure the KZG encoding is correct. The processID and rootHashBefore must match
// the STATETX block values so the cross-block binding check passes.
func TestCheatValidKZGRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		blob   func() *types.Blob
	}{
		{
			name: "sparse_blob",
			blob: func() *types.Blob {
				var b types.Blob
				big.NewInt(42).FillBytes(b[0:32])
				big.NewInt(100).FillBytes(b[32:64])
				return &b
			},
		},
		{
			name: "full_blob",
			blob: func() *types.Blob {
				b, _ := blobs.GetBlobData1()
				return b
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			blob := tc.blob()
			if blob == nil {
				t.Skip("blob data not available")
			}
			base, election, _ := buildCheatInput(t)

			commitment, err := blob.ComputeCommitment()
			if err != nil {
				t.Fatalf("ComputeCommitment: %v", err)
			}
			comm48 := [48]byte(commitment)

			// Use the election's actual processID (BE) and the OLD root
			// (before state transition) so the circuit's cross-block binding
			// check passes. election.OldRoot was advanced by BuildStateBlock,
			// so we use base.oldRoot which was saved before the transition.
			pidHex := election.ProcessIDHex()
			rootBEHex := arboHexToBEHex(base.oldRoot)

			z := deriveKZGZ(pidHex, rootBEHex, comm48)

			y, err := blobs.EvaluateBarycentricNative(blob, z, false)
			if err != nil {
				t.Fatalf("EvaluateBarycentricNative: %v", err)
			}
			var yClaimed [32]byte
			y.FillBytes(yClaimed[:])

			processIDBytes, _ := hex.DecodeString(trimHex(pidHex))
			rootBytes, _ := hex.DecodeString(trimHex(rootBEHex))

			kzgBlock, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{
				ProcessID:      processIDBytes,
				RootHashBefore: rootBytes,
				Commitment:     comm48,
				YClaimed:       yClaimed,
				Blob:           blob[:],
			})
			if err != nil {
				t.Fatalf("EncodeKZGBlock: %v", err)
			}

			input := append(append(append(append(base.baseBin, base.stateBlock...), base.censusBlock...), base.reencBlock...), kzgBlock...)
			assertCircuitValid(t, input, tc.name)
		})
	}
}
