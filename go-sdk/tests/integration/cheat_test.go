// cheat_test.go tests that the davinci-zkvm circuit correctly rejects tampered
// protocol inputs by verifying specific fail_mask bits are set.
// These tests use ziskemu directly and do NOT require the davinci-zkvm API
// service. They exercise circuit constraint violations to verify the circuit
// correctly rejects malformed inputs.
// Each test:
//  1. Generates a self-contained valid circuit input (2 ballot proofs on-the-fly)
//  2. Verifies the valid input is accepted (overall_ok = 1)
//  3. Tampers one field and verifies the corresponding fail_mask bit is set
//
// Prerequisites:
//   - ziskemu in PATH
//   - gen-input, found via GEN_INPUT_BIN, then target/release, then PATH
//   - CIRCUIT_ELF_PATH or the default circuit.elf location
package integration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	leanimt "github.com/vocdoni/lean-imt-go"
)

// Fail-mask bit constants => must match circuit/src/types.rs.
const (
	failCurve       = uint32(1 << 1)  // proof point not on curve
	failPairing     = uint32(1 << 2)  // batch pairing check failed
	failECDSA       = uint32(1 << 3)  // ECDSA signature or address binding failed
	failSMTVoteID   = uint32(1 << 10) // voteID insertion chain invalid
	failSMTBallot   = uint32(1 << 11) // ballot insertion chain invalid
	failSMTResults  = uint32(1 << 12) // net Results transition invalid
	failSMTProcess  = uint32(1 << 13) // process read-proof invalid
	failConsistency = uint32(1 << 14) // voteID namespace / proof binding mismatch
	failBallotNS    = uint32(1 << 15) // ballot namespace / address binding mismatch
	failCensus      = uint32(1 << 16) // census membership proof failed
	failReenc       = uint32(1 << 17) // re-encryption verification failed
	failKZG         = uint32(1 << 18) // KZG barycentric evaluation mismatch
	failMissing     = uint32(1 << 19) // mandatory block absent
	failResultAccum = uint32(1 << 20) // net Results accumulator leaf mismatch
	failLeafHash    = uint32(1 << 21) // ballot SMT leaf hash mismatch
	failBinding     = uint32(1 << 22) // cross-block binding mismatch
	failRefresh     = uint32(1 << 24) // silent-refresh chain: count, keys, chain or re-randomization
	failParse       = uint32(1 << 31) // input malformed / truncated / trailing bytes

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
	// preBatchResults is the accumulator BEFORE this batch's Results transition
	// (only populated by buildCheatInputTwoBatches; nil in the single-batch helper).
	// Together with batchReencBallots / batchOverwrittenBallots it lets a test
	// recompute the "no-refresh-delta" Results leaf without touching the tree.
	preBatchResults frAccumBallot
	// batchReencBallots is this batch's re-encrypted ballots.
	batchReencBallots []wideBallot
	// batchOverwrittenBallots is this batch's overwritten (old) ballots.
	batchOverwrittenBallots []wideBallot
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
	return buildCheatInputN(t, 2)
}

// buildCheatInputN is buildCheatInput for an election of n voters, all
// voting in one batch.
func buildCheatInputN(t *testing.T, n int) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()
	election, err := NewElection(n)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	return buildCheatInputElection(t, election)
}

// buildCheatInputElection builds one batch in which every voter of election
// votes, so a test can adjust the election (census, slot overrides) first.
func buildCheatInputElection(t *testing.T, election *Election) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()
	n := len(election.Voters)

	// Generate the ballot proofs.
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

	// Write proof_N.json and sig_N.json (1-indexed); the guest derives the
	// public inputs.
	for i, res := range batch.Results {
		idx := i + 1

		proofPath := filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", idx))
		if err := os.WriteFile(proofPath, res.ProofJSON, 0600); err != nil {
			t.Fatalf("write proof_%d: %v", idx, err)
		}

		sigPath := filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", idx))
		if err := os.WriteFile(sigPath, res.SigJSON, 0600); err != nil {
			t.Fatalf("write sig_%d: %v", idx, err)
		}
	}

	// Run gen-input.
	genInputBin := findGenInputBin(t)
	outBin := filepath.Join(tmpDir, "input.bin")
	cmd := exec.Command(genInputBin, "--proofs-dir", tmpDir, "--output", outBin, "--nproofs", strconv.Itoa(n))
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

	// Build re-encryption block before the state block so that re-encrypted
	// ballots are available for net Results accumulation.
	reencData, reencBallots, err := election.BuildReencBlock(oldRoot, batch.Results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}

	// Build state block (advances election.OldRoot, accumulates net Results,
	// stashes DA cells for BuildKZGBlock).
	stateData, _, err := election.BuildStateBlock(election.Voters, batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock: %v", err)
	}

	// Build KZG block AFTER the state block so it can rebuild the same DA
	// cells the guest constructs from verified state.
	kzgBlock, _, err := election.BuildKZGBlock(oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
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

// encodeKZGRequest converts a *davinci.KZGRequest (service format) to the
// KZGBLK binary block the guest parses (magic + pid + rhb + n_blobs +
// n × 48-byte commitments).
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
	commitments := make([][48]byte, len(req.Commitments))
	for i, c := range req.Commitments {
		cb, err := hex.DecodeString(trimHex(c))
		if err != nil {
			return nil, fmt.Errorf("commitment[%d]: %w", i, err)
		}
		if len(cb) != 48 {
			return nil, fmt.Errorf("commitment[%d]: expected 48 bytes, got %d", i, len(cb))
		}
		copy(commitments[i][:], cb)
	}
	return davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      processIDBytes,
		RootHashBefore: rootBytes,
		Commitments:    commitments,
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
	// Then the workspace build, then PATH: a stale copy on PATH must never
	// shadow the tree's own build.
	candidates := []string{
		"../../../../target/release/gen-input",
		"../../../target/release/gen-input",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("gen-input"); err == nil {
		return p
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

// assertCircuitFailsExactly is assertCircuitFails with fail_mask == wantBits,
// for inputs built to trip one check and nothing else.
func assertCircuitFailsExactly(t *testing.T, input []byte, wantBits uint32, label string) {
	t.Helper()
	outputs, err := runZiskEmu(input)
	if err != nil {
		t.Fatalf("[%s] ziskemu failed: %v", label, err)
	}
	if len(outputs) < 2 {
		t.Fatalf("[%s] too few outputs: %d", label, len(outputs))
	}
	if ok, mask := outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask]; ok != 0 || mask != wantBits {
		t.Errorf("[%s] expected overall_ok=0 fail_mask=0x%08x, got overall_ok=%d fail_mask=0x%08x", label, wantBits, ok, mask)
	}
}

// Cheat Tests

// TestCheatSanity verifies that the self-generated input is accepted by the circuit.
// This is a prerequisite for all other cheat tests.
func TestCheatSanity(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	assertCircuitValid(t, base.fullInput(), "sanity")
}

// TestCheatWrongKZGCommitment observes that flipping a byte in a host
// commitment changes the guest-emitted blobs digest. The guest cannot detect
// a mismatched commitment (the on-chain point-evaluation precompile does that
// via z = H(tag || pid || root || D || n || b || commitment); a different
// commitment shifts z, and y = P_cells(z) shifts with it), so overall_ok
// stays 1 — but the digest that binds (commitment, y) pairs must diverge
// from the honest baseline. If it does not, the digest is not covering the
// commitment and the on-chain check is spoofable.
func TestCheatWrongKZGCommitment(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	honest, err := runZiskEmu(base.fullInput())
	if err != nil {
		t.Fatalf("honest ziskemu: %v", err)
	}
	if honest[davinci.OutputOverallOk] != 1 {
		t.Fatalf("honest input rejected: fail_mask=0x%08x", honest[davinci.OutputFailMask])
	}

	// Rebuild the KZG block with the first commitment tampered.
	pidHex := election.ProcessIDHex()
	rootBEHex := arboHexToBEHex(base.oldRoot)
	pidBE, _ := hex.DecodeString(trimHex(pidHex))
	rootBE, _ := hex.DecodeString(trimHex(rootBEHex))

	_, tb, err := election.BuildKZGBlock(base.oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
	}
	if len(tb.Commitments) == 0 {
		t.Fatal("expected at least one commitment")
	}
	tampered := make([][48]byte, len(tb.Commitments))
	for i, c := range tb.Commitments {
		tampered[i] = [48]byte(c)
	}
	tampered[0][0] ^= 0x01

	badKZG, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      pidBE,
		RootHashBefore: rootBE,
		Commitments:    tampered,
	})
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}

	var full []byte
	full = append(full, base.baseBin...)
	full = append(full, base.stateBlock...)
	full = append(full, base.censusBlock...)
	full = append(full, base.reencBlock...)
	full = append(full, badKZG...)

	got, err := runZiskEmu(full)
	if err != nil {
		t.Fatalf("tampered ziskemu: %v", err)
	}
	same := true
	for i := 0; i < 8; i++ {
		if got[davinci.OutputBlobsDigest+i] != honest[davinci.OutputBlobsDigest+i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("blobs digest unchanged after flipping a commitment byte — digest does not bind the commitment")
	}
}

// TestCheatTamperedBlobCommitment: the sequencer commits to a wrong blob 0
// (one cell changed) and hands the guest that commitment C'. The guest cannot
// see blob bytes, so it accepts, but it evaluates its own cells at a point
// derived from its own D and C', and publishes (C', P(z')). The wrong blob
// does not open to P(z') at z', so the settlement's point-evaluation check
// (kzg4844.VerifyProof here) refuses the batch. D is fixed before z', so the
// sequencer cannot fit the content to a point it already knows.
func TestCheatTamperedBlobCommitment(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	honest, err := runZiskEmu(base.fullInput())
	if err != nil {
		t.Fatalf("honest ziskemu: %v", err)
	}
	if honest[davinci.OutputOverallOk] != 1 {
		t.Fatalf("honest input rejected: fail_mask=0x%08x", honest[davinci.OutputFailMask])
	}
	_, tb, err := election.BuildKZGBlock(base.oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
	}
	regs32 := func(out []uint32, base int) (b [32]byte) {
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint32(b[4*i:], out[base+i])
		}
		return
	}
	if d := regs32(honest, davinci.OutputCellsDigest); d != tb.CellsDigest {
		t.Fatalf("guest D %x, CellsDigest %x", d, tb.CellsDigest)
	}

	// Wrong blob 0: the last cell of the stream changed, still a field element.
	bad := tb.Blobs[0]
	last := len(tb.Cells) - 1
	if last >= 4096 {
		t.Fatalf("test assumes the last cell sits in blob 0, T = %d", len(tb.Cells))
	}
	bad[last*32+31] ^= 0x01
	badCom, err := kzg4844.BlobToCommitment(&bad)
	if err != nil {
		t.Fatalf("BlobToCommitment: %v", err)
	}
	coms := make([][48]byte, len(tb.Commitments))
	for i, c := range tb.Commitments {
		coms[i] = [48]byte(c)
	}
	coms[0] = [48]byte(badCom)
	pidBE, _ := hex.DecodeString(trimHex(election.ProcessIDHex()))
	rootBE, _ := hex.DecodeString(trimHex(arboHexToBEHex(base.oldRoot)))
	badKZG, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{ProcessID: pidBE, RootHashBefore: rootBE, Commitments: coms})
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}
	in := *base
	in.kzgBlock = badKZG
	got, err := runZiskEmu(in.fullInput())
	if err != nil {
		t.Fatalf("tampered ziskemu: %v", err)
	}
	if got[davinci.OutputOverallOk] != 1 || got[davinci.OutputFailMask] != 0 {
		t.Fatalf("guest has no blob bytes and must still accept: ok=%d mask=0x%08x",
			got[davinci.OutputOverallOk], got[davinci.OutputFailMask])
	}
	if regs32(got, davinci.OutputCellsDigest) != tb.CellsDigest {
		t.Fatal("D moved with a commitment; it must depend on the cells only")
	}

	// The point the contract derives, and what the guest evaluated there.
	z := kzg4844.Point(davinci.EvaluationPoint([32]byte(pidBE), [32]byte(rootBE), tb.CellsDigest, len(coms), 0, coms[0]))
	_, yGuest, err := kzg4844.ComputeProof(&tb.Blobs[0], z)
	if err != nil {
		t.Fatalf("ComputeProof honest: %v", err)
	}
	var pairs []byte
	pairs = append(pairs, coms[0][:]...)
	pairs = append(pairs, yGuest[:]...)
	for i := 1; i < len(coms); i++ {
		pairs = append(pairs, coms[i][:]...)
		pairs = append(pairs, tb.Ys[i][:]...)
	}
	if regs32(got, davinci.OutputBlobsDigest) != sha256.Sum256(pairs) {
		t.Fatal("guest did not evaluate its cells at EvaluationPoint(D, C')")
	}

	// The wrong blob opens to another value at z, so no proof for C' meets
	// the published y: settlement reverts.
	badProof, yBad, err := kzg4844.ComputeProof(&bad, z)
	if err != nil {
		t.Fatalf("ComputeProof tampered: %v", err)
	}
	if yBad == yGuest {
		t.Fatal("tampered blob evaluates to the guest's y at the bound point")
	}
	if err := kzg4844.VerifyProof(badCom, z, yGuest, badProof); err == nil {
		t.Fatal("tampered blob opened to the published y")
	}
}

// kzgBlockWithCount rewrites an encoded KZGBLK to carry n commitments: the
// honest ones truncated, or extended with copies of the last.
func kzgBlockWithCount(block []byte, n int) []byte {
	const header = 8 + 32 + 32 + 8 // magic, process id, root before, n_blobs
	have := (len(block) - header) / 48
	out := append([]byte(nil), block[:header]...)
	binary.LittleEndian.PutUint64(out[header-8:], uint64(n))
	for i := 0; i < n; i++ {
		j := min(i, have-1)
		out = append(out, block[header+48*j:header+48*(j+1)]...)
	}
	return out
}

// TestCheatKZGBlobCount: the honest batch's blobs digest equals the one
// BuildTransitionBlobs computes (the guest and the Go builder lay out the
// same cells), and one commitment fewer or more than ceil(T / 4096) sets
// FAIL_KZG and nothing else, for every fill of the last integer cell
// (V + U mod 4).
func TestCheatKZGBlobCount(t *testing.T) {
	cases := []struct {
		name          string
		voters, first int // election size; voters in an earlier, unchecked batch
		residue       int // (V + U) mod 4 of the checked batch
	}{
		{"one-vote", 1, 0, 2},           // V 1, U 1
		{"two-votes", 2, 0, 0},          // V 2, U 2
		{"vote-one-refresh", 2, 1, 3},   // V 1, U 1 + 1 refresh
		{"vote-three-refresh", 4, 3, 1}, // V 1, U 1 + 3 refreshes
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			election, err := NewElection(c.voters)
			if err != nil {
				t.Fatalf("NewElection: %v", err)
			}
			var base *cheatElectionInput
			if c.first == 0 {
				base, election, _ = buildCheatInputElection(t, election)
			} else {
				base, election, _ = buildCheatInputBatches(t, election, election.Voters[:c.first], election.Voters[c.first:])
			}
			sd := base.stateData
			if got := (len(sd.VoteIDSmt) + len(sd.BallotSmt) + len(sd.RefreshSmt)) % 4; got != c.residue {
				t.Fatalf("(V + U) mod 4 = %d, want %d", got, c.residue)
			}
			outputs, err := runZiskEmu(base.fullInput())
			if err != nil {
				t.Fatalf("ziskemu: %v", err)
			}
			if outputs[davinci.OutputOverallOk] != 1 {
				t.Fatalf("honest batch rejected: fail_mask=0x%08x", outputs[davinci.OutputFailMask])
			}
			_, tb, err := election.BuildKZGBlock(base.oldRoot)
			if err != nil {
				t.Fatalf("BuildKZGBlock: %v", err)
			}
			var digest [32]byte
			for i := 0; i < 8; i++ {
				binary.LittleEndian.PutUint32(digest[4*i:], outputs[davinci.OutputBlobsDigest+i])
			}
			if digest != tb.Digest {
				t.Fatalf("guest blobs digest %x, BuildTransitionBlobs %x", digest, tb.Digest)
			}
			for i := 0; i < 8; i++ {
				binary.LittleEndian.PutUint32(digest[4*i:], outputs[davinci.OutputCellsDigest+i])
			}
			if digest != tb.CellsDigest {
				t.Fatalf("guest cells digest %x, BuildTransitionBlobs %x", digest, tb.CellsDigest)
			}
			honest := int(binary.LittleEndian.Uint64(base.kzgBlock[72:80]))
			for _, n := range []int{honest - 1, honest + 1} {
				bad := *base
				bad.kzgBlock = kzgBlockWithCount(base.kzgBlock, n)
				assertCircuitFailsExactly(t, bad.fullInput(), failKZG, fmt.Sprintf("%s-%d-blobs", c.name, n))
			}
		})
	}
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

// TestCheatSingleVote proves that a transition may carry a single vote
// package (open inclusion): nothing in the guest or input-gen needs a
// power-of-two batch.
func TestCheatSingleVote(t *testing.T) {
	base, _, _ := buildCheatInputN(t, 1)
	assertCircuitValid(t, base.fullInput(), "single_vote")
}

// TestCheatSlotMismatch writes voter 0's ballot to a slot other than the one
// its address derives (spec 4.1.6). The key is still inside the ballot
// namespace, so only the slot binding can catch it.
func TestCheatSlotMismatch(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	keyBI, err := davinci.LeHexToBigInt(base.stateData.BallotSmt[0].NewKey)
	if err != nil || !keyBI.IsUint64() {
		t.Fatalf("ballot key %s: %v", base.stateData.BallotSmt[0].NewKey, err)
	}
	// Stay inside the namespace and keep limbs 1..3 zero, so only the slot
	// equality can reject it.
	wrong := smtKeyHex(keyBI.Uint64() + 1)
	base.stateData.BallotSmt[0].NewKey = wrong
	base.stateData.BallotSmt[0].OldKey = wrong
	assertCircuitFails(t, base.reencodeState(t), failBallotNS, "slot_mismatch")
}

// smtKeyHex renders a u64 SMT key the way the state encoder expects it: 32
// LE bytes, key in limb 0.
func smtKeyHex(key uint64) string {
	return "0x" + hex.EncodeToString(keyLE32(arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(key))))
}

// TestCheatSlotHighPathBits sets the path bit just above the proof's sibling
// count. The census walk never reads it and the slot comes from the address,
// so the proof still verifies and the state block stays valid: only the
// explicit `index >> n_siblings == 0` rule (spec 3A.4) can reject the input.
// It keeps census proofs canonical.
func TestCheatSlotHighPathBits(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	censusProofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	censusProofs[0].Index |= 1 << uint(len(censusProofs[0].Siblings))
	tamperedCensus, err := davinci.EncodeCensusBlock(censusProofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	tampered := append(append(base.baseBin, base.stateBlock...), tamperedCensus...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFailsExactly(t, tampered, failCensus, "slot_high_path_bits")
}

// legacySlotKey is the compact-path slot, BallotMin + ((1 << n) |
// path_bits). The census root does not bind a leaf position, so the guest
// must reject it.
func legacySlotKey(t *testing.T, e *Election, idx int) uint64 {
	t.Helper()
	p, err := e.Census.GenerateProof(idx)
	if err != nil {
		t.Fatalf("GenerateProof(%d): %v", idx, err)
	}
	return davinci.BallotMin + (uint64(1)<<uint(len(p.Siblings)) | p.PathBits)
}

// TestCheatSlotPathDerived builds an otherwise honest batch whose ballots sit
// at path-derived slots: the state, DA and refresh data are all
// consistent, so only the address slot binding (spec 4.1.6) can reject it.
func TestCheatSlotPathDerived(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	election.SlotOverride = map[int]uint64{}
	for i := range election.Voters {
		key := legacySlotKey(t, election, i)
		if want, _ := election.slotKey(election.Voters[i]); want == key {
			t.Fatalf("voter %d: legacy slot equals the address slot", i)
		}
		election.SlotOverride[i] = key
	}
	base, _, _ := buildCheatInputElection(t, election)
	assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "slot_path_derived")
}

// shareAddress makes voter b a second census member for voter a's address:
// same signer, weight w + 1, so the leaves PackAddressWeight(addr, w) and
// PackAddressWeight(addr, w + 1) are distinct tree leaves that bind the same
// voter and slot. That is the crafted census of spec 4.1.7 (the census
// contract refuses it; the guest must too).
func shareAddress(t *testing.T, e *Election, a, b int) {
	t.Helper()
	va, vb := e.Voters[a], e.Voters[b]
	vb.Signer, vb.AddressBytes, vb.AddressBigInt = va.Signer, va.AddressBytes, va.AddressBigInt
	vb.Weight = new(big.Int).Add(va.Weight, big.NewInt(1))
	e.censusLeaves[b] = packAddressWeight(vb.AddressBigInt, vb.Weight)
	imt, err := leanimt.New(davinci.KeccakHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatalf("leanimt.New: %v", err)
	}
	for _, l := range e.censusLeaves {
		imt.Insert(l)
	}
	e.Census = imt
}

// TestCheatDuplicateSlot votes twice for one address in one batch through a
// census that carries two leaves for it. Census, signatures, state chain
// (INSERT then UPDATE of the same slot), accounting and DA are all
// consistent; only the pairwise-distinct slot check (spec 4.1.7) rejects it.
// Batch 1 seeds one ballot so occupied_before covers the in-batch overwrite.
func TestCheatDuplicateSlot(t *testing.T) {
	election, err := NewElection(3)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	shareAddress(t, election, 1, 2)
	k1, _ := election.slotKey(election.Voters[1])
	k2, _ := election.slotKey(election.Voters[2])
	if k1 != k2 {
		t.Fatalf("shared address gave slots %#x and %#x", k1, k2)
	}
	base, _, _ := buildCheatInputBatches(t, election, election.Voters[:1], election.Voters[1:3])
	if base.stateData.OverwrittenCount != 1 {
		t.Fatalf("expected one in-batch overwrite, got %d", base.stateData.OverwrittenCount)
	}
	assertCircuitFailsExactly(t, base.fullInput(), failBallotNS, "duplicate_slot")
}

// TestCheatReencKeyNonCanonical commits the encryption key as (x + p, y), the
// same point in a second encoding. The registry rejects that key at genesis,
// but the guest must still not abort on it: the subgroup check and the
// fixed-base table both use the reduced key, and the pairing reduces it as
// public input 4, so the batch proves the same statement as with (x, y).
// A guest that feeds the raw key to the precompile exits instead.
func TestCheatReencKeyNonCanonical(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	fieldP, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	rx, ry := election.EncKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	txp := new(big.Int).Add(tx, fieldP)
	var buf [64]byte
	txp.FillBytes(buf[:32])
	ty.FillBytes(buf[32:])
	digest := sha256.Sum256(buf[:])
	leaf := new(big.Int).SetBytes(digest[:])
	bLen := arbo.HashFunctionSha256.Len()
	if err := election.ProcTree.Update(
		arbo.BigIntToBytes(keyLen, big.NewInt(0x03)),
		arbo.BigIntToBytes(bLen, leaf),
	); err != nil {
		t.Fatalf("update key leaf: %v", err)
	}
	election.configVals[2] = leaf
	root, err := election.ProcTree.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	election.OldRoot = "0x" + hex.EncodeToString(pad32(root))

	base, _, _ := buildCheatInputElection(t, election)
	// REENCBLK: magic(8) n(8) pub_key_x as 4 LE limbs.
	var le [32]byte
	txp.FillBytes(le[:])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	copy(base.reencBlock[16:48], le[:])
	assertCircuitValid(t, base.fullInput(), "reenc_key_non_canonical")
}

// TestCheatWrongReencKey verifies that a wrong re-encryption public key causes FAIL_REENC.
func TestCheatWrongReencKey(t *testing.T) {
	base, election, results := buildCheatInput(t)

	// Build a reenc block with the correct entries but a wrong public key.
	reencData, _, err := election.BuildReencBlock(base.oldRoot, results)
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

// TestCheatWrongReencSeed verifies that a tampered batch re-encryption seed
// causes FAIL_REENC: the guest re-derives the scalar chain from the seed and
// the old state root, so a swapped seed produces different offset scalars and
// the re-encrypted ciphertexts no longer match.
func TestCheatWrongReencSeed(t *testing.T) {
	base, election, results := buildCheatInput(t)

	reencData, _, err := election.BuildReencBlock(base.oldRoot, results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	// Replace the seed with an obviously different 32-byte value.
	reencData.Seed = bigIntToFr32(new(big.Int).SetUint64(0xC0DE1234DEADBEEF))

	tamperedReenc, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	tampered := append(append(base.baseBin, base.stateBlock...), base.censusBlock...)
	tampered = append(tampered, tamperedReenc...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failReenc, "wrong_reenc_seed")
}

// TestCheatReencStaleRoot verifies that building the reenc block against a
// different old state root (e.g. the zero root) produces a chain the guest
// cannot reproduce, so re-encryption verification fails.
func TestCheatReencStaleRoot(t *testing.T) {
	base, election, results := buildCheatInput(t)

	staleRoot := "0x" + hex.EncodeToString(make([]byte, 32))
	reencData, _, err := election.BuildReencBlock(staleRoot, results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}

	tamperedReenc, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	tampered := append(append(base.baseBin, base.stateBlock...), base.censusBlock...)
	tampered = append(tampered, tamperedReenc...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failReenc, "stale_reenc_root")
}

// TestCheatTamperPaddedSlot verifies the soundness of the num_fields-aware skip:
// the guest skips the per-field EC re-encryption work on padded slots
// (i >= num_fields) but guards it by asserting those slots carry the TE identity.
// An attacker who stuffs a non-identity ciphertext into a skipped slot (e.g. to
// smuggle extra encrypted weight past the homomorphic accumulator) must be
// rejected. The fixture's NumFields is 6, so slot 6 is padded.
func TestCheatTamperPaddedSlot(t *testing.T) {
	base, election, results := buildCheatInput(t)

	if election.NumFields >= davinci.NumFields {
		t.Skipf("fixture NumFields=%d leaves no padded slot to tamper", election.NumFields)
	}
	padIdx := election.NumFields // first padded (skipped) ciphertext slot

	reencData, _, err := election.BuildReencBlock(base.oldRoot, results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	// Corrupt the padded slot's original ciphertext to a non-identity x-coord on
	// both sides, simulating an attacker trying to ride the skipped EC check.
	for i := range reencData.Entries {
		reencData.Entries[i].Original[padIdx].C1.X = bigIntToFr32(big.NewInt(0x99))
		reencData.Entries[i].Reencrypted[padIdx].C1.X = bigIntToFr32(big.NewInt(0x99))
	}

	tamperedReenc, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	tampered := append(append(base.baseBin, base.stateBlock...), base.censusBlock...)
	tampered = append(tampered, tamperedReenc...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failReenc, "tamper_padded_slot")
}

// TestCheatWrongStateRoot verifies that an incorrect old state root in STATETX causes
// at least one FAIL_SMT_* bit in the fail_mask.
func TestCheatWrongStateRoot(t *testing.T) {
	base, _, _ := buildCheatInput(t)

	// Shallow-copy the stateData and corrupt the old root.
	sd := *base.stateData
	sd.OldStateRoot = "0x" + hex.EncodeToString(make([]byte, 32)) // all-zeros
	sd.ProcessID = sd.OldStateRoot                                // processID = hash of old state

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

// TestCheatDoubleVote simulates a replay/double-vote: the second voter's
// voteID SMT entry is forced to re-use the first voter's voteID key. The
// circuit must reject it — a duplicate voteID either breaks the voteID
// insertion chain (FAIL_SMT_VOTEID) or the voteID-to-proof binding
// (FAIL_CONSISTENCY). This is the on-chain defense against counting the
// same vote twice.
func TestCheatDoubleVote(t *testing.T) {
	base, _, _ := buildCheatInput(t)

	sd := *base.stateData
	if len(sd.VoteIDSmt) < 2 {
		t.Skip("need at least 2 voteID SMT entries")
	}
	// Make voter 1 claim voter 0's voteID key (a duplicate insert).
	sd.VoteIDSmt[1].NewKey = sd.VoteIDSmt[0].NewKey

	tamperedState, err := davinci.EncodeStateBlock(&sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	tampered := append(base.baseBin, tamperedState...)
	tampered = append(tampered, base.censusBlock...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failSMTVoteID|failConsistency, "double_vote")
}

// TestCheatInflatedResults forges the net Results leaf to a value that does
// not match the in-circuit recomputed tally (NewResults = OldResults +
// Σ(voter ballots) − Σ(overwritten ballots)). A bad actor inflating the
// tally must be rejected: the leaf is bound to the actual ballots, so the
// forged new_value trips FAIL_RESULT_ACCUM (and the SMT transition no longer
// reconstructs new_root, FAIL_SMT_RESULTS).
func TestCheatInflatedResults(t *testing.T) {
	base, _, _ := buildCheatInput(t)

	sd := *base.stateData
	if sd.ResultsSmt == nil {
		t.Skip("no Results SMT transition in this batch")
	}
	// Forge a different net Results leaf (claim an arbitrary tally).
	forged := make([]byte, 32)
	for i := range forged {
		forged[i] = 0xAB
	}
	re := *sd.ResultsSmt
	re.NewValue = hex.EncodeToString(forged)
	sd.ResultsSmt = &re

	tamperedState, err := davinci.EncodeStateBlock(&sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	tampered := append(base.baseBin, tamperedState...)
	tampered = append(tampered, base.censusBlock...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failResultAccum|failSMTResults, "inflated_results")
}

// proofRecordLen is one proof of the Proofs section: A(64) ‖ B(128) ‖ C(64).
// The guest derives the public inputs; the input carries none.
const proofRecordLen = 64 + 128 + 64

// proofsSectionOffset parses the gen-input header/VK to locate the proofs
// section of baseBin. Layout: header(32B) | alpha(64) beta(128) gamma(128)
// delta(128) | gamma_abc_len(8) | gamma_abc(len*64) | nproofs_check(8).
// nPublic is the header's count (71).
func proofsSectionOffset(t *testing.T, baseBin []byte) (off, nproofs, nPublic int) {
	t.Helper()
	u64at := func(w int) uint64 { return binary.LittleEndian.Uint64(baseBin[w*8:]) }
	if u64at(0) != 0x423631484f545247 {
		t.Fatalf("bad magic in baseBin")
	}
	nproofs = int(u64at(2))
	nPublic = int(u64at(3))
	gammaAbcLen := int(u64at(4 + 8 + 16 + 16 + 16))
	off = 32 + 448 + 8 + gammaAbcLen*64 + 8
	return off, nproofs, nPublic
}

// reencOriginalOff is the offset of reencBlock entry i, original field f, in
// the REENCBLK: magic(8) n(8) key x(32) key y(32) seed(32), then per entry 16
// original and 16 re-encrypted ciphertexts of 4 LE words each.
func reencOriginalOff(i, f int) int { return 112 + i*2*16*128 + f*128 }

// TestCheatTamperedOriginal flips one bit of a live original ciphertext
// coordinate of voter 0 (public input 7). The guest derives the proof's public
// inputs from these ciphertexts, so the batch pairing must fail; the
// re-encryption check trips as well.
func TestCheatTamperedOriginal(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	base.reencBlock = append([]byte(nil), base.reencBlock...)
	base.reencBlock[reencOriginalOff(0, 0)] ^= 0x01 // c1.x, low bit: stays canonical
	assertCircuitFails(t, base.fullInput(), failPairing, "tampered-original")
}

// TestCheatSwappedFieldOrder swaps fields 0 and 1 of voter 0, in both the
// original and the re-encrypted ballot. The values are the voter's, in the
// wrong positions of the public-input vector.
func TestCheatSwappedFieldOrder(t *testing.T) {
	base, election, _ := buildCheatInput(t)
	if election.NumFields < 2 {
		t.Skipf("NumFields=%d has no second field", election.NumFields)
	}
	blk := append([]byte(nil), base.reencBlock...)
	for _, off := range []int{reencOriginalOff(0, 0), reencOriginalOff(0, 16)} {
		f0 := append([]byte(nil), blk[off:off+128]...)
		copy(blk[off:off+128], blk[off+128:off+256])
		copy(blk[off+128:off+256], f0)
	}
	base.reencBlock = blk
	assertCircuitFails(t, base.fullInput(), failPairing, "swapped-field-order")
}

// TestCheatOriginalNonCanonical ships voter 0's c1.x as x + r, the same field
// element in a second encoding. Re-encryption reduces it and the pairing sees
// its residue, so the canonical-encoding rule (FAIL_BINDING) rejects it; the
// vote envelope hashes the raw coordinates, so the voter's signature (over
// the canonical ones) fails too.
func TestCheatOriginalNonCanonical(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	blk := append([]byte(nil), base.reencBlock...)
	off := reencOriginalOff(0, 0)
	le := make([]byte, 32)
	copy(le, blk[off:off+32])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	v := new(big.Int).SetBytes(le)
	v.Add(v, bn254R)
	if v.BitLen() > 256 {
		t.Skip("x + r does not fit in 256 bits")
	}
	v.FillBytes(le)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		le[i], le[j] = le[j], le[i]
	}
	copy(blk[off:off+32], le)
	base.reencBlock = blk
	assertCircuitFailsExactly(t, base.fullInput(), failBinding|failECDSA, "original-plus-r")
}

// TestCheatSwappedProofs swaps the first two proof records (A, B, C). Both
// remain valid proofs, of the other voter's public inputs, which the guest
// derives per index: the pairing fails and nothing else does.
func TestCheatSwappedProofs(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, nproofs, _ := proofsSectionOffset(t, base.baseBin)
	if nproofs < 2 {
		t.Fatalf("need >= 2 proofs, got %d", nproofs)
	}
	full := base.fullInput()
	rec0 := append([]byte(nil), full[off:off+proofRecordLen]...)
	copy(full[off:off+proofRecordLen], full[off+proofRecordLen:off+2*proofRecordLen])
	copy(full[off+proofRecordLen:off+2*proofRecordLen], rec0)
	assertCircuitFailsExactly(t, full, failPairing, "swapped-proofs")
}

// TestCheatCensusSiblingFlipped flips one bit of voter 0's first census
// sibling: the Keccak walk no longer reaches the root.
func TestCheatCensusSiblingFlipped(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	census := append([]byte(nil), base.censusBlock...)
	// magic(8) n(8), proof 0: root(32) leaf(32) index(8) n_siblings(8) siblings.
	census[16+32+32+8+8] ^= 0x01
	assertCircuitFailsExactly(t, base.assembleWith(census), failCensus, "census-sibling-flipped")
}

// TestCheatCensusLeafIsInternalNode presents the level-1 node above voter 0
// as a leaf, one level shorter: the walk reaches the root, and only the
// leaf bound (check 3A.6, leaf < 2^248) tells it from a member. Address and
// weight read from the node are garbage, so other checks fail too.
func TestCheatCensusLeafIsInternalNode(t *testing.T) {
	base, election, _ := buildCheatInputN(t, 4)
	proofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	p := proofs[0]
	if p.Index&1 != 0 || len(p.Siblings) < 2 {
		t.Fatalf("voter 0 should be a left leaf with 2 siblings, got path %b, %d siblings", p.Index, len(p.Siblings))
	}
	leaf, _ := new(big.Int).SetString(trimHex(p.Leaf), 16)
	sib, _ := new(big.Int).SetString(trimHex(p.Siblings[0]), 16)
	node := davinci.KeccakHasher(leaf, sib)
	if node.BitLen() <= 248 {
		t.Skip("the internal node happens to be below 2^248")
	}
	proofs[0] = davinci.CensusProof{Root: p.Root, Leaf: bigIntToFr32(node), Index: p.Index >> 1, Siblings: p.Siblings[1:]}
	census, err := davinci.EncodeCensusBlock(proofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	assertCircuitFails(t, base.assembleWith(census), failCensus, "census-leaf-internal-node")
}

// TestCheatVKDeltaEqualsGamma copies the VK's gamma into delta: a VK
// without a phase-2 contribution, under which anyone can forge proofs. The
// guest refuses it outright (the VK hash no longer matches leaf 0x07 either).
func TestCheatVKDeltaEqualsGamma(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// Layout: header(32B) | alpha(64) | beta(128) | gamma(128) | delta(128) | ...
	gammaOff := 32 + 64 + 128
	copy(full[gammaOff+128:gammaOff+256], full[gammaOff:gammaOff+128])
	assertCircuitFails(t, full, failCurve, "vk-delta-equals-gamma")
}

// TestCheatNPublicNot71 declares the old circuit's three public inputs in
// the header. The guest only verifies BallotProof(16) proofs (71 inputs).
func TestCheatNPublicNot71(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	binary.LittleEndian.PutUint64(full[24:], 3)
	assertCircuitFails(t, full, failParse, "n-public-3")
}

// TestCheatNPublic3ShapedVK is TestCheatNPublicNot71 with a VK of the old
// shape too: gamma_abc cut to 4 points and gamma_abc_len = 4, so the length
// check holds and only the n_public rule (FAIL_PARSE) refuses it. Without
// that rule the verifier would index gamma_abc past its end.
func TestCheatNPublic3ShapedVK(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// header(32) | alpha(64) beta(128) gamma(128) delta(128) | gamma_abc_len(8) | gamma_abc
	const lenOff = 32 + 448
	icOff := lenOff + 8
	if n := binary.LittleEndian.Uint64(full[lenOff:]); n != 72 {
		t.Fatalf("gamma_abc_len = %d, want 72", n)
	}
	binary.LittleEndian.PutUint64(full[24:], 3)
	binary.LittleEndian.PutUint64(full[lenOff:], 4)
	cut := append(append([]byte(nil), full[:icOff+4*64]...), full[icOff+72*64:]...)
	assertCircuitFails(t, cut, failParse, "n-public-3-vk-4-ic")
}

// TestCheatZeroedVKGamma zeroes the VK gamma G2 point (the all-zero encoding
// the pairing precompile treats as infinity, which would silently drop the
// public-input pairing term). g2_is_valid must reject identity VK points.
func TestCheatZeroedVKGamma(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// Layout: header(32B) | alpha(64) | beta(128) | gamma(128) | ...
	gammaOff := 32 + 64 + 128
	for i := gammaOff; i < gammaOff+128; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve, "zeroed-vk-gamma")
}

// TestCheatZeroedProofA zeroes proof 0's A point (identity encoding). The
// pairing precompile skips identity pairs, so an unchecked zero A would drop
// e(r0·A0, B0) from the batch equation; the strict on-curve check must reject
// it first ((0,0) is not on the curve).
func TestCheatZeroedProofA(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, _, _ := proofsSectionOffset(t, base.baseBin)
	full := base.fullInput()
	for i := off; i < off+64; i++ {
		full[i] = 0
	}
	assertCircuitFails(t, full, failCurve, "zeroed-proof-a")
}

// TestCheatTamperGammaAbc overwrites gamma_abc[1] with gamma_abc[0]: both
// remain on-curve, so rejection must come from the pairing equation via the
// aggregated public-input MSM. Regression guard for the γ-side aggregation.
func TestCheatTamperGammaAbc(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	// gamma_abc entries (64 B each) start after header(32) + VK(448) + len(8).
	abcOff := 32 + 448 + 8
	copy(full[abcOff+64:abcOff+128], full[abcOff:abcOff+64])
	assertCircuitFails(t, full, failPairing, "tamper-gamma-abc")
}

// TestCheatTamperedSignature flips one byte of voter 0's ECDSA r. Recovery
// then yields a different (or no) address, breaking the address binding.
func TestCheatTamperedSignature(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, nproofs, _ := proofsSectionOffset(t, base.baseBin)
	sigOff := off + nproofs*proofRecordLen // ECDSA block: nproofs × (r32 ‖ s32 ‖ recid8)
	full := base.fullInput()
	full[sigOff] ^= 0x01
	assertCircuitFails(t, full, failECDSA, "tampered-signature")
}

// TestCheatTrailingGarbage appends bytes after the last block (8 of them:
// ZisK requires input length ≡ 0 mod 8, shorter tails never reach the guest).
// The parser must reject inputs it did not fully consume.
func TestCheatTrailingGarbage(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := append(base.fullInput(), 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA)
	assertCircuitFails(t, full, failParse, "trailing-garbage")
}

// TestCheatMissingStateBlock drops the STATETX block entirely.
func TestCheatMissingStateBlock(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	var full []byte
	full = append(full, base.baseBin...)
	full = append(full, base.censusBlock...)
	full = append(full, base.reencBlock...)
	full = append(full, base.kzgBlock...)
	assertCircuitFails(t, full, failMissing, "missing-state-block")
}

// TestCheatMissingKZGBlock omits the KZG block. Chained mode has no DA blob,
// so the guest accepts it, but the blobs-digest publics (8 × u32) must be all
// zero and NBlobs must be 0 so an Ethereum-mode consumer can never satisfy the
// on-chain digest check against an omitted blob.
func TestCheatMissingKZGBlock(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	var full []byte
	full = append(full, base.baseBin...)
	full = append(full, base.stateBlock...)
	full = append(full, base.censusBlock...)
	full = append(full, base.reencBlock...)
	outputs, err := runZiskEmu(full)
	if err != nil {
		t.Fatalf("ziskemu failed: %v", err)
	}
	if outputs[davinci.OutputOverallOk] != 1 {
		t.Fatalf("expected overall_ok=1 without KZG block, got %d; fail_mask=0x%08x",
			outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
	}
	for i := 0; i < 8; i++ {
		if outputs[davinci.OutputBlobsDigest+i] != 0 {
			t.Errorf("blobs_digest word %d nonzero (0x%08x) with KZG block absent",
				i, outputs[davinci.OutputBlobsDigest+i])
		}
	}
	if outputs[davinci.OutputNBlobs] != 0 {
		t.Errorf("n_blobs = %d, want 0 with KZG block absent", outputs[davinci.OutputNBlobs])
	}
}

// TestCheatOversizedNproofs claims nproofs=1025 (> MAX_BATCH_SIZE) in the
// header while carrying only 2 proof records. The parser must flag-and-clamp,
// never trust the declared count.
func TestCheatOversizedNproofs(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	full := base.fullInput()
	binary.LittleEndian.PutUint64(full[16:], 1025)
	assertCircuitFails(t, full, failParse, "oversized-nproofs")
}

// buildCheatInputTwoBatches builds a self-contained circuit input for BATCH 2
// of a 4-voter election. Batch 1 (voters 0, 1) is simulated to advance the
// state tree; batch 2 (voters 2, 3) is what ziskemu proves. With
// occupied_before = 2, w = 0 and RefreshTarget(2,0,2) capped at
// occupied_before-w=2, batch 2 carries exactly two silent-refresh entries for
// voters 0 and 1. The returned struct populates preBatchResults /
// batchReencBallots / batchOverwrittenBallots so tests can recompute Results
// leaves that skip the refresh deltas.
func buildCheatInputTwoBatches(t *testing.T) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()

	election, err := NewElection(4)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	// Batch 1: voters 0, 1 (occupied_before=0 → target=0, no refresh).
	// Batch 2: voters 2, 3.
	base, election, results := buildCheatInputBatches(t, election, election.Voters[:2], election.Voters[2:4])
	if len(base.stateData.RefreshSmt) != 2 {
		t.Fatalf("expected 2 refresh entries for batch 2, got %d", len(base.stateData.RefreshSmt))
	}
	return base, election, results
}

// buildCheatInputBatches applies batch1Voters to the election state, then
// returns the full circuit input of the batch2Voters transition.
func buildCheatInputBatches(t *testing.T, election *Election, batch1Voters, batch2Voters []*Voter) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()
	return buildCheatInputBatchesHook(t, election, batch1Voters, batch2Voters, nil)
}

// buildCheatInputBatchesHook is buildCheatInputBatches with a hook that runs
// after batch 1 is applied (skipped when batch1Voters is empty) and before
// batch 2 is built, so a test can change how batch 2 is laid out. The
// eligibility block follows the election: CSP when it has a CSP key, the
// lean-IMT census otherwise.
func buildCheatInputBatchesHook(t *testing.T, election *Election, batch1Voters, batch2Voters []*Voter, between func()) (*cheatElectionInput, *Election, []*BallotResult) {
	t.Helper()

	if len(batch1Voters) > 0 {
		batch1, err := GenerateBallotBatch(election.ProcessID, election.EncKey, batch1Voters, 41)
		if err != nil {
			t.Fatalf("GenerateBallotBatch (batch 1): %v", err)
		}
		oldRoot1 := election.OldRoot
		_, reenc1, err := election.BuildReencBlock(oldRoot1, batch1.Results)
		if err != nil {
			t.Fatalf("BuildReencBlock (batch 1): %v", err)
		}
		if _, _, err := election.BuildStateBlock(batch1Voters, batch1.Results, reenc1); err != nil {
			t.Fatalf("BuildStateBlock (batch 1): %v", err)
		}
	}
	if between != nil {
		between()
	}

	batch2, err := GenerateBallotBatch(election.ProcessID, election.EncKey, batch2Voters, 42)
	if err != nil {
		t.Fatalf("GenerateBallotBatch (batch 2): %v", err)
	}

	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "verification_key.json"), ballotproof.CircomVerificationKey, 0600); err != nil {
		t.Fatalf("write vk: %v", err)
	}
	for i, res := range batch2.Results {
		idx := i + 1
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", idx)), res.ProofJSON, 0600); err != nil {
			t.Fatalf("write proof_%d: %v", idx, err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", idx)), res.SigJSON, 0600); err != nil {
			t.Fatalf("write sig_%d: %v", idx, err)
		}
	}
	genInputBin := findGenInputBin(t)
	outBin := filepath.Join(tmpDir, "input.bin")
	cmd := exec.Command(genInputBin, "--proofs-dir", tmpDir, "--output", outBin, "--nproofs", strconv.Itoa(len(batch2Voters)))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-input: %v\n%s", err, out)
	}
	baseBin, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatalf("read base bin: %v", err)
	}

	oldRoot2 := election.OldRoot
	reencData, reencBallots, err := election.BuildReencBlock(oldRoot2, batch2.Results)
	if err != nil {
		t.Fatalf("BuildReencBlock (batch 2): %v", err)
	}

	// Snapshot pre-batch-2 accumulator BEFORE BuildStateBlock mutates it.
	preBatchResults := election.Results

	stateData, overwrittenBallots, err := election.BuildStateBlock(batch2Voters, batch2.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock (batch 2): %v", err)
	}

	// KZG block last: reads DA cells stashed by BuildStateBlock.
	kzgBlock, _, err := election.BuildKZGBlock(oldRoot2)
	if err != nil {
		t.Fatalf("BuildKZGBlock (batch 2): %v", err)
	}
	stateBlockBytes, err := davinci.EncodeStateBlock(stateData)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	censusBlockBytes := eligibilityBlock(t, election, batch2Voters)
	reencBlockBytes, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}
	kzgBlockBytes, err := encodeKZGRequest(kzgBlock)
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}

	return &cheatElectionInput{
		baseBin:                 baseBin,
		stateData:               stateData,
		stateBlock:              stateBlockBytes,
		censusBlock:             censusBlockBytes,
		reencBlock:              reencBlockBytes,
		kzgBlock:                kzgBlockBytes,
		oldRoot:                 oldRoot2,
		preBatchResults:         preBatchResults,
		batchReencBallots:       reencBallots,
		batchOverwrittenBallots: overwrittenBallots,
	}, election, batch2.Results
}

// eligibilityBlock encodes the eligibility block for voters: the CSPBLK when
// the election has a CSP key, the CENSUS block otherwise. Both sit between
// STATETX and REENCBLK, so the bytes go in cheatElectionInput.censusBlock.
func eligibilityBlock(t *testing.T, e *Election, voters []*Voter) []byte {
	t.Helper()
	if e.CspKey != nil {
		csp, err := e.BuildCspData(voters)
		if err != nil {
			t.Fatalf("BuildCspData: %v", err)
		}
		b, err := davinci.EncodeCspBlock(csp)
		if err != nil {
			t.Fatalf("EncodeCspBlock: %v", err)
		}
		return b
	}
	proofs, err := e.BuildCensusProofs(voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	b, err := davinci.EncodeCensusBlock(proofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	return b
}

// reencodeState re-encodes base.stateData and reassembles the full circuit
// input. Small convenience so refresh tests don't repeat the concat dance.
func (c *cheatElectionInput) reencodeState(t *testing.T) []byte {
	t.Helper()
	sb, err := davinci.EncodeStateBlock(c.stateData)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	var out []byte
	out = append(out, c.baseBin...)
	out = append(out, sb...)
	out = append(out, c.censusBlock...)
	out = append(out, c.reencBlock...)
	out = append(out, c.kzgBlock...)
	return out
}

// TestCheatRefreshSanity: the two-batch fixture must be accepted, with
// OccupiedBefore echoed in register 42 as the true pre-batch count (2).
func TestCheatRefreshSanity(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	outputs, err := runZiskEmu(base.fullInput())
	if err != nil {
		t.Fatalf("ziskemu failed: %v", err)
	}
	if outputs[davinci.OutputOverallOk] != 1 {
		t.Fatalf("expected overall_ok=1, got %d; fail_mask=0x%08x",
			outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
	}
	if got := outputs[davinci.OutputOccupiedBefore]; got != 2 {
		t.Errorf("expected occupied_before register (%d) = 2, got %d",
			davinci.OutputOccupiedBefore, got)
	}
}

// TestCheatRefreshTooFew drops one refresh entry and its OLD ballot so
// n_refreshed < RefreshTarget(2,0,2)=2. The guest must reject with FAIL_REFRESH.
func TestCheatRefreshTooFew(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	base.stateData.RefreshSmt = base.stateData.RefreshSmt[:1]
	base.stateData.BallotProofs.RefreshedBallots = base.stateData.BallotProofs.RefreshedBallots[:1]
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_too_few")
}

// TestCheatRefreshOccupiedLie exercises the sequencer lying about
// OccupiedBefore. The guest computes target = RefreshTarget(n,w,claimed) and
// only enforces n_refreshed >= target, so claiming a lower value is a valid
// (but suspicious) transition — the consumer (fold guest / contract) is what
// must pin this value against its own view of running votes − overwrites.
func TestCheatRefreshOccupiedLie(t *testing.T) {
	t.Run("occupied_zero", func(t *testing.T) {
		base, _, _ := buildCheatInputTwoBatches(t)
		base.stateData.OccupiedBefore = 0 // target=0, we ship 2 refreshes: accepted
		outputs, err := runZiskEmu(base.reencodeState(t))
		if err != nil {
			t.Fatalf("ziskemu failed: %v", err)
		}
		if outputs[davinci.OutputOverallOk] != 1 {
			t.Fatalf("expected overall_ok=1 (extra refreshes are ok), got %d; fail_mask=0x%08x",
				outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
		}
		if got := outputs[davinci.OutputOccupiedBefore]; got != 0 {
			t.Errorf("expected occupied_before register = 0 (echoes the lie), got %d", got)
		}
	})
	t.Run("occupied_one", func(t *testing.T) {
		base, _, _ := buildCheatInputTwoBatches(t)
		base.stateData.OccupiedBefore = 1 // target=1, we ship 2 refreshes: accepted
		outputs, err := runZiskEmu(base.reencodeState(t))
		if err != nil {
			t.Fatalf("ziskemu failed: %v", err)
		}
		if outputs[davinci.OutputOverallOk] != 1 {
			t.Fatalf("expected overall_ok=1, got %d; fail_mask=0x%08x",
				outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
		}
		if got := outputs[davinci.OutputOccupiedBefore]; got != 1 {
			t.Errorf("expected occupied_before register = 1 (echoes the lie), got %d", got)
		}
	})
}

// TestCheatRefreshDuplicateKey collides two refresh entries onto the same
// ballot key. Duplicate (or non-strictly-increasing) keys must be rejected.
func TestCheatRefreshDuplicateKey(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	// Force entry 1 to reuse entry 0's key on both sides.
	base.stateData.RefreshSmt[1].OldKey = base.stateData.RefreshSmt[0].OldKey
	base.stateData.RefreshSmt[1].NewKey = base.stateData.RefreshSmt[0].NewKey
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_dup_key")
}

// TestCheatRefreshOverlapsBatch reuses a ballot key that the batch itself
// already touched, so the refresh set is not disjoint from the ballot set.
func TestCheatRefreshOverlapsBatch(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	if len(base.stateData.BallotSmt) == 0 {
		t.Skip("no ballot entries to collide with")
	}
	base.stateData.RefreshSmt[0].OldKey = base.stateData.BallotSmt[0].NewKey
	base.stateData.RefreshSmt[0].NewKey = base.stateData.BallotSmt[0].NewKey
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_overlaps_batch")
}

// TestCheatRefreshBadNamespace puts a refresh entry at key 0x04 (the Results
// namespace, not the ballot namespace >= 0x10). The guest must reject it.
func TestCheatRefreshBadNamespace(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	key04 := bigIntToFr32(new(big.Int).SetUint64(keyResults))
	base.stateData.RefreshSmt[0].OldKey = key04
	base.stateData.RefreshSmt[0].NewKey = key04
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_bad_namespace")
}

// TestCheatRefreshWrongScalar simulates a refresh built with a scalar chain
// that doesn't match the batch's seeded chain — the guest re-derives its own
// scalars, recomputes new_value = SHA-256(old + Enc(0; r_i)), and rejects a
// mismatch. We approximate this by hashing to something the guest won't
// derive; either way, the mismatch triggers FAIL_REFRESH.
func TestCheatRefreshWrongScalar(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	bogus := make([]byte, 32)
	for i := range bogus {
		bogus[i] = 0x5A
	}
	base.stateData.RefreshSmt[0].NewValue = "0x" + hex.EncodeToString(bogus)
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_wrong_scalar")
}

// TestCheatRefreshStaleOld swaps the first refreshed OLD ballot for a
// different (but well-formed) one, so SHA-256(refreshed_ballots[0]) no longer
// matches refresh_smt[0].old_value.
func TestCheatRefreshStaleOld(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	// All-identity padded ballot: a well-formed wideBallot value that won't
	// match the real (voted) old ballot's leaf hash.
	identity := make([]string, BallotFields)
	zeroHex := bigIntToFr32(big.NewInt(0))
	oneHex := bigIntToFr32(big.NewInt(1))
	for i := 0; i < NumFields; i++ {
		identity[i*4] = zeroHex
		identity[i*4+1] = oneHex
		identity[i*4+2] = zeroHex
		identity[i*4+3] = oneHex
	}
	base.stateData.BallotProofs.RefreshedBallots[0] = identity
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_stale_old")
}

// TestCheatRefreshSkipsAccumulator forges the net Results leaf to the value
// it would have if the refresh deltas were NOT folded in. The batch ballots
// and overwrites still contribute (so the leaf isn't wildly off), but the
// refresh (add(new) - sub(old)) is skipped. Guest must catch it via the
// accumulator recomputation.
func TestCheatRefreshSkipsAccumulator(t *testing.T) {
	base, election, _ := buildCheatInputTwoBatches(t)
	if base.stateData.ResultsSmt == nil {
		t.Fatal("expected a Results transition")
	}

	// Compute the "skipped" newResults: pre-batch + Σ reenc − Σ overwritten.
	wrongResults := base.preBatchResults
	for _, rb := range base.batchReencBallots {
		wrongResults = frAccumAdd(wrongResults, frAccumFromBallot(rb))
	}
	for _, ob := range base.batchOverwrittenBallots {
		wrongResults = frAccumSub(wrongResults, frAccumFromBallot(ob))
	}
	wrongLeaf := frAccumLeafHash(wrongResults)

	// The tree currently holds the CORRECT leaf at key 0x04. Downgrading it
	// gives us a hypothetical "post-batch tree with WRONG_LEAF" whose root
	// matches what a valid Results transition from the pre-Results state
	// would produce with WRONG_LEAF (key-layout unchanged ⇒ path unchanged).
	bLen := arbo.HashFunctionSha256.Len()
	keyBytes := arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(keyResults))
	if err := election.ProcTree.Update(keyBytes, arbo.BigIntToBytes(bLen, wrongLeaf)); err != nil {
		t.Fatalf("tree.Update(wrong leaf): %v", err)
	}
	newRootBytes, err := election.ProcTree.Root()
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	newRootHex := "0x" + hex.EncodeToString(pad32(newRootBytes))

	re := *base.stateData.ResultsSmt
	re.NewValue = "0x" + hex.EncodeToString(arbo.BigIntToBytes(bLen, wrongLeaf))
	re.NewRoot = newRootHex
	base.stateData.ResultsSmt = &re
	base.stateData.NewStateRoot = newRootHex

	assertCircuitFails(t, base.reencodeState(t), failResultAccum, "refresh_skips_accum")
}

// TestCheatRefreshNoop turns a refresh entry into a NOOP (fnc0=fnc1=0,
// new_root == old_root). The guest pins every refresh entry to be an UPDATE
// of an existing ballot slot; a NOOP must be rejected.
func TestCheatRefreshNoop(t *testing.T) {
	base, _, _ := buildCheatInputTwoBatches(t)
	// Also break the chained root so this can't accidentally slip past.
	base.stateData.RefreshSmt[0].Fnc0 = 0
	base.stateData.RefreshSmt[0].Fnc1 = 0
	base.stateData.RefreshSmt[0].NewRoot = base.stateData.RefreshSmt[0].OldRoot
	base.stateData.RefreshSmt[0].NewValue = base.stateData.RefreshSmt[0].OldValue
	assertCircuitFails(t, base.reencodeState(t), failRefresh, "refresh_noop")
}

// TestCheatResultsNoop replaces the net Results transition with a NOOP
// (fnc0=fnc1=0) that still carries the expected old/new leaf hashes, and
// leaves NewStateRoot at the root after the ballot chain. The votes land in
// the tree but the tally leaf never moves. The guest must pin the Results
// transition to an UPDATE of key 0x04 and reject this.
func TestCheatResultsNoop(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	sd := base.stateData
	if sd.ResultsSmt == nil {
		t.Fatal("expected a Results transition in the base input")
	}
	r := *sd.ResultsSmt
	r.NewRoot = r.OldRoot
	r.Fnc0, r.Fnc1 = 0, 0
	sd.ResultsSmt = &r
	sd.NewStateRoot = r.OldRoot

	stateBlock, err := davinci.EncodeStateBlock(sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	tampered := append(append(base.baseBin, stateBlock...), base.censusBlock...)
	tampered = append(tampered, base.reencBlock...)
	tampered = append(tampered, base.kzgBlock...)
	assertCircuitFails(t, tampered, failSMTResults, "results_noop")
}
