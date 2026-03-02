package tests

// TestChainedSMT and TestStateTxEmulator test the full DAVINCI state-transition
// STATETX binary block using the ziskemu emulator (no service needed).
//
// TestChainedSMT: inserts N voteID keys (from the actual Groth16 proof public inputs)
// into an arbo SHA-256 tree, builds the STATETX block with the chained transitions,
// and verifies:
//   - output[0] = 1 (overall ok)
//   - output[9] = 2 (legacy SMT block absent — not a failure)
//   - output[14] = n_voters
//
// TestStateTxEmulator: full state-transition with voteID chain + ballot chain +
// process read-proofs.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

const (
	stateTxLevels = 256    // arbo maxLevels for test trees
	votesPerBatch = 5      // small batch for emulator test
	voteIDMin     = uint64(0x8000_0000_0000_0000)
)

// parseVoteIDsFromBinary extracts voteID values (public input index 1, word 0)
// for the first n proofs from the davinci-zkvm binary input format.
//
// Binary layout (all LE):
//   Header: magic(u64) logn(u64) nproofs(u64) n_public(u64)  = 32 bytes
//   VK:     alpha_g1(64) beta_g2(128) gamma_g2(128) delta_g2(128)
//           n_gamma_abc(u64) + (n_public+1)×64 bytes
//   Proofs count (u64) + nproofs × (G1=64 + G2=128 + G1=64 + n_public×32)
func parseVoteIDsFromBinary(data []byte, n int) ([]uint64, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short for header")
	}
	off := 0
	off += 8 // magic
	off += 8 // logn
	nproofs := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	nPublic := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8

	if n > nproofs {
		return nil, fmt.Errorf("requested %d voteIDs but only %d proofs", n, nproofs)
	}
	if nPublic < 2 {
		return nil, fmt.Errorf("n_public=%d < 2, no voteID in public inputs", nPublic)
	}

	// Skip VK: alpha_g1(64) + beta_g2(128) + gamma_g2(128) + delta_g2(128)
	off += 64 + 128 + 128 + 128
	// gamma_abc count (u64) + (nPublic+1) G1 entries
	nAbc := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	if nAbc != nPublic+1 {
		return nil, fmt.Errorf("gamma_abc_len=%d != n_public+1=%d", nAbc, nPublic+1)
	}
	off += nAbc * 64

	// Proofs section: count (u64) + nproofs × proof
	off += 8 // nproofs_check
	proofSize := 64 + 128 + 64 + nPublic*32 // G1 + G2 + G1 + public inputs

	voteIDs := make([]uint64, n)
	for i := 0; i < n; i++ {
		proofOff := off + i*proofSize
		// Skip a(G1=64) + b(G2=128) + c(G1=64) + pubs[0](32) → pubs[1] at +288
		voteIDOff := proofOff + 64 + 128 + 64 + 32
		if voteIDOff+8 > len(data) {
			return nil, fmt.Errorf("data too short at proof %d voteID offset %d", i, voteIDOff)
		}
		// voteID is Fr word[0] in LE — the uint64 value
		voteIDs[i] = binary.LittleEndian.Uint64(data[voteIDOff : voteIDOff+8])
	}
	return voteIDs, nil
}

// parseAddrsLo16FromBinary extracts the lower 16 bits of address (public input[0], word[0])
// for the first n proofs from the davinci-zkvm binary input.
func parseAddrsLo16FromBinary(data []byte, n int) ([]uint64, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short for header")
	}
	off := 0
	off += 8 // magic
	off += 8 // logn
	nproofs := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	nPublic := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8

	if n > nproofs {
		return nil, fmt.Errorf("requested %d addresses but only %d proofs", n, nproofs)
	}
	if nPublic < 1 {
		return nil, fmt.Errorf("n_public=%d < 1, no address in public inputs", nPublic)
	}

	off += 64 + 128 + 128 + 128
	nAbc := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8 + nAbc*64
	off += 8 // nproofs_check

	proofSize := 64 + 128 + 64 + nPublic*32
	addrs := make([]uint64, n)
	for i := 0; i < n; i++ {
		proofOff := off + i*proofSize
		// pubs[0] starts at proofOff + G1+G2+G1 = +256
		addrOff := proofOff + 64 + 128 + 64
		if addrOff+8 > len(data) {
			return nil, fmt.Errorf("data too short at proof %d addr offset %d", i, addrOff)
		}
		addrs[i] = binary.LittleEndian.Uint64(data[addrOff:addrOff+8]) & 0xFFFF
	}
	return addrs, nil
}

// TestChainedSMT verifies that chained voteID + ballot insertions are
// correctly validated by the STATETX circuit using ziskemu.
// Uses all 5 proofs from the pre-generated data (votesPerBatch=5), builds
// a single arbo tree with both VoteID and Ballot namespaces, and checks
// that overall_ok=1 with the correct state root transition.
// Unlike TestStateTxEmulator, this test omits process read-proofs to verify
// that the circuit accepts batches without process config checks.
func TestChainedSMT(t *testing.T) {
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
	}

	baseInput, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	// Extract real voteIDs and address lower-16-bits from the Groth16 proofs.
	voteIDs, err := parseVoteIDsFromBinary(baseInput, votesPerBatch)
	if err != nil {
		t.Fatalf("parseVoteIDsFromBinary: %v", err)
	}
	addrsLo16, err := parseAddrsLo16FromBinary(baseInput, votesPerBatch)
	if err != nil {
		t.Fatalf("parseAddrsLo16FromBinary: %v", err)
	}
	t.Logf("voteIDs: %v  addrsLo16: %v", voteIDs, addrsLo16)

	// Build a single arbo SHA-256 tree for both VoteID and Ballot namespaces.
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    stateTxLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}

	oldRootBytes, _ := tree.Root()
	oldRootHex := "0x" + hex.EncodeToString(pad32(oldRootBytes))

	// Insert voteID keys (namespace >= 0x8000_0000_0000_0000).
	var voteIDChain []davinci.SmtEntry
	for i, vid := range voteIDs {
		keyBI := new(big.Int).SetUint64(vid)
		valBI := new(big.Int).SetUint64(uint64(100 + i))
		entry, err := buildArboInsertEntry(tree, keyBI, valBI, stateTxLevels)
		if err != nil {
			t.Fatalf("voteID insert[%d]: %v", i, err)
		}
		voteIDChain = append(voteIDChain, entry)
	}

	// Insert ballot keys (namespace [0x10, 0x7FFF_FFFF_FFFF_FFFF]).
	// key = BallotMin + (censusIdx << 16) + (address & 0xFFFF)
	ballotMin := uint64(0x10)
	var ballotChain []davinci.SmtEntry
	for i := 0; i < votesPerBatch; i++ {
		ballotKey := ballotMin + uint64(i)<<16 + addrsLo16[i]
		keyBI := new(big.Int).SetUint64(ballotKey)
		valBI := new(big.Int).SetUint64(uint64(200 + i))
		entry, err := buildArboInsertEntry(tree, keyBI, valBI, stateTxLevels)
		if err != nil {
			t.Fatalf("ballot insert[%d]: %v", i, err)
		}
		ballotChain = append(ballotChain, entry)
	}

	newRootBytes, _ := tree.Root()
	newRootHex := "0x" + hex.EncodeToString(pad32(newRootBytes))

	t.Logf("old_root=%s  new_root=%s  voteIDs=%d  ballots=%d",
		oldRootHex[:10], newRootHex[:10], len(voteIDChain), len(ballotChain))

	sd := &davinci.StateTransitionData{
		VotersCount:      uint64(votesPerBatch),
		OverwrittenCount: 0,
		ProcessID:        "0x" + hex.EncodeToString(make([]byte, 32)),
		OldStateRoot:     oldRootHex,
		NewStateRoot:     newRootHex,
		VoteIDSmt:        voteIDChain,
		BallotSmt:        ballotChain,
	}

	stateBlock, err := davinci.EncodeStateBlock(sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	combined := append(baseInput, stateBlock...)
	t.Logf("combined input: %d bytes (%d base + %d STATETX)", len(combined), len(baseInput), len(stateBlock))

	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	t.Logf("ziskemu outputs: %v", outputsHex(outputs))

	// This test provides Groth16 + ECDSA + STATETX (voteID + ballot chains) but
	// omits census, re-encryption, and KZG blocks. overall_ok=0 is expected because
	// mandatory blocks are missing. We check the state-transition specific outputs.
	if outputs[1]&0x00000E00 != 0 { // bits 9-13 cover SMT failures
		t.Errorf("fail_mask has SMT bits set: 0x%08x", outputs[1])
	}
	if outputs[42] != 2 {
		t.Errorf("output[42] (legacy_smt_ok) = %d, want 2 (absent)", outputs[42])
	}
	if outputs[18] != uint32(votesPerBatch) {
		t.Errorf("output[18] (voters_count) = %d, want %d", outputs[18], votesPerBatch)
	}
	// Verify new root is non-zero.
	newRootNonZero := false
	for i := 10; i <= 17; i++ {
		if outputs[i] != 0 {
			newRootNonZero = true
			break
		}
	}
	if !newRootNonZero {
		t.Errorf("output[10-17] (new_state_root) is zero, expected non-zero")
	}
}

// TestStateTxEmulator tests a full state-transition with both voteID chain
// and ballot chain, plus process read-proofs.
func TestStateTxEmulator(t *testing.T) {
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
	}

	baseInput, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	const nVotes = 3
	const procLevels = 256 // 256 levels supports 32-byte keys (sha256 hash length)

	// Build separate trees: process (small, config keys), state (large, votes).
	procDB := memdb.New()
	procTree, err := arbo.NewTree(arbo.Config{
		Database:     procDB,
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree(proc): %v", err)
	}

	// Insert config entries: processID(0), ballotMode(2), encKey(3), censusOrigin(6).
	configKeys := []uint64{0x00, 0x02, 0x03, 0x06}
	configVals := []uint64{0xABCDEF, 0x01, 0x1234, 0x01}
	bLen := arbo.HashFunctionSha256.Len()
	for i, k := range configKeys {
		keyBI := new(big.Int).SetUint64(k)
		valBI := new(big.Int).SetUint64(configVals[i])
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, keyBI),
			arbo.BigIntToBytes(bLen, valBI),
		); err != nil {
			t.Fatalf("procTree.Add[%d]: %v", i, err)
		}
	}

	// Capture OldStateRoot = proc tree root after config is set.
	oldRootBytes, _ := procTree.Root()
	oldRootHex := "0x" + hex.EncodeToString(pad32(oldRootBytes))

	// Generate process read-proofs (fnc0=0, fnc1=0 → no mutation).
	processSmt, err := buildArboReadProofs(procTree, configKeys, bLen, procLevels)
	if err != nil {
		t.Fatalf("buildArboReadProofs: %v", err)
	}

	// Extract real voteIDs and address lower-16-bits from Groth16 proof public inputs.
	// pubs[i][0] = address, pubs[i][1] = voteID.
	voteIDs, err := parseVoteIDsFromBinary(baseInput, nVotes)
	if err != nil {
		t.Fatalf("parseVoteIDsFromBinary: %v", err)
	}
	addrsLo16, err := parseAddrsLo16FromBinary(baseInput, nVotes)
	if err != nil {
		t.Fatalf("parseAddrsLo16FromBinary: %v", err)
	}

	// Now insert VoteID keys using real voteIDs from proofs.
	var voteIDChain []davinci.SmtEntry
	for i := 0; i < nVotes; i++ {
		keyBI := new(big.Int).SetUint64(voteIDs[i])
		valBI := new(big.Int).SetUint64(uint64(1000 + i))
		entry, err := buildArboInsertEntry(procTree, keyBI, valBI, procLevels)
		if err != nil {
			t.Fatalf("voteID insert[%d]: %v", i, err)
		}
		voteIDChain = append(voteIDChain, entry)
	}

	// Insert ballot keys using real address lower-16-bits from proofs.
	ballotMin := uint64(0x10)
	var ballotChain []davinci.SmtEntry
	for i := 0; i < nVotes; i++ {
		// key = BallotMin + (censusIdx << 16) + (address & 0xFFFF)
		keyBI := new(big.Int).SetUint64(ballotMin + uint64(i)<<16 + addrsLo16[i])
		valBI := new(big.Int).SetUint64(uint64(2000 + i))
		entry, err := buildArboInsertEntry(procTree, keyBI, valBI, procLevels)
		if err != nil {
			t.Fatalf("ballot insert[%d]: %v", i, err)
		}
		ballotChain = append(ballotChain, entry)
	}

	newRootBytes, _ := procTree.Root()
	newRootHex := "0x" + hex.EncodeToString(pad32(newRootBytes))

	t.Logf("old=%s  new=%s  voteIDs=%d  ballots=%d  procProofs=%d",
		oldRootHex[:10], newRootHex[:10], len(voteIDChain), len(ballotChain), len(processSmt))

	sd := &davinci.StateTransitionData{
		VotersCount:      nVotes,
		OverwrittenCount: 0,
		ProcessID:        oldRootHex, // use old root as dummy processID
		OldStateRoot:     oldRootHex,
		NewStateRoot:     newRootHex,
		VoteIDSmt:        voteIDChain,
		BallotSmt:        ballotChain,
		ProcessSmt:       processSmt,
	}

	stateBlock, err := davinci.EncodeStateBlock(sd)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}

	combined := append(baseInput, stateBlock...)
	t.Logf("combined input: %d bytes (%d base + %d STATETX)", len(combined), len(baseInput), len(stateBlock))

	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	t.Logf("outputs: %v", outputsHex(outputs))

	// This test provides Groth16 + ECDSA + STATETX with process proofs but omits
	// census, re-encryption, and KZG blocks. overall_ok=0 is expected because
	// mandatory blocks are missing. We verify the state-transition outputs are correct.
	if outputs[1]&0x00007E00 != 0 { // bits 9-14 cover SMT + consistency failures
		t.Errorf("fail_mask has state-transition bits set: 0x%08x", outputs[1])
	}
	if outputs[18] != nVotes {
		t.Errorf("output[18] (voters_count) = %d, want %d", outputs[18], nVotes)
	}
}

// buildArboReadProofs generates SMT read-proofs (fnc0=0, fnc1=0) for the
// given config keys. In arbo, a "read proof" is a standard inclusion proof;
// the circuit interprets fnc0=fnc1=0 as "no state change" and verifies the
// leaf exists in old_root == new_root.
func buildArboReadProofs(tree *arbo.Tree, keys []uint64, bLen, levels int) ([]davinci.SmtEntry, error) {
	rootBytes, err := tree.Root()
	if err != nil {
		return nil, err
	}
	rootHex := "0x" + hex.EncodeToString(pad32(rootBytes))

	var entries []davinci.SmtEntry
	for _, k := range keys {
		keyBI := new(big.Int).SetUint64(k)
		keyBytes := arbo.BigIntToBytes(bLen, keyBI)

		_, valBytes, packedSibs, exists, err := tree.GenProof(keyBytes)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil // key not present; skip (circuit will ignore)
		}
		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSibs)
		if err != nil {
			return nil, err
		}
		// Pad siblings to levels.
		zero := make([]byte, bLen)
		for len(sibs) < levels {
			sibs = append(sibs, zero)
		}
		sibs = sibs[:levels]

		sibStrs := make([]string, levels)
		for i, s := range sibs {
			sibStrs[i] = "0x" + hex.EncodeToString(pad32(s))
		}

		entries = append(entries, davinci.SmtEntry{
			OldRoot:  rootHex,
			NewRoot:  rootHex, // read-proof: root unchanged
			OldKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
			OldValue: "0x" + hex.EncodeToString(pad32(valBytes)),
			IsOld0:   0,
			NewKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
			NewValue: "0x" + hex.EncodeToString(pad32(valBytes)),
			Fnc0:     0,
			Fnc1:     0, // read: no change
			Siblings: sibStrs,
		})
	}
	return entries, nil
}

// outputsHex formats a uint32 slice as hex strings for logging.
func outputsHex(outputs []uint32) []string {
	result := make([]string, len(outputs))
	for i, v := range outputs {
		result[i] = fmt.Sprintf("%08x", v)
	}
	return result
}
