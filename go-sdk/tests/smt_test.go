package tests

// TestSMTTransition verifies that an Arbo SHA-256 SMT state-transition is
// correctly validated by the davinci-zkvm circuit.
//
// The test builds a real arbo tree, performs an insert transition, and
// submits a full ProveRequest (128 Groth16 ballot proofs + 128 ECDSA sigs +
// 1 SMT transition) to the running service.  The job must complete successfully
// (indicating output[0]=1, which implies output[9]=1).
//
// TestSMTEmulator exercises the same logic but calls ziskemu directly
// (no service required), using the pre-generated input.bin + appended SMT block.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

const smtLevels = 256 // 32-byte keys need maxLevels≥256 (ceil(256/8)=32)

// TestSMTInsertTransition submits a ProveRequest that includes a valid SMT
// insert transition.  The job must complete successfully.
func TestSMTInsertTransition(t *testing.T) {
	// Load the 128 ballot proofs + ECDSA signatures.
	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	// Build an arbo SHA-256 tree and insert 5 initial leaves.
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    smtLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}
	bLen := arbo.HashFunctionSha256.Len() // 32

	for i := int64(1); i <= 5; i++ {
		k := arbo.BigIntToBytes(bLen, big.NewInt(i))
		v := arbo.BigIntToBytes(bLen, big.NewInt(i*10))
		if err := tree.Add(k, v); err != nil {
			t.Fatalf("tree.Add(%d): %v", i, err)
		}
	}

	// Build insert entry for key=42 using the correct helper.
	smtEntry, err := buildArboInsertEntry(tree, big.NewInt(42), big.NewInt(420), smtLevels)
	if err != nil {
		t.Fatalf("buildArboInsertEntry: %v", err)
	}

	// Attach SMT entry to the ProveRequest.
	req.Smt = []davinci.SmtEntry{smtEntry}

	t.Logf("SMT insert: old_root=%s → new_root=%s", smtEntry.OldRoot[:10], smtEntry.NewRoot[:10])
	t.Logf("  new_key=%s  is_old0=%d", smtEntry.NewKey[:10], smtEntry.IsOld0)

	// Submit to the service and wait for completion.
	client := davinci.NewClient(apiURL)
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("SubmitProve: %v", err)
	}
	t.Logf("Queued job %s (with SMT transition)", jobID)

	proof, err := client.WaitForJob(jobID, 0)
	if err != nil {
		t.Fatalf("WaitForJob %s: %v", jobID, err)
	}
	t.Logf("Job %s done (status: %s)", jobID, proof.Status)
}

// TestSMTUpdateTransition verifies that an SMT update (replace value for
// existing key) is correctly validated.
func TestSMTUpdateTransition(t *testing.T) {
	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    smtLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}

	// Insert the key we'll later update.
	keyBI := big.NewInt(7)
	keyBytes := arbo.BigIntToBytes(bLen, keyBI)
	oldValueBytes := arbo.BigIntToBytes(bLen, big.NewInt(70))
	if err := tree.Add(keyBytes, oldValueBytes); err != nil {
		t.Fatalf("tree.Add: %v", err)
	}
	// Add a few more leaves for a non-trivial tree.
	for _, i := range []int64{1, 2, 3} {
		k := arbo.BigIntToBytes(bLen, big.NewInt(i))
		v := arbo.BigIntToBytes(bLen, big.NewInt(i*100))
		if err := tree.Add(k, v); err != nil {
			t.Fatalf("tree.Add(%d): %v", i, err)
		}
	}

	oldRootBytes, err := tree.Root()
	if err != nil {
		t.Fatalf("tree.Root (old): %v", err)
	}

	// Get proof of the existing key before update.
	_, _, packedSiblings, exists, err := tree.GenProof(keyBytes)
	if err != nil {
		t.Fatalf("GenProof: %v", err)
	}
	if !exists {
		t.Fatal("key not found (should exist)")
	}

	newValueBytes := arbo.BigIntToBytes(bLen, big.NewInt(700))
	if err := tree.Update(keyBytes, newValueBytes); err != nil {
		t.Fatalf("tree.Update: %v", err)
	}

	newRootBytes, err := tree.Root()
	if err != nil {
		t.Fatalf("tree.Root (new): %v", err)
	}

	// For update: fnc0=0, fnc1=1, is_old0=0.
	// No sibling removal (fnc1=1 → not an insert).
	siblingsUnpacked, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSiblings)
	if err != nil {
		t.Fatalf("UnpackSiblings: %v", err)
	}
	zero32 := make([]byte, bLen)
	for len(siblingsUnpacked) < smtLevels {
		siblingsUnpacked = append(siblingsUnpacked, zero32)
	}
	siblingsUnpacked = siblingsUnpacked[:smtLevels]

	smtEntry := davinci.SmtEntry{
		OldRoot:  "0x" + hex.EncodeToString(pad32(oldRootBytes)),
		NewRoot:  "0x" + hex.EncodeToString(pad32(newRootBytes)),
		OldKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
		OldValue: "0x" + hex.EncodeToString(pad32(oldValueBytes)),
		IsOld0:   0,
		NewKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
		NewValue: "0x" + hex.EncodeToString(pad32(newValueBytes)),
		Fnc0:     0, // update
		Fnc1:     1,
		Siblings: make([]string, smtLevels),
	}
	for i, s := range siblingsUnpacked {
		smtEntry.Siblings[i] = "0x" + hex.EncodeToString(pad32(s))
	}

	req.Smt = []davinci.SmtEntry{smtEntry}

	t.Logf("SMT update: old_root=%s → new_root=%s", smtEntry.OldRoot[:10], smtEntry.NewRoot[:10])

	client := davinci.NewClient(apiURL)
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("SubmitProve: %v", err)
	}
	t.Logf("Queued job %s (SMT update)", jobID)

	proof, err := client.WaitForJob(jobID, 0)
	if err != nil {
		t.Fatalf("WaitForJob %s: %v", jobID, err)
	}
	t.Logf("Job %s done (status: %s)", jobID, proof.Status)
}

// pad32 zero-pads a byte slice to exactly 32 bytes (big-endian convention).
func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	if len(b) > 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// smtMagic is "SMTBLK!!" encoded as little-endian uint64.
var smtMagic = []byte("SMTBLK!!")

// leHex32ToFrLE converts a 0x-prefixed little-endian hex string to a [u64;4]
// little-endian word array stored as 32 bytes (4 × LE uint64).
// Arbo stores all values (keys, values, hashes) in little-endian byte order,
// so the hex bytes map directly to LE words without any byte reversal.
func leHex32ToFrLE(s string) ([32]byte, error) {
	hex32 := strings.TrimPrefix(s, "0x")
	if len(hex32) < 64 {
		hex32 = hex32 + strings.Repeat("0", 64-len(hex32))
	}
	leBuf, err := hex.DecodeString(hex32)
	if err != nil {
		return [32]byte{}, err
	}
	var out [32]byte
	copy(out[:], leBuf)
	return out, nil
}

// writeFrLE writes a 0x-prefixed hex32 field as [u64;4] LE to buf.
func writeFrLE(buf *[]byte, s string) error {
	v, err := leHex32ToFrLE(s)
	if err != nil {
		return fmt.Errorf("leHex32ToFrLE(%q): %w", s, err)
	}
	*buf = append(*buf, v[:]...)
	return nil
}

// writeU64LE writes a uint64 in little-endian to buf.
func writeU64LE(buf *[]byte, v uint64) {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	*buf = append(*buf, b[:]...)
}

// encodeSMTBlock encodes a slice of SmtEntry into the SMT binary block format.
func encodeSMTBlock(entries []davinci.SmtEntry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	nLevels := len(entries[0].Siblings)
	var buf []byte
	buf = append(buf, smtMagic...)
	writeU64LE(&buf, uint64(len(entries)))
	writeU64LE(&buf, uint64(nLevels))
	for _, e := range entries {
		if err := writeFrLE(&buf, e.OldRoot); err != nil {
			return nil, err
		}
		if err := writeFrLE(&buf, e.NewRoot); err != nil {
			return nil, err
		}
		if err := writeFrLE(&buf, e.OldKey); err != nil {
			return nil, err
		}
		if err := writeFrLE(&buf, e.OldValue); err != nil {
			return nil, err
		}
		writeU64LE(&buf, uint64(e.IsOld0))
		if err := writeFrLE(&buf, e.NewKey); err != nil {
			return nil, err
		}
		if err := writeFrLE(&buf, e.NewValue); err != nil {
			return nil, err
		}
		writeU64LE(&buf, uint64(e.Fnc0))
		writeU64LE(&buf, uint64(e.Fnc1))
		if len(e.Siblings) != nLevels {
			return nil, fmt.Errorf("inconsistent sibling count: %d vs %d", len(e.Siblings), nLevels)
		}
		for _, sib := range e.Siblings {
			if err := writeFrLE(&buf, sib); err != nil {
				return nil, err
			}
		}
	}
	return buf, nil
}

// buildArboInsertEntry creates an SMT insert assignment using arbo SHA-256.
// Caller provides the tree and the new (key, value) to insert.
// Returns a SmtEntry ready for use with the circuit, and modifies the tree.
//
// Algorithm (matches wrapper_arbo.go semantics, with correct displaced-leaf detection):
//  1. GenProof(newKey) BEFORE insertion — detect displaced leaf — set IsOld0/OldKey/OldValue
//  2. Record OldRoot
//  3. tree.Add(newKey, newValue)
//  4. Record NewRoot
//  5. GenProof(newKey) AFTER insertion — get siblings for the updated tree
//  6. If IsOld0==false && fnc1==false (insert with displaced leaf): remove last sibling
//  7. Pad siblings to `levels`
func buildArboInsertEntry(tree *arbo.Tree, newKeyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	newKeyBytes := arbo.BigIntToBytes(bLen, newKeyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	// Step 1: GenProof BEFORE insertion to detect a displaced (existing) leaf.
	// arbo returns the first leaf found on the path (may be a different key).
	oldLeafKey, oldLeafValue, _, exists, err := tree.GenProof(newKeyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof before: %w", err)
	}
	if exists {
		return davinci.SmtEntry{}, fmt.Errorf("key %s already exists in tree", newKeyBI)
	}

	// isOld0=true  → new key goes into a truly empty slot
	// isOld0=false → a different leaf exists at this path and will be displaced
	isOld0 := len(oldLeafKey) == 0
	if isOld0 {
		oldLeafKey = make([]byte, bLen)
		oldLeafValue = make([]byte, bLen)
	}

	// Step 2: Record OldRoot (before insertion).
	oldRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (old): %w", err)
	}

	// Step 3: Insert the new leaf.
	if err := tree.Add(newKeyBytes, newValueBytes); err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Add: %w", err)
	}

	// Step 4: Record NewRoot (after insertion).
	newRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (new): %w", err)
	}

	// Step 5: GenProof AFTER insertion — siblings from the updated tree.
	// This matches wrapper_arbo.go which calls GenProofWithTx after the operation.
	_, _, packedSiblingsAfter, existsAfter, err := tree.GenProof(newKeyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof after: %w", err)
	}
	if !existsAfter {
		return davinci.SmtEntry{}, fmt.Errorf("new key not found after insertion")
	}

	siblingsUnpacked, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSiblingsAfter)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("UnpackSiblings: %w", err)
	}

	// Step 6: remove last sibling when IsOld0=false and fnc1=false (insert).
	// The displaced leaf hash is the last sibling; the circuit uses hash1Old directly.
	if !isOld0 && len(siblingsUnpacked) > 0 {
		siblingsUnpacked = siblingsUnpacked[:len(siblingsUnpacked)-1]
	}

	// Step 7: Pad to exactly `levels` entries with zero.
	zero32 := make([]byte, bLen)
	for len(siblingsUnpacked) < levels {
		siblingsUnpacked = append(siblingsUnpacked, zero32)
	}
	siblingsUnpacked = siblingsUnpacked[:levels]

	entry := davinci.SmtEntry{
		OldRoot:  "0x" + hex.EncodeToString(pad32(oldRootBytes)),
		NewRoot:  "0x" + hex.EncodeToString(pad32(newRootBytes)),
		OldKey:   "0x" + hex.EncodeToString(pad32(oldLeafKey)),
		OldValue: "0x" + hex.EncodeToString(pad32(oldLeafValue)),
		NewKey:   "0x" + hex.EncodeToString(pad32(newKeyBytes)),
		NewValue: "0x" + hex.EncodeToString(pad32(newValueBytes)),
		Fnc0:     1,
		Fnc1:     0,
		Siblings: make([]string, levels),
	}
	if isOld0 {
		entry.IsOld0 = 1
	}
	for i, s := range siblingsUnpacked {
		entry.Siblings[i] = "0x" + hex.EncodeToString(pad32(s))
	}
	return entry, nil
}

// TestSMTEmulator tests the SMT verifier by calling ziskemu directly (no service needed).
// It reads the pre-generated input.bin, appends an SMT block built from arbo, and
// verifies that ziskemu outputs output[9]=1.
func TestSMTEmulator(t *testing.T) {
	// Locate the pre-generated base binary input.
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
	}

	// Build an SMT transition using arbo SHA-256.
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    smtLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}
	bLen := arbo.HashFunctionSha256.Len()

	// Seed the tree with some initial leaves.
	for i := int64(1); i <= 5; i++ {
		k := arbo.BigIntToBytes(bLen, big.NewInt(i))
		v := arbo.BigIntToBytes(bLen, big.NewInt(i*100))
		if err := tree.Add(k, v); err != nil {
			t.Fatalf("seed tree.Add(%d): %v", i, err)
		}
	}

	// Build insert entry for key=99.
	entry, err := buildArboInsertEntry(tree, big.NewInt(99), big.NewInt(990), smtLevels)
	if err != nil {
		t.Fatalf("buildArboInsertEntry: %v", err)
	}
	t.Logf("SMT entry: old_root=%s... new_root=%s... is_old0=%d",
		entry.OldRoot[:10], entry.NewRoot[:10], entry.IsOld0)

	// Encode SMT block and append to base binary.
	smtBlock, err := encodeSMTBlock([]davinci.SmtEntry{entry})
	if err != nil {
		t.Fatalf("encodeSMTBlock: %v", err)
	}

	baseBin, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	combinedBin := append(baseBin, smtBlock...)
	tmpFile := filepath.Join(t.TempDir(), "input_smt.bin")
	if err := os.WriteFile(tmpFile, combinedBin, 0644); err != nil {
		t.Fatalf("write tmp bin: %v", err)
	}
	t.Logf("Combined input: %d bytes (%d base + %d SMT)", len(combinedBin), len(baseBin), len(smtBlock))

	// Find the circuit ELF relative to the test.
	elfPath := filepath.Join(dataDir, "..", "..", "circuit", "elf", "circuit.elf")
	if _, err := os.Stat(elfPath); err != nil {
		// Try absolute path based on test file location.
		elfPath = "/home/p4u/davinci-zkvm/circuit/elf/circuit.elf"
	}

	// Run ziskemu.
	ziskemu, err := exec.LookPath("ziskemu")
	if err != nil {
		t.Skipf("ziskemu not in PATH: %v", err)
	}

	cmd := exec.Command(ziskemu, "-e", elfPath, "-i", tmpFile)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("ziskemu: %v\nstdout: %s", err, out)
	}

	// Parse outputs: each line is a hex u32.
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	t.Logf("ziskemu outputs: %v", lines)

	get := func(i int) uint32 {
		if i >= len(lines) {
			return 0
		}
		var v uint32
		fmt.Sscanf(strings.TrimSpace(lines[i]), "%x", &v)
		return v
	}

	if get(0) != 1 {
		t.Errorf("output[0] (overall_ok) = %d, want 1", get(0))
	}
	if get(1) != 0 {
		t.Errorf("output[1] (fail_mask) = 0x%x, want 0", get(1))
	}
	if get(7) != 1 {
		t.Errorf("output[7] (groth16_ok) = %d, want 1", get(7))
	}
	if get(8) != 1 {
		t.Errorf("output[8] (ecdsa_ok) = %d, want 1", get(8))
	}
	if get(9) != 1 {
		t.Errorf("output[9] (smt_ok) = %d, want 1", get(9))
	}
}
