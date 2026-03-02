package tests

// TestSMTEmulator exercises the SMT circuit using ziskemu directly
// (no API service required). It builds an arbo SHA-256 SMT state-transition,
// encodes the SMTBLK binary block, appends it to the pre-generated input.bin,
// and runs ziskemu to verify output[0]=1.
//
// TestSMTEmulator: reads the pre-generated input.bin + appended SMT block,
// calls ziskemu directly.

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

	// This test only provides Groth16 + ECDSA + legacy SMTBLK, without census,
	// re-encryption, or KZG blocks. overall_ok=0 is expected because mandatory
	// blocks are missing. We verify the components that ARE present passed.
	if get(40) != 1 {
		t.Errorf("output[40] (groth16_ok) = %d, want 1", get(40))
	}
	if get(41) != 1 {
		t.Errorf("output[41] (ecdsa_ok) = %d, want 1", get(41))
	}
	if get(42) != 1 {
		t.Errorf("output[42] (smt_ok) = %d, want 1", get(42))
	}
	if get(42) != 1 {
		t.Errorf("output[42] (smt_ok) = %d, want 1", get(42))
	}
}

// runZiskEmu writes input bytes to a temp file, executes ziskemu, and returns
// parsed uint32 outputs. Returns an error if ziskemu is not in PATH or fails.
func runZiskEmu(inputBytes []byte) ([]uint32, error) {
	ziskemuBin, err := exec.LookPath("ziskemu")
	if err != nil {
		return nil, fmt.Errorf("ziskemu not in PATH: %w", err)
	}
	elfPath := os.Getenv("CIRCUIT_ELF_PATH")
	if elfPath == "" {
		elfPath = "/home/p4u/davinci-zkvm/circuit/elf/circuit.elf"
	}
	tmp, err := os.CreateTemp("", "statetx-*.bin")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(inputBytes); err != nil {
		return nil, err
	}
	tmp.Close()

	cmd := exec.Command(ziskemuBin, "-e", elfPath, "-i", tmp.Name())
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ziskemu failed: %w\noutput: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var outputs []uint32
	for _, l := range lines {
		var v uint32
		fmt.Sscanf(strings.TrimSpace(l), "%x", &v)
		outputs = append(outputs, v)
	}
	return outputs, nil
}
