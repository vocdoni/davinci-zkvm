package tests

// This file provides shared helpers for SMT operations and the ziskemu emulator
// used by statetransition_test.go and other circuit-level tests.

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strings"

	arbo "github.com/vocdoni/arbo"
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
