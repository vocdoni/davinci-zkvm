package tests

// TestKZGBarycentric tests the KZG barycentric evaluation block in the ZisK circuit.
//
// The circuit verifies Y = P(Z) where:
//   - P is the polynomial interpolating the EIP-4844 blob data
//   - Z = SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48) mod BLS12-381 Fr
//   - Y is the claimed evaluation result P(Z)
//
// We use SHA-2 (not Poseidon) for Z derivation — it is hardware-accelerated on ZisK.

import (
	"crypto/sha256"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/vocdoni/davinci-node/crypto/blobs"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// computeKZGZ derives the KZG evaluation point using the same algorithm as the Rust circuit:
//
//	Z = SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48)
//
// The 32-byte hash is returned as a *big.Int (big-endian). The Rust circuit reduces this
// mod BLS12-381 Fr via `from_be_bytes_mod_order`. We pass the big.Int directly to
// EvaluateBarycentricNative which performs the same reduction internally.
func computeKZGZ(processID, rootHashBefore []byte, commitment [48]byte) *big.Int {
	var preimage [112]byte // 32 + 32 + 48
	// Right-align into 32-byte big-endian slots.
	copy(preimage[32-len(processID):32], processID)
	copy(preimage[64-len(rootHashBefore):64], rootHashBefore)
	copy(preimage[64:], commitment[:])
	h := sha256.Sum256(preimage[:])
	return new(big.Int).SetBytes(h[:])
}

// TestKZGEmulator_Simple uses a sparse blob (10 non-zero cells) for a quick emulator test.
func TestKZGEmulator_Simple(t *testing.T) {
	var blob types.Blob
	for i := 0; i < 10; i++ {
		big.NewInt(int64(i + 1)).FillBytes(blob[i*32 : (i+1)*32])
	}
	runKZGEmulatorTest(t, &blob, "simple_sparse")
}

// TestKZGEmulator_BlobData1 uses the full embedded test blob from davinci-node.
func TestKZGEmulator_BlobData1(t *testing.T) {
	blob, err := blobs.GetBlobData1()
	if err != nil {
		t.Fatalf("GetBlobData1: %v", err)
	}
	runKZGEmulatorTest(t, blob, "blobdata1")
}

// TestKZGEmulator_WrongY verifies that the circuit sets FAIL_KZG when Y is incorrect.
func TestKZGEmulator_WrongY(t *testing.T) {
	var blob types.Blob
	big.NewInt(42).FillBytes(blob[0:32])

	commitment, err := blob.ComputeCommitment()
	if err != nil {
		t.Fatalf("ComputeCommitment: %v", err)
	}

	processID := []byte{0x42}
	rootHashBefore := []byte{0x07}
	comm48 := [48]byte(commitment)

	// Encode an incorrect Y (all 0xff).
	var wrongY [32]byte
	for i := range wrongY {
		wrongY[i] = 0xff
	}

	inputBin, ok := findKZGBaseBin(t)
	if !ok {
		return
	}
	baseBin, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	kzgBlock, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      processID,
		RootHashBefore: rootHashBefore,
		Commitment:     comm48,
		YClaimed:       wrongY,
		Blob:           blob[:],
	})
	if err != nil {
		t.Fatalf("EncodeKZGBlock: %v", err)
	}

	combined := append(baseBin, kzgBlock...)
	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}

	if outputs[davinci.OutputOverallOk] != 0 {
		t.Errorf("expected overall_ok=0 for wrong Y, got %d", outputs[davinci.OutputOverallOk])
	}
	const failKZG = 1 << 18
	if outputs[davinci.OutputFailMask]&failKZG == 0 {
		t.Errorf("expected FAIL_KZG bit set, fail_mask=0x%08x", outputs[davinci.OutputFailMask])
	}
	t.Logf("Correctly rejected wrong Y: fail_mask=0x%08x", outputs[davinci.OutputFailMask])
}

// runKZGEmulatorTest runs the full KZG barycentric evaluation test through the ZisK emulator.
func runKZGEmulatorTest(t *testing.T, blob *types.Blob, name string) {
	t.Helper()

	commitment, err := blob.ComputeCommitment()
	if err != nil {
		t.Fatalf("[%s] ComputeCommitment: %v", name, err)
	}

	// Deterministic process context.
	processID := []byte{0x42}
	rootHashBefore := []byte{0x07}
	comm48 := [48]byte(commitment)

	// Derive Z: must match circuit's compute_z exactly.
	z := computeKZGZ(processID, rootHashBefore, comm48)
	t.Logf("[%s] Z = 0x%x", name, z)

	// Evaluate Y = P(Z) via Go reference implementation.
	y, err := blobs.EvaluateBarycentricNative(blob, z, false)
	if err != nil {
		t.Fatalf("[%s] EvaluateBarycentricNative: %v", name, err)
	}
	t.Logf("[%s] Y = 0x%x", name, y)

	var yClaimed [32]byte
	y.FillBytes(yClaimed[:])

	inputBin, ok := findKZGBaseBin(t)
	if !ok {
		return
	}
	baseBin, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("[%s] read input.bin: %v", name, err)
	}

	kzgBlock, err := davinci.EncodeKZGBlock(&davinci.KZGEvalData{
		ProcessID:      processID,
		RootHashBefore: rootHashBefore,
		Commitment:     comm48,
		YClaimed:       yClaimed,
		Blob:           blob[:],
	})
	if err != nil {
		t.Fatalf("[%s] EncodeKZGBlock: %v", name, err)
	}

	combined := append(baseBin, kzgBlock...)
	t.Logf("[%s] combined input: %d bytes (base=%d kzg=%d)", name, len(combined), len(baseBin), len(kzgBlock))

	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("[%s] ziskemu: %v", name, err)
	}
	t.Logf("[%s] outputs: %v", name, outputsHex(outputs))

	if outputs[davinci.OutputOverallOk] != 1 {
		t.Errorf("[%s] overall_ok=%d want 1; fail_mask=0x%08x",
			name, outputs[davinci.OutputOverallOk], outputs[davinci.OutputFailMask])
	}
	if outputs[davinci.OutputFailMask] != 0 {
		t.Errorf("[%s] fail_mask=0x%08x want 0", name, outputs[davinci.OutputFailMask])
	}

	// Verify BlobCommitmentLimbs (outputs[28..39]) match the commitment bytes.
	for l := 0; l < 3; l++ {
		chunk := commitment[l*16 : (l+1)*16]
		// Reconstruct as two u64s (lo and hi of 128-bit limb).
		var expectedLo, expectedHi uint64
		for i := 0; i < 8; i++ {
			expectedHi = (expectedHi << 8) | uint64(chunk[i])
			expectedLo = (expectedLo << 8) | uint64(chunk[8+i])
		}
		base := davinci.OutputBlobCommitment + l*4
		gotLo := uint64(outputs[base]) | (uint64(outputs[base+1]) << 32)
		gotHi := uint64(outputs[base+2]) | (uint64(outputs[base+3]) << 32)
		if gotLo != expectedLo || gotHi != expectedHi {
			t.Errorf("[%s] limb[%d]: got lo=0x%x hi=0x%x, want lo=0x%x hi=0x%x",
				name, l, gotLo, gotHi, expectedLo, expectedHi)
		}
	}
}

// findKZGBaseBin locates the base Groth16 input.bin for KZG tests.
func findKZGBaseBin(t *testing.T) (string, bool) {
	t.Helper()
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
		return "", false
	}
	return inputBin, true
}
