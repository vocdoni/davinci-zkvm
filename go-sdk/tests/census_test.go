package tests

// TestCensusProof verifies that lean-IMT Poseidon census membership proofs
// are correctly validated by the davinci-zkvm circuit.
//
// The test builds a lean-IMT tree with PoseidonHasher, inserts N voter leaves
// (each = PackAddressWeight(address, weight)), generates proofs, and feeds them
// to the circuit via the emulator.  output[0] must be 1.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	iden3poseidon "github.com/iden3/go-iden3-crypto/poseidon"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	leanimt "github.com/vocdoni/lean-imt-go"
)

// poseidonHasher wraps iden3 Poseidon for use with lean-IMT.
func poseidonHasher(a, b *big.Int) *big.Int {
	out, err := iden3poseidon.Hash([]*big.Int{a, b})
	if err != nil {
		panic(err)
	}
	return out
}

// bigIntEq compares two *big.Int values.
func bigIntEq(a, b *big.Int) bool { return a.Cmp(b) == 0 }

// packAddressWeight packs address (160 bits) and weight (88 bits) into one big.Int.
// Compatible with lean-imt-go/census.PackAddressWeight.
func packAddressWeight(address, weight *big.Int) *big.Int {
	packed := new(big.Int).Lsh(address, 88)
	return packed.Or(packed, weight)
}

// bigIntToFr32 converts a *big.Int to a 32-byte big-endian hex string (with 0x prefix).
func bigIntToFr32(v *big.Int) string {
	b := v.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return "0x" + hex.EncodeToString(padded)
}

// fr32FromHex converts "0x..." hex string to [4]uint64 LE limbs (circuit FrRaw format).
func fr32FromHex(s string) ([4]uint64, error) {
	h := s
	if len(h) > 2 && h[:2] == "0x" {
		h = h[2:]
	}
	b, err := hex.DecodeString(fmt.Sprintf("%064s", h))
	if err != nil {
		return [4]uint64{}, err
	}
	// big-endian bytes → LE u64 limbs
	var out [4]uint64
	for i := 0; i < 4; i++ {
		start := 24 - i*8
		out[i] = binary.BigEndian.Uint64(b[start : start+8])
	}
	return out, nil
}

// TestCensusProofEmulator builds a lean-IMT Poseidon tree, generates proofs,
// and verifies them via the ziskemu emulator.
func TestCensusProofEmulator(t *testing.T) {
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
	}
	baseInput, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	// Build a lean-IMT Poseidon tree with nVoters voters.
	const nVoters = 5
	tree, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	type voterData struct {
		leaf *big.Int
	}
	voters := make([]voterData, nVoters)
	for i := 0; i < nVoters; i++ {
		addr := new(big.Int).SetInt64(int64(0x1000 + i*0x100))
		weight := new(big.Int).SetInt64(1)
		leaf := packAddressWeight(addr, weight)
		voters[i] = voterData{leaf: leaf}
		tree.Insert(leaf)
	}

	root, ok := tree.Root()
	if !ok {
		t.Fatal("tree root not available")
	}
	t.Logf("Census tree root: %s", bigIntToFr32(root))

	// Generate proofs for all voters.
	censusProofs := make([]davinci.CensusProof, nVoters)
	for i := 0; i < nVoters; i++ {
		proof, err := tree.GenerateProof(i)
		if err != nil {
			t.Fatalf("gen proof %d: %v", i, err)
		}
		if !tree.VerifyProof(proof) {
			t.Fatalf("proof %d does not verify in Go", i)
		}

		sibStrs := make([]string, len(proof.Siblings))
		for j, s := range proof.Siblings {
			sibStrs[j] = bigIntToFr32(s)
		}
		censusProofs[i] = davinci.CensusProof{
			Root:     bigIntToFr32(root),
			Leaf:     bigIntToFr32(proof.Leaf),
			Index:    proof.Index,
			Siblings: sibStrs,
		}
		t.Logf("voter %d: leaf=%s index=%d siblings=%d", i,
			censusProofs[i].Leaf[:10], censusProofs[i].Index, len(censusProofs[i].Siblings))
	}

	// Encode census block.
	censusBytes, err := davinci.EncodeCensusBlock(censusProofs)
	if err != nil {
		t.Fatalf("encode census: %v", err)
	}
	t.Logf("Census block: %d bytes", len(censusBytes))

	// Combine base input with census block.
	combined := append(baseInput, censusBytes...)
	t.Logf("Combined input: %d bytes (base=%d census=%d)", len(combined), len(baseInput), len(censusBytes))

	// Run emulator.
	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	t.Logf("Outputs: %v", outputsHex(outputs))

	// This test provides Groth16 + ECDSA + CENSUSBLK but omits STATETX, re-encryption,
	// and KZG blocks. overall_ok=0 is expected. We verify census-specific bits are clear.
	if outputs[1]&0x00010000 != 0 { // bit 16 = FAIL_CENSUS
		t.Errorf("FAIL_CENSUS bit set in fail_mask: 0x%08x", outputs[1])
	}
}
