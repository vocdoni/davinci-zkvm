package tests

// TestReencryptionEmulator verifies that the BabyJubJub ElGamal re-encryption
// verification in the davinci-zkvm circuit is correct.
//
// The test:
//  1. Generates a BabyJubJub ElGamal key pair using bjj_gnark.
//  2. Encrypts 3 ballots (8 fields each).
//  3. Re-encrypts each ballot using davinci-node's Ballot.Reencrypt with a known rawK.
//  4. Converts all BabyJubJub coordinates from Reduced TwistedEdwards (bjj_gnark)
//     to standard TwistedEdwards (iden3/circuit convention) via format.FromRTEtoTE.
//  5. Appends the REENCBLK to the base circuit input and runs via ziskemu.
//  6. Expects output[0]=1.

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// rtePointToFr32Hex converts a bjj_gnark (RTE) point to TE hex strings (32-byte BE, "0x" prefix).
func rtePointToFr32Hex(p interface{ Point() (*big.Int, *big.Int) }) (xHex, yHex string) {
	rx, ry := p.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	xHex = bigIntToFr32(tx)
	yHex = bigIntToFr32(ty)
	return
}

func TestReencryptionEmulator(t *testing.T) {
	// Load pre-built base input (same as census test uses).
	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	if _, err := os.Stat(inputBin); err != nil {
		t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
	}
	baseInput, err := os.ReadFile(inputBin)
	if err != nil {
		t.Fatalf("read input.bin: %v", err)
	}

	const nVoters = 3
	const nFields = 8

	// --- Generate ElGamal key pair using bjj_gnark (RTE coordinates) ---
	pubKey, _, err := elgamal.GenerateKey(bjjgnark.New())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pkX, pkY := rtePointToFr32Hex(pubKey)
	t.Logf("Encryption pubKey (TE): X=%s... Y=%s...", pkX[:10], pkY[:10])

	// --- Encrypt and re-encrypt ballots ---
	entries := make([]davinci.ReencryptionEntry, nVoters)
	for v := 0; v < nVoters; v++ {
		ballot := elgamal.NewBallot(bjjgnark.New())

		// Encrypt each of the 8 fields with a small message.
		for i := 0; i < nFields; i++ {
			msg := big.NewInt(int64(v*100 + i + 1))
			c1, c2, _, err := elgamal.Encrypt(pubKey, msg)
			if err != nil {
				t.Fatalf("Encrypt v=%d i=%d: %v", v, i, err)
			}
			ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
		}

		// Choose a random rawK and re-encrypt.
		rawK, err := rand.Int(rand.Reader, pubKey.Order())
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		reencBallot, _, err := ballot.Reencrypt(pubKey, rawK)
		if err != nil {
			t.Fatalf("Reencrypt v=%d: %v", v, err)
		}

		// Build the wire entry with rawK and TE-converted coordinates.
		rawKHex := "0x" + hex.EncodeToString(pad32(rawK.Bytes()))
		entry := davinci.ReencryptionEntry{
			K: rawKHex,
		}
		for i := 0; i < nFields; i++ {
			origC1x, origC1y := rtePointToFr32Hex(ballot.Ciphertexts[i].C1)
			origC2x, origC2y := rtePointToFr32Hex(ballot.Ciphertexts[i].C2)
			reencC1x, reencC1y := rtePointToFr32Hex(reencBallot.Ciphertexts[i].C1)
			reencC2x, reencC2y := rtePointToFr32Hex(reencBallot.Ciphertexts[i].C2)
			entry.Original[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: origC1x, Y: origC1y},
				C2: davinci.BjjPoint{X: origC2x, Y: origC2y},
			}
			entry.Reencrypted[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: reencC1x, Y: reencC1y},
				C2: davinci.BjjPoint{X: reencC2x, Y: reencC2y},
			}
		}
		entries[v] = entry
		t.Logf("Voter %d: rawK=%s...", v, rawKHex[:10])
	}

	reencData := &davinci.ReencryptionData{
		EncryptionKeyX: pkX,
		EncryptionKeyY: pkY,
		Entries:        entries,
	}

	// Encode the REENCBLK and append to base input.
	reencBytes, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}
	t.Logf("REENCBLK: %d bytes", len(reencBytes))

	combined := append(baseInput, reencBytes...)
	t.Logf("Combined input: %d bytes (base=%d reenc=%d)", len(combined), len(baseInput), len(reencBytes))

	// Run ziskemu.
	outputs, err := runZiskEmu(combined)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	t.Logf("ziskemu outputs: %v", outputsHex(outputs))

	if outputs[0] != 1 {
		t.Errorf("expected output[0]=1 (overall_ok), got %d; fail_mask=0x%08x", outputs[0], outputs[1])
	}
}
