package integration

// TestFullE2E is the full end-to-end integration test for the DAVINCI zkVM circuit.
//
// It submits a full ProveRequest to the running davinci-zkvm service, which includes:
//  1. Groth16 batch proof verification (128 ballot proofs + verification key)
//  2. ECDSA signature verification (one per ballot proof)
//  3. STATETX state transition: process config reads + voteID/ballot insertions
//  4. CENSUS lean-IMT Poseidon membership proofs (one per voter)
//  5. REENCBLK BabyJubJub ElGamal re-encryption verification
//  6. KZG EIP-4844 blob barycentric evaluation (SHA-256 Z derivation)
//
// The test requires the davinci-zkvm service to be running at apiURL.
// Start it with: docker compose up -d --build
//
// Expected: job completes with status "done".

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/crypto/blobs"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	leanimt "github.com/vocdoni/lean-imt-go"
)

func TestFullE2E(t *testing.T) {
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}

	// Load base ProveRequest (VK + 128 ballot proofs + ECDSA sigs).
	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Skipf("test fixtures not found (run 'make gen-input' first): %v", err)
	}

	const nVotes = 3
	const nFields = 8
	const procLevels = 256

	dataDir := testDataDir()
	inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
	baseInput, err := os.ReadFile(inputBin)
	if err != nil {
		t.Skipf("base input not found at %s: %v", inputBin, err)
	}

	// ─── 1. STATETX block ────────────────────────────────────────────────────
	procDB := memdb.New()
	procTree, err := arbo.NewTree(arbo.Config{
		Database:     procDB,
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}

	configKeys := []uint64{0x00, 0x02, 0x03, 0x06}
	configVals := []uint64{0xABCDEF, 0x01, 0x1234, 0x01}
	bLen := arbo.HashFunctionSha256.Len()
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(configVals[i])),
		); err != nil {
			t.Fatalf("procTree.Add config[%d]: %v", i, err)
		}
	}

	oldRootBytes, _ := procTree.Root()
	oldRootHex := "0x" + hex.EncodeToString(pad32(oldRootBytes))

	processSmt, err := buildArboReadProofs(procTree, configKeys, bLen, procLevels)
	if err != nil {
		t.Fatalf("buildArboReadProofs: %v", err)
	}

	voteIDs, err := parseVoteIDsFromBinary(baseInput, nVotes)
	if err != nil {
		t.Fatalf("parseVoteIDsFromBinary: %v", err)
	}
	addrsLo16, err := parseAddrsLo16FromBinary(baseInput, nVotes)
	if err != nil {
		t.Fatalf("parseAddrsLo16FromBinary: %v", err)
	}

	var voteIDChain []davinci.SmtEntry
	for i := 0; i < nVotes; i++ {
		entry, err := buildArboInsertEntry(procTree,
			new(big.Int).SetUint64(voteIDs[i]),
			new(big.Int).SetUint64(uint64(1000+i)),
			procLevels)
		if err != nil {
			t.Fatalf("voteID insert[%d]: %v", i, err)
		}
		voteIDChain = append(voteIDChain, entry)
	}

	const ballotMin = uint64(0x10)
	var ballotChain []davinci.SmtEntry
	for i := 0; i < nVotes; i++ {
		key := ballotMin + uint64(i)<<16 + addrsLo16[i]
		entry, err := buildArboInsertEntry(procTree,
			new(big.Int).SetUint64(key),
			new(big.Int).SetUint64(uint64(2000+i)),
			procLevels)
		if err != nil {
			t.Fatalf("ballot insert[%d]: %v", i, err)
		}
		ballotChain = append(ballotChain, entry)
	}

	newRootBytes, _ := procTree.Root()
	newRootHex := "0x" + hex.EncodeToString(pad32(newRootBytes))

	req.State = &davinci.StateTransitionData{
		VotersCount:      nVotes,
		OverwrittenCount: 0,
		ProcessID:        oldRootHex,
		OldStateRoot:     oldRootHex,
		NewStateRoot:     newRootHex,
		VoteIDSmt:        voteIDChain,
		BallotSmt:        ballotChain,
		ProcessSmt:       processSmt,
	}

	// ─── 2. CENSUS block ─────────────────────────────────────────────────────
	imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatalf("leanimt.New: %v", err)
	}
	leaves := make([]*big.Int, nVotes)
	for i := 0; i < nVotes; i++ {
		addr := new(big.Int).SetBytes([]byte{byte(0x10 + i), byte(0x20 + i)})
		leaves[i] = packAddressWeight(addr, big.NewInt(int64(100+i)))
		imt.Insert(leaves[i])
	}
	root, ok := imt.Root()
	if !ok {
		t.Fatal("census tree root not available")
	}

	censusProofs := make([]davinci.CensusProof, nVotes)
	for i := 0; i < nVotes; i++ {
		proof, err := imt.GenerateProof(i)
		if err != nil {
			t.Fatalf("imt.GenerateProof[%d]: %v", i, err)
		}
		sibs := make([]string, len(proof.Siblings))
		for j, s := range proof.Siblings {
			sibs[j] = bigIntToFr32(s)
		}
		censusProofs[i] = davinci.CensusProof{
			Root:     bigIntToFr32(root),
			Leaf:     bigIntToFr32(proof.Leaf),
			Index:    proof.Index,
			Siblings: sibs,
		}
	}
	req.CensusProofs = censusProofs

	// ─── 3. REENCBLK block ───────────────────────────────────────────────────
	pubKey, _, err := elgamal.GenerateKey(bjjgnark.New())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pkX, pkY := rtePointToFr32Hex(pubKey)

	entries := make([]davinci.ReencryptionEntry, nVotes)
	for v := 0; v < nVotes; v++ {
		ballot := elgamal.NewBallot(bjjgnark.New())
		for i := 0; i < nFields; i++ {
			c1, c2, _, err := elgamal.Encrypt(pubKey, big.NewInt(int64(v*100+i+1)))
			if err != nil {
				t.Fatalf("Encrypt v=%d i=%d: %v", v, i, err)
			}
			ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
		}
		rawK, err := rand.Int(rand.Reader, pubKey.Order())
		if err != nil {
			t.Fatalf("rand.Int: %v", err)
		}
		reencBallot, _, err := ballot.Reencrypt(pubKey, rawK)
		if err != nil {
			t.Fatalf("Reencrypt v=%d: %v", v, err)
		}

		entry := davinci.ReencryptionEntry{K: bigIntToFr32(rawK)}
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
	}
	req.Reencryption = &davinci.ReencryptionData{
		EncryptionKeyX: pkX,
		EncryptionKeyY: pkY,
		Entries:        entries,
	}

	// ─── 4. KZG block ────────────────────────────────────────────────────────
	var blob types.Blob
	for i := 0; i < 10; i++ {
		big.NewInt(int64(i + 1)).FillBytes(blob[i*32 : (i+1)*32])
	}
	kzgCommitment, err := blob.ComputeCommitment()
	if err != nil {
		t.Fatalf("blob.ComputeCommitment: %v", err)
	}
	var comm48 [48]byte
	copy(comm48[:], kzgCommitment[:])

	// Derive Z: SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48).
	processIDBytes, _ := hex.DecodeString(oldRootHex[2:])
	oldRootHashBytes, _ := hex.DecodeString(oldRootHex[2:])
	var kzgPreimage [112]byte
	copy(kzgPreimage[32-len(processIDBytes):32], processIDBytes)
	copy(kzgPreimage[64-len(oldRootHashBytes):64], oldRootHashBytes)
	copy(kzgPreimage[64:], comm48[:])
	kzgHash := sha256.Sum256(kzgPreimage[:])
	kzgZ := new(big.Int).SetBytes(kzgHash[:])

	kzgY, err := blobs.EvaluateBarycentricNative(&blob, kzgZ, false)
	if err != nil {
		t.Fatalf("EvaluateBarycentricNative: %v", err)
	}
	var yClaimed [32]byte
	kzgY.FillBytes(yClaimed[:])

	req.KZG = &davinci.KZGRequest{
		ProcessID:      "0x" + hex.EncodeToString(processIDBytes),
		RootHashBefore: "0x" + hex.EncodeToString(oldRootHashBytes),
		Commitment:     "0x" + hex.EncodeToString(comm48[:]),
		YClaimed:       "0x" + hex.EncodeToString(yClaimed[:]),
		Blob:           "0x" + hex.EncodeToString(blob[:]),
	}

	// ─── 5. Submit to API and wait ───────────────────────────────────────────
	client := newClient()
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("SubmitProve: %v", err)
	}
	t.Logf("Submitted job %s", jobID)

	job, err := client.WaitForJob(jobID, proofTimeout())
	if err != nil {
		t.Fatalf("WaitForJob %s: %v", jobID, err)
	}
	if job.ElapsedMs != nil {
		t.Logf("Job %s done in %dms (%.1fs)", jobID, *job.ElapsedMs, float64(*job.ElapsedMs)/1000)
	}
	if job.Status != "done" {
		if job.Error != nil {
			t.Fatalf("job failed: %s", *job.Error)
		}
		t.Fatalf("unexpected job status: %s", job.Status)
	}
}
