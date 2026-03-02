// smt_service_test.go contains SMT state-transition tests that submit jobs to
// a running davinci-zkvm HTTP service. These tests require the service to be
// reachable at apiURL (default: http://localhost:8080).
//
// Start the service with: docker compose up -d --build
package integration

import (
	"encoding/hex"
	"math/big"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

const smtServiceLevels = 256

// TestSMTInsertTransition submits a ProveRequest that includes a valid SMT
// insert transition.  The job must complete successfully.
func TestSMTInsertTransition(t *testing.T) {
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}

	// Load the 128 ballot proofs + ECDSA signatures.
	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	// Build an arbo SHA-256 tree and insert 5 initial leaves.
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    smtServiceLevels,
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
	smtEntry, err := buildArboInsertEntry(tree, big.NewInt(42), big.NewInt(420), smtServiceLevels)
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

	proof, err := client.WaitForJob(jobID, proofTimeout())
	if err != nil {
		t.Fatalf("WaitForJob %s: %v", jobID, err)
	}
	t.Logf("Job %s done (status: %s)", jobID, proof.Status)
}

// TestSMTUpdateTransition verifies that an SMT update (replace value for
// existing key) is correctly validated.
func TestSMTUpdateTransition(t *testing.T) {
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}

	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("load fixtures: %v", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	db := memdb.New()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     db,
		MaxLevels:    smtServiceLevels,
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
	siblingsUnpacked, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSiblings)
	if err != nil {
		t.Fatalf("UnpackSiblings: %v", err)
	}
	zero32 := make([]byte, bLen)
	for len(siblingsUnpacked) < smtServiceLevels {
		siblingsUnpacked = append(siblingsUnpacked, zero32)
	}
	siblingsUnpacked = siblingsUnpacked[:smtServiceLevels]

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
		Siblings: make([]string, smtServiceLevels),
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

	proof, err := client.WaitForJob(jobID, proofTimeout())
	if err != nil {
		t.Fatalf("WaitForJob %s: %v", jobID, err)
	}
	t.Logf("Job %s done (status: %s)", jobID, proof.Status)
}
