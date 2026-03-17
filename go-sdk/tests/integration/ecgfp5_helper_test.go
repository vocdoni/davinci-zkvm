package integration

import "testing"

func TestEcgfp5HelperLeafHash(t *testing.T) {
	requireWasmPkg(t)
	election, err := NewElection(1)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	pkHex, err := generateStarkKeypair([]byte("integration-test-stark-enc-key"))
	if err != nil {
		t.Fatalf("generateStarkKeypair: %v", err)
	}
	batch, err := GenerateStarkBallotBatch(election.ProcessID, pkHex, election.Voters[:1], 42)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}
	ballot := ciphertextsFromBundle(batch.Results[0].Bundle)
	var out ecgfp5HashResponse
	if err := runEcgfp5Helper(map[string]any{"command": "leaf_hash", "ballot": ballot}, &out); err != nil {
		t.Fatalf("runEcgfp5Helper leaf_hash: %v", err)
	}
	if len(out.HashHex) != 64 {
		t.Fatalf("leaf hash len = %d, want 64", len(out.HashHex))
	}
}
