package integration

import (
	"encoding/json"
	"strings"
	"testing"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func TestBuildStarkStateAndReencBlocks(t *testing.T) {
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	if err := election.ConfigureForStark(); err != nil {
		t.Fatalf("ConfigureForStark: %v", err)
	}

	batch, err := GenerateStarkBallotBatch(election.ProcessID, election.StarkEncKeyHex, election.Voters[:2], 42)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}

	reenc, reencBallots, err := election.BuildStarkReencBlock(batch.Results)
	if err != nil {
		t.Fatalf("BuildStarkReencBlock: %v", err)
	}
	if len(reenc.Entries) != 2 {
		t.Fatalf("reenc entries = %d, want 2", len(reenc.Entries))
	}
	reencBytes, err := davinci.EncodeEcgfp5ReencBlock(reenc)
	if err != nil {
		t.Fatalf("EncodeEcgfp5ReencBlock: %v", err)
	}
	if len(reencBytes) == 0 {
		t.Fatal("expected non-empty ecgfp5 reenc block")
	}

	state, overwritten, err := election.BuildStarkStateBlock(election.Voters[:2], batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStarkStateBlock: %v", err)
	}
	if len(overwritten) != 0 {
		t.Fatalf("overwritten ballots = %d, want 0", len(overwritten))
	}
	if state.Ecgfp5BallotProofs == nil {
		t.Fatal("expected ecgfp5 ballot proofs in state block")
	}
	stateBytes, err := davinci.EncodeStateBlock(state)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	if len(stateBytes) == 0 {
		t.Fatal("expected non-empty ecgfp5 state block")
	}
}

func TestBuildStarkStateBlockUsesEmptyOverwriteSlice(t *testing.T) {
	requireWasmPkg(t)

	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	if err := election.ConfigureForStark(); err != nil {
		t.Fatalf("ConfigureForStark: %v", err)
	}

	batch, err := GenerateStarkBallotBatch(election.ProcessID, election.StarkEncKeyHex, election.Voters[:2], 42)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}
	_, reencBallots, err := election.BuildStarkReencBlock(batch.Results)
	if err != nil {
		t.Fatalf("BuildStarkReencBlock: %v", err)
	}
	state, overwritten, err := election.BuildStarkStateBlock(election.Voters[:2], batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStarkStateBlock: %v", err)
	}
	if len(overwritten) != 0 {
		t.Fatalf("overwritten ballots = %d, want 0", len(overwritten))
	}

	body, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("json.Marshal(state): %v", err)
	}
	if !strings.Contains(string(body), `"overwritten_ballots":[]`) {
		t.Fatalf("state json must encode overwritten_ballots as [], got: %s", string(body))
	}
}
