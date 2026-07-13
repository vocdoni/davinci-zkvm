// snapshot.go serializes and restores a chained-election State so an
// orchestrator can survive restarts. Per-ballot re-encryption draws a random
// k, so replaying the vote log does not reproduce the same tree; the full
// state (arbo contents, net accumulator, per-voter ballots and counters) has
// to be captured verbatim.
package chain

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"

	"github.com/fxamacker/cbor/v2"
)

// stateSnapshot is the wire form of a State. The immutable Config is not
// stored: RestoreState takes it as an argument (it is recomputable from the
// election record and binds the genesis root).
type stateSnapshot struct {
	TreeDump     []byte
	Root         string
	Results      [][]byte
	VotedBallots map[int][]byte
	Voters       uint64
	Overwrites   uint64
}

// Snapshot serializes the full mutable state to a CBOR blob. Restore it with
// RestoreState and the same Config.
func (s *State) Snapshot() ([]byte, error) {
	dump, err := s.tree.Dump(nil)
	if err != nil {
		return nil, fmt.Errorf("dump tree: %w", err)
	}

	results := make([][]byte, len(s.results))
	for i, v := range s.results {
		results[i] = v.Bytes()
	}

	voted := make(map[int][]byte, len(s.votedBallots))
	for idx, b := range s.votedBallots {
		voted[idx] = b.Serialize()
	}

	return cbor.Marshal(stateSnapshot{
		TreeDump:     dump,
		Root:         s.root,
		Results:      results,
		VotedBallots: voted,
		Voters:       s.voters,
		Overwrites:   s.overwrites,
	})
}

// RestoreState rebuilds a State from a Snapshot blob and the election Config.
// The Config must match the one the snapshot was taken under; the restored
// root is checked against the rebuilt arbo tree to catch a mismatch.
func RestoreState(cfg Config, blob []byte) (*State, error) {
	if cfg.ProcessID == nil || cfg.BallotMode == nil || cfg.EncKey == nil || cfg.CensusRoot == nil || cfg.BallotVKHash == nil {
		return nil, fmt.Errorf("chain.Config: ProcessID, BallotMode, EncKey, CensusRoot and BallotVKHash are required")
	}
	var snap stateSnapshot
	if err := cbor.Unmarshal(blob, &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if len(snap.Results) != davinci.BallotFields {
		return nil, fmt.Errorf("snapshot results: want %d coords, got %d", davinci.BallotFields, len(snap.Results))
	}

	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("arbo.NewTree: %w", err)
	}
	if err := tree.ImportDump(snap.TreeDump); err != nil {
		return nil, fmt.Errorf("import tree dump: %w", err)
	}

	rootBytes, err := tree.Root()
	if err != nil {
		return nil, fmt.Errorf("restored root: %w", err)
	}
	root := "0x" + hex.EncodeToString(pad32(rootBytes))
	if root != snap.Root {
		return nil, fmt.Errorf("restored root %s != snapshot root %s", root, snap.Root)
	}

	// Anchor the snapshot to the election config: verify the five immutable
	// config leaves in the restored tree match cfg. Without this, a snapshot
	// taken under a different config (different process_id, encryption key,
	// census_root, etc.) restores without detection, and Finalize would
	// accept proofs built under the wrong parameters. The config leaves are
	// set at genesis and never modified, so they must match at any point in
	// the chain.
	bLen := arbo.HashFunctionSha256.Len()
	expectedLeaves := []struct {
		key   uint64
		value *big.Int
	}{
		{0x00, cfg.ProcessID},
		{0x02, cfg.BallotMode},
		{0x03, encKeyLeafValue(cfg.EncKey)},
		{0x06, new(big.Int).SetUint64(cfg.CensusOrigin)},
		{0x07, cfg.BallotVKHash},
	}
	for _, leaf := range expectedLeaves {
		keyBytes := arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(leaf.key))
		_, got, err := tree.Get(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("snapshot anchor: config leaf 0x%02x not found: %w", leaf.key, err)
		}
		want := arbo.BigIntToBytes(bLen, leaf.value)
		if !bytes.Equal(got, want) {
			return nil, fmt.Errorf("snapshot anchor: config leaf 0x%02x mismatch — "+
				"snapshot was taken under different election parameters", leaf.key)
		}
	}

	var results accumBallot
	for i, b := range snap.Results {
		results[i] = new(big.Int).SetBytes(b)
	}

	voted := make(map[int]*elgamal.Ballot, len(snap.VotedBallots))
	for idx, b := range snap.VotedBallots {
		ballot := elgamal.NewBallot(cfg.EncKey)
		if err := ballot.Deserialize(b); err != nil {
			return nil, fmt.Errorf("deserialize ballot[%d]: %w", idx, err)
		}
		voted[idx] = ballot
	}

	return &State{
		cfg:          cfg,
		tree:         tree,
		root:         snap.Root,
		results:      results,
		votedBallots: voted,
		voters:       snap.Voters,
		overwrites:   snap.Overwrites,
	}, nil
}
