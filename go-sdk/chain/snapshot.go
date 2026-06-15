// snapshot.go serializes and restores a chained-election State so an
// orchestrator can survive restarts. Per-ballot re-encryption draws a random
// k, so replaying the vote log does not reproduce the same tree; the full
// state (arbo contents, net accumulator, per-voter ballots and counters) has
// to be captured verbatim.
package chain

import (
	"encoding/hex"
	"fmt"
	"math/big"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/davinci-node/crypto/elgamal"

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
	if cfg.ProcessID == nil || cfg.BallotMode == nil || cfg.EncKey == nil || cfg.CensusRoot == nil {
		return nil, fmt.Errorf("chain.Config: ProcessID, BallotMode, EncKey and CensusRoot are required")
	}
	var snap stateSnapshot
	if err := cbor.Unmarshal(blob, &snap); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	if len(snap.Results) != 32 {
		return nil, fmt.Errorf("snapshot results: want 32 coords, got %d", len(snap.Results))
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
