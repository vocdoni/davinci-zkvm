// snapshot.go serializes and restores a chained-election State so an
// orchestrator can survive restarts. Each batch draws a fresh random
// re-encryption seed and picks its silent-refresh set from OS randomness,
// so replaying the vote log does not reproduce the same tree; the full
// state (arbo contents, net accumulator, per-voter ballots and counters)
// has to be captured verbatim. Neither the seed nor the refresh selection
// are ever persisted — the map size is enough to recompute the batch's
// OccupiedBefore and the guest's refresh target on the next ApplyBatch.
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
	VotedBallots map[uint64][]byte // keyed by full ballot tree key
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

	voted := make(map[uint64][]byte, len(s.votedBallots))
	for key, b := range s.votedBallots {
		voted[key] = b.Serialize()
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

	// Validate the accumulator coordinates: bounded, canonical and on-curve.
	// A corrupted or tampered snapshot would otherwise only surface later as
	// a panic inside the TE point arithmetic.
	var results accumBallot
	for i, b := range snap.Results {
		if len(b) > 32 {
			return nil, fmt.Errorf("snapshot results[%d]: %d bytes, want <= 32", i, len(b))
		}
		v := new(big.Int).SetBytes(b)
		if v.Cmp(bn254ScalarField) >= 0 {
			return nil, fmt.Errorf("snapshot results[%d]: coordinate not in field", i)
		}
		results[i] = v
	}
	for i := 0; i < davinci.BallotFields/2; i++ {
		if !isOnCurveTE(results[i*2], results[i*2+1]) {
			return nil, fmt.Errorf("snapshot results: point %d not on BabyJubJub", i)
		}
	}

	voted := make(map[uint64]*elgamal.Ballot, len(snap.VotedBallots))
	for key, b := range snap.VotedBallots {
		ballot := elgamal.NewBallot(cfg.EncKey)
		if err := ballot.Deserialize(b); err != nil {
			return nil, fmt.Errorf("deserialize ballot[%#x]: %w", key, err)
		}
		voted[key] = ballot
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
