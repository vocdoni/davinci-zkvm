package chain

import (
	"strings"
	"testing"

	qt "github.com/frankban/quicktest"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// A vote id or slot whose 63 low bits equal an existing key puts both leaves
// at depth 64 (arbo splits them on level 63). ApplyBatch builds it, and every
// later proof of either leaf carries the non-zero 64th sibling and the zero
// sentinel in the 65th slot, which the guests and the registry accept.
func TestApplyBatchBuildsDepth64Twins(t *testing.T) {
	const ns = uint64(1) << 63
	encKey := testEncKey(t)
	b := testBallot(t, encKey, 10)
	fresh := func(c *qt.C) *State {
		st, err := NewState(testConfig(encKey))
		c.Assert(err, qt.IsNil)
		return st
	}
	isZero := func(h string) bool { return strings.Trim(strings.TrimPrefix(h, "0x"), "0") == "" }
	// atDepth64 checks a proof of a leaf at depth 64.
	atDepth64 := func(c *qt.C, e davinci.SmtEntry, what string) {
		c.Assert(e.Siblings, qt.HasLen, davinci.SMTProofLevels, qt.Commentf(what))
		c.Assert(isZero(e.Siblings[davinci.SMTLevels-1]), qt.IsFalse, qt.Commentf("%s: sibling 63", what))
		c.Assert(isZero(e.Siblings[davinci.SMTLevels]), qt.IsTrue, qt.Commentf("%s: sentinel", what))
	}
	apply := func(c *qt.C, st *State, votes ...Vote) *davinci.StateTransitionData {
		std, _, err := st.ApplyBatch(votes)
		c.Assert(err, qt.IsNil)
		for _, chain := range [][]davinci.SmtEntry{std.VoteIDSmt, std.BallotSmt, std.RefreshSmt, std.ProcessSmt} {
			for _, e := range chain {
				c.Assert(e.Siblings, qt.HasLen, davinci.SMTProofLevels)
			}
		}
		return std
	}
	t.Run("config_and_results_twins", func(t *testing.T) {
		c := qt.New(t)
		for i, k := range configKeys {
			st := fresh(c)
			apply(c, st, Vote{Slot: 0x20, VoteID: ns | k, Ballot: b})
			next := apply(c, st, Vote{Slot: 0x21, VoteID: ns | 0x1111, Ballot: b})
			atDepth64(c, next.ProcessSmt[i], "config read proof")
		}
		st := fresh(c)
		first := apply(c, st, Vote{Slot: 0x20, VoteID: ns | keyResults, Ballot: b})
		atDepth64(c, *first.ResultsSmt, "results update of the same batch")
		next := apply(c, st, Vote{Slot: 0x21, VoteID: ns | 0x1111, Ballot: b})
		atDepth64(c, *next.ResultsSmt, "results update")
		sibs, err := st.leafSiblings(keyResults)
		c.Assert(err, qt.IsNil)
		atDepth64(c, davinci.SmtEntry{Siblings: sibs}, "results leaf for the finalize payload")
	})
	t.Run("existing_slot_twin", func(t *testing.T) {
		c := qt.New(t)
		st := fresh(c)
		apply(c, st, Vote{Slot: 0x20, VoteID: ns | 0x1111, Ballot: b})
		apply(c, st, Vote{Slot: 0x21, VoteID: ns | 0x20, Ballot: b})
		over := apply(c, st, Vote{Slot: 0x20, VoteID: ns | 0x2222, Ballot: b})
		atDepth64(c, over.BallotSmt[0], "overwrite of the displaced slot")
	})
	t.Run("same_batch_twin", func(t *testing.T) {
		c := qt.New(t)
		st := fresh(c)
		apply(c, st,
			Vote{Slot: 0x21, VoteID: ns | 0x30, Ballot: b},
			Vote{Slot: 0x30, VoteID: ns | 0x2222, Ballot: b},
		)
		over := apply(c, st, Vote{Slot: 0x30, VoteID: ns | 0x3333, Ballot: b})
		atDepth64(c, over.BallotSmt[0], "overwrite of a slot whose twin came first")
	})
	t.Run("existing_vote_id_twin", func(t *testing.T) {
		c := qt.New(t)
		st := fresh(c)
		apply(c, st, Vote{Slot: 0x21, VoteID: ns | 0x40, Ballot: b})
		apply(c, st, Vote{Slot: 0x40, VoteID: ns | 0x3333, Ballot: b})
		over := apply(c, st, Vote{Slot: 0x40, VoteID: ns | 0x4444, Ballot: b})
		atDepth64(c, over.BallotSmt[0], "overwrite of a slot next to a vote id")
	})
}
