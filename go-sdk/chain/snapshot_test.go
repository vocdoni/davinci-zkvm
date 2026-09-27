package chain

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/fxamacker/cbor/v2"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec/params"
)

// testEncKey returns a fresh BabyJubJub ElGamal key pair for tests.
func testEncKey(t *testing.T) *bjjgnark.BJJ {
	t.Helper()
	pub, _, err := elgamal.GenerateKey(bjjgnark.New())
	qt.Assert(t, err, qt.IsNil)
	return pub.(*bjjgnark.BJJ)
}

// testBallot encrypts eight small values under encKey, producing a valid
// ballot ready for state application.
func testBallot(t *testing.T, encKey *bjjgnark.BJJ, seed int64) *elgamal.Ballot {
	t.Helper()
	var msg [params.FieldsPerBallot]*big.Int
	for i := range msg {
		msg[i] = big.NewInt(seed + int64(i))
	}
	b, err := elgamal.NewBallot(encKey).Encrypt(msg, encKey, big.NewInt(seed+1))
	qt.Assert(t, err, qt.IsNil)
	return b
}

func testConfig(encKey *bjjgnark.BJJ) Config {
	return Config{
		ProcessID:    big.NewInt(0xabcdef),
		BallotMode:   big.NewInt(0x01),
		EncKey:       encKey,
		CensusOrigin: 1,
		CensusRoot:   big.NewInt(0x1234),
		BallotVKHash: big.NewInt(0x77),
	}
}

func vote(censusIdx int, voteID, addrLo uint64, b *elgamal.Ballot) Vote {
	return Vote{
		Slot:   ballotKey(censusIdx, addrLo),
		VoteID: voteID | (uint64(1) << 63),
		Ballot: b,
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	c := qt.New(t)
	encKey := testEncKey(t)
	cfg := testConfig(encKey)

	st, err := NewState(cfg)
	c.Assert(err, qt.IsNil)

	// Batch 1: three first-time voters.
	_, _, err = st.ApplyBatch([]Vote{
		vote(0, 1, 0x01, testBallot(t, encKey, 10)),
		vote(1, 2, 0x02, testBallot(t, encKey, 20)),
		vote(2, 3, 0x03, testBallot(t, encKey, 30)),
	})
	c.Assert(err, qt.IsNil)

	// Batch 2: one overwrite (census idx 1) plus one new voter.
	_, _, err = st.ApplyBatch([]Vote{
		vote(1, 4, 0x02, testBallot(t, encKey, 40)),
		vote(3, 5, 0x04, testBallot(t, encKey, 50)),
	})
	c.Assert(err, qt.IsNil)

	wantRoot := st.Root()
	wantVoters, wantOverwrites := st.Voters()
	c.Assert(wantVoters, qt.Equals, uint64(5))
	c.Assert(wantOverwrites, qt.Equals, uint64(1))

	blob, err := st.Snapshot()
	c.Assert(err, qt.IsNil)
	c.Assert(len(blob) > 0, qt.IsTrue)

	st2, err := RestoreState(cfg, blob)
	c.Assert(err, qt.IsNil)

	// Restore reproduces root and counters exactly.
	c.Assert(st2.Root(), qt.Equals, wantRoot)
	gotVoters, gotOverwrites := st2.Voters()
	c.Assert(gotVoters, qt.Equals, wantVoters)
	c.Assert(gotOverwrites, qt.Equals, wantOverwrites)

	// The restored state is re-drivable: a further batch builds on the
	// restored root (its OldStateRoot must equal the snapshot root) and the
	// overwrite bookkeeping (votedBallots) survived the round trip.
	std, _, err := st2.ApplyBatch([]Vote{
		vote(0, 6, 0x01, testBallot(t, encKey, 60)), // overwrite idx 0 from batch 1
		vote(4, 7, 0x05, testBallot(t, encKey, 70)),
	})
	c.Assert(err, qt.IsNil)
	c.Assert(std.OldStateRoot, qt.Equals, wantRoot)
	c.Assert(std.OverwrittenCount, qt.Equals, uint64(1))
	c.Assert(st2.Root() != wantRoot, qt.IsTrue)

	// Re-snapshotting the restored+advanced state and restoring again is
	// stable (idempotent root).
	blob2, err := st2.Snapshot()
	c.Assert(err, qt.IsNil)
	st3, err := RestoreState(cfg, blob2)
	c.Assert(err, qt.IsNil)
	c.Assert(st3.Root(), qt.Equals, st2.Root())
}

func TestRestoreStateRejectsCorruptSnapshot(t *testing.T) {
	c := qt.New(t)
	encKey := testEncKey(t)
	cfg := testConfig(encKey)
	st, err := NewState(cfg)
	c.Assert(err, qt.IsNil)
	_, _, err = st.ApplyBatch([]Vote{vote(0, 1, 0x01, testBallot(t, encKey, 10))})
	c.Assert(err, qt.IsNil)
	blob, err := st.Snapshot()
	c.Assert(err, qt.IsNil)

	tamper := func(mutate func(*stateSnapshot)) error {
		var snap stateSnapshot
		c.Assert(cbor.Unmarshal(blob, &snap), qt.IsNil)
		mutate(&snap)
		b, err := cbor.Marshal(snap)
		c.Assert(err, qt.IsNil)
		_, err = RestoreState(cfg, b)
		return err
	}

	// Coordinate outside the field.
	err = tamper(func(s *stateSnapshot) { s.Results[0] = bn254ScalarField.Bytes() })
	c.Assert(err, qt.ErrorMatches, ".*not in field.*")

	// Off-curve point: x replaced, y kept.
	err = tamper(func(s *stateSnapshot) { s.Results[0] = big.NewInt(12345).Bytes() })
	c.Assert(err, qt.ErrorMatches, ".*not on BabyJubJub.*")

	// Oversize coordinate encoding.
	err = tamper(func(s *stateSnapshot) { s.Results[0] = make([]byte, 33) })
	c.Assert(err, qt.ErrorMatches, ".*want <= 32.*")

	// Restore under a different election config must be rejected.
	cfg2 := cfg
	cfg2.ProcessID = big.NewInt(0x999)
	_, err = RestoreState(cfg2, blob)
	c.Assert(err, qt.ErrorMatches, ".*config leaf 0x00 mismatch.*")
}

func TestApplyBatchValidation(t *testing.T) {
	c := qt.New(t)
	encKey := testEncKey(t)
	st, err := NewState(testConfig(encKey))
	c.Assert(err, qt.IsNil)
	b := testBallot(t, encKey, 10)

	_, _, err = st.ApplyBatch(make([]Vote, davinci.MaxBatchSize+1))
	c.Assert(err, qt.ErrorMatches, ".*exceeds MaxBatchSize.*")

	_, _, err = st.ApplyBatch([]Vote{{Slot: davinci.VoteIDMin, VoteID: 1 | 1<<63, Ballot: b}})
	c.Assert(err, qt.ErrorMatches, ".*outside the ballot namespace.*")

	_, _, err = st.ApplyBatch([]Vote{{Slot: 0x04, VoteID: 1 | 1<<63, Ballot: b}})
	c.Assert(err, qt.ErrorMatches, ".*outside the ballot namespace.*")

	_, _, err = st.ApplyBatch([]Vote{
		{Slot: 0x20, VoteID: 1 | 1<<63, Ballot: b},
		{Slot: 0x20, VoteID: 2 | 1<<63, Ballot: b},
	})
	c.Assert(err, qt.ErrorMatches, ".*already written by vote\\[0\\].*")

	// Rejected batches leave the state untouched.
	voters, overwrites := st.Voters()
	c.Assert(voters, qt.Equals, uint64(0))
	c.Assert(overwrites, qt.Equals, uint64(0))
}

func TestNewStateNumFieldsBounds(t *testing.T) {
	c := qt.New(t)
	encKey := testEncKey(t)
	for _, mode := range []int64{0x00, 0x11} { // num_fields 0 and 17
		cfg := testConfig(encKey)
		cfg.BallotMode = big.NewInt(mode)
		_, err := NewState(cfg)
		c.Assert(err, qt.IsNotNil, qt.Commentf("BallotMode %#x", mode))
	}
}
