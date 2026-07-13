package chain

import (
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/spec/params"
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
		CensusIdx:   censusIdx,
		VoteID:      voteID | (uint64(1) << 63),
		AddressLo16: addrLo,
		Ballot:      b,
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
