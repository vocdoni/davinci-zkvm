// refresh_test.go covers the silent-revoting host pass in ApplyBatch:
// how many refresh entries land in a batch, that they hit occupied
// slots the batch did not write, and that a refresh preserves the
// ballot's plaintext while changing its stored bytes.
package chain

import (
	"bytes"
	"math/big"
	"sort"
	"testing"

	qt "github.com/frankban/quicktest"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
)

// testEncKeyPair returns a fresh BabyJubJub ElGamal keypair (pub, priv) so
// refresh tests can decrypt individual ciphertexts and confirm the refresh
// preserves the plaintext.
func testEncKeyPair(t *testing.T) (*bjjgnark.BJJ, *big.Int) {
	t.Helper()
	pub, priv, err := elgamal.GenerateKey(bjjgnark.New())
	qt.Assert(t, err, qt.IsNil)
	return pub.(*bjjgnark.BJJ), priv
}

// ballotKey spreads test voters over the slot namespace. ApplyBatch takes
// the slot as given (the guest is what ties it to the census proof), so any
// injective layout works here.
func ballotKey(censusIdx int, addrLo16 uint64) uint64 {
	return ballotMin + uint64(censusIdx)<<16 + addrLo16
}

// decryptField0 decrypts field 0 of the ballot with the election private
// key. Every ballot in these tests is encoded with numFields active, so
// field 0 always carries a real plaintext.
func decryptField0(t *testing.T, encKey *bjjgnark.BJJ, priv *big.Int, b *elgamal.Ballot) uint64 {
	t.Helper()
	_, m, err := elgamal.Decrypt(encKey, priv, b.Ciphertexts[0].C1, b.Ciphertexts[0].C2, maxTallyMsg)
	qt.Assert(t, err, qt.IsNil)
	return m.Uint64()
}

// TestApplyBatchSilentRefreshSampled seeds enough voters that batch 2's
// refresh target is strictly smaller than the candidate set, exercising
// the crypto/rand sampling path. Checks: RefreshSmt has exactly
// RefreshTarget entries, keys are strictly increasing and disjoint from
// the batch's ballot keys, and RefreshedBallots pairs one-to-one with
// RefreshSmt.
func TestApplyBatchSilentRefreshSampled(t *testing.T) {
	c := qt.New(t)
	encKey, priv := testEncKeyPair(t)
	cfg := testConfig(encKey)

	st, err := NewState(cfg)
	c.Assert(err, qt.IsNil)

	// Batch 1: enough voters that the second batch's RefreshTarget
	// (RefreshMin = 16) is strictly less than the candidate pool.
	const initial = 30
	votes1 := make([]Vote, initial)
	for i := 0; i < initial; i++ {
		votes1[i] = vote(i, uint64(100+i), uint64(0x100+i), testBallot(t, encKey, int64(1000+i)))
	}
	_, _, err = st.ApplyBatch(votes1)
	c.Assert(err, qt.IsNil)

	// Snapshot the tree state the second batch will refresh over: keys
	// and their currently stored (already-re-encrypted) ballots, plus
	// each ballot's plaintext for the "decryption unchanged" check.
	oldBallots := make(map[uint64]*elgamal.Ballot, len(st.votedBallots))
	oldPlain := make(map[uint64]uint64, len(st.votedBallots))
	for k, b := range st.votedBallots {
		oldBallots[k] = b
		oldPlain[k] = decryptField0(t, encKey, priv, b)
	}
	occupiedBefore := len(st.votedBallots)
	c.Assert(occupiedBefore, qt.Equals, initial)

	// Batch 2: a single new voter, no overwrite. Sampled refresh path.
	votes2 := []Vote{vote(200, 200, 0x200, testBallot(t, encKey, 5000))}
	std, _, err := st.ApplyBatch(votes2)
	c.Assert(err, qt.IsNil)

	wantTarget := davinci.RefreshTarget(len(votes2), int(std.OverwrittenCount), occupiedBefore)
	c.Assert(wantTarget > 0, qt.IsTrue,
		qt.Commentf("expected non-trivial refresh target, got %d", wantTarget))
	c.Assert(wantTarget < occupiedBefore-int(std.OverwrittenCount), qt.IsTrue,
		qt.Commentf("expected a proper subset, cand=%d target=%d",
			occupiedBefore-int(std.OverwrittenCount), wantTarget))

	// OccupiedBefore is echoed to the STATETX header for the guest and the
	// consumer to check against.
	c.Assert(std.OccupiedBefore, qt.Equals, uint64(occupiedBefore))
	c.Assert(len(std.RefreshSmt), qt.Equals, wantTarget)
	c.Assert(std.BallotProofs, qt.IsNotNil)
	c.Assert(len(std.BallotProofs.RefreshedBallots), qt.Equals, len(std.RefreshSmt))

	// Keys strictly increasing.
	batchKeys := make(map[uint64]struct{}, len(std.BallotSmt))
	for _, e := range std.BallotSmt {
		batchKeys[hexKeyToUint64(t, e.NewKey)] = struct{}{}
	}
	var prev uint64
	refreshedKeys := make([]uint64, 0, len(std.RefreshSmt))
	for i, e := range std.RefreshSmt {
		k := hexKeyToUint64(t, e.NewKey)
		if i > 0 {
			c.Assert(k > prev, qt.IsTrue,
				qt.Commentf("refresh keys not strictly increasing at %d: %#x <= %#x", i, k, prev))
		}
		// Disjoint from ballot keys of this batch.
		_, hit := batchKeys[k]
		c.Assert(hit, qt.IsFalse, qt.Commentf("refresh key %#x collides with batch write", k))
		// Ballot namespace.
		c.Assert(k >= ballotMin, qt.IsTrue, qt.Commentf("refresh key %#x below ballot range", k))
		prev = k
		refreshedKeys = append(refreshedKeys, k)
	}

	// Every refreshed ballot: bytes changed, plaintext unchanged.
	for _, k := range refreshedKeys {
		newBallot, ok := st.votedBallots[k]
		c.Assert(ok, qt.IsTrue, qt.Commentf("key %#x missing after refresh", k))
		old := oldBallots[k]
		c.Assert(bytes.Equal(old.Serialize(), newBallot.Serialize()), qt.IsFalse,
			qt.Commentf("refresh did not change stored ballot at %#x", k))
		gotPlain := decryptField0(t, encKey, priv, newBallot)
		c.Assert(gotPlain, qt.Equals, oldPlain[k],
			qt.Commentf("refresh perturbed plaintext at %#x: %d -> %d", k, oldPlain[k], gotPlain))
	}

	// Ballot bookkeeping unchanged in shape: exactly one insert this batch.
	c.Assert(len(st.votedBallots), qt.Equals, occupiedBefore+len(votes2))
}

// TestApplyBatchSilentRefreshFullChurn covers the small-tree branch where
// the candidate set is smaller than RefreshTarget. Every previously
// occupied slot the batch did not write must be refreshed.
func TestApplyBatchSilentRefreshFullChurn(t *testing.T) {
	c := qt.New(t)
	encKey, _ := testEncKeyPair(t)
	cfg := testConfig(encKey)

	st, err := NewState(cfg)
	c.Assert(err, qt.IsNil)

	// Seed the tree with a handful of voters (well below RefreshMin=16).
	const initial = 5
	votes1 := make([]Vote, initial)
	for i := 0; i < initial; i++ {
		votes1[i] = vote(i, uint64(100+i), uint64(0x100+i), testBallot(t, encKey, int64(2000+i)))
	}
	_, _, err = st.ApplyBatch(votes1)
	c.Assert(err, qt.IsNil)

	// Second batch: overwrite one existing key, no new voter. Expected
	// candidates: the initial-1 keys not overwritten by this batch.
	wroteKey := ballotKey(0, 0x100) // matches votes1[0]
	votes2 := []Vote{vote(0, 300, 0x100, testBallot(t, encKey, 9000))}
	std, _, err := st.ApplyBatch(votes2)
	c.Assert(err, qt.IsNil)

	c.Assert(std.OverwrittenCount, qt.Equals, uint64(1))
	c.Assert(std.OccupiedBefore, qt.Equals, uint64(initial))
	wantTarget := davinci.RefreshTarget(len(votes2), int(std.OverwrittenCount), initial)
	// Every candidate is refreshed: full churn.
	c.Assert(wantTarget, qt.Equals, initial-1)
	c.Assert(len(std.RefreshSmt), qt.Equals, wantTarget)
	c.Assert(len(std.BallotProofs.RefreshedBallots), qt.Equals, len(std.RefreshSmt))

	// The refresh set must be exactly the previously occupied keys minus
	// the one the batch overwrote.
	gotKeys := make([]uint64, 0, len(std.RefreshSmt))
	for _, e := range std.RefreshSmt {
		gotKeys = append(gotKeys, hexKeyToUint64(t, e.NewKey))
	}
	sort.Slice(gotKeys, func(i, j int) bool { return gotKeys[i] < gotKeys[j] })

	wantKeys := make([]uint64, 0, initial-1)
	for i := 0; i < initial; i++ {
		k := ballotKey(i, uint64(0x100+i))
		if k == wroteKey {
			continue
		}
		wantKeys = append(wantKeys, k)
	}
	sort.Slice(wantKeys, func(i, j int) bool { return wantKeys[i] < wantKeys[j] })
	c.Assert(gotKeys, qt.DeepEquals, wantKeys)
}

// hexKeyToUint64 parses a STATETX key (0x-prefixed 32-byte arbo-LE hex)
// back to its uint64 ballot key. Only the low 8 bytes are populated by
// buildArboUpdateEntry — the ballot namespace stays below 2^63.
func hexKeyToUint64(t *testing.T, hexKey string) uint64 {
	t.Helper()
	bi, err := davinci.LeHexToBigInt(hexKey)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, bi.IsUint64(), qt.IsTrue,
		qt.Commentf("ballot key %s does not fit in uint64", hexKey))
	return bi.Uint64()
}
