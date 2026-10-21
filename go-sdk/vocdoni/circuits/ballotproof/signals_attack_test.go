package ballotproof_test

import (
	"testing"

	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	ballotprooftest "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/test/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/types"
)

// BUG: PublicSignals returns signals for a ballot whose fields at or above numFields are not the identity; the guest derives the identity there, so those signals match no batch (TS and the node refuse the ballot).
func TestPublicSignalsRefusesNonIdentityPadding(t *testing.T) {
	key := ballotprooftest.GenDeterministicEncryptionKeyForTest(7)
	pid := types.NewProcessID([20]byte{0xaa, 1, 2}, [4]byte{0, 0, 0, 1}, 9)
	addr := types.HexBytes{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05}
	for _, nf := range []uint8{1, 3, 15} {
		mode := spec.BallotMode{NumFields: nf, GroupSize: nf, CostExponent: 1, MaxValue: 7, MaxValueSum: 7 * uint64(nf)}
		in := &ballotproof.BallotProofInputs{
			ProcessID: pid, Address: addr,
			EncryptionKey: types.SliceOf(key.BigInts(), types.BigIntConverter),
			K:             types.NewInt(777 + int(nf)), BallotMode: mode, Weight: types.NewInt(3),
		}
		res, err := ballotproof.GenerateBallotProofInputs(in)
		if err != nil {
			t.Fatalf("nf=%d: %v", nf, err)
		}
		honest := res.Ballot.FromTEtoRTE()
		if _, err := ballotproof.PublicSignals(pid, mode, key, addr, res.VoteID, honest, in.Weight); err != nil {
			t.Fatalf("nf=%d honest ballot: %v", nf, err)
		}
		for _, f := range []int{int(nf), 15} {
			bad := honest.FromRTEtoTE().FromTEtoRTE() // a copy
			bad.Ciphertexts[f] = &elgamal.Ciphertext{C1: honest.Ciphertexts[0].C1, C2: honest.Ciphertexts[0].C2}
			if _, err := ballotproof.PublicSignals(pid, mode, key, addr, res.VoteID, bad, in.Weight); err == nil {
				t.Errorf("nf=%d: field %d not the identity, want an error", nf, f)
			}
		}
	}
}
