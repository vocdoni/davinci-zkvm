package ballotproof_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	ballotprooftest "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/test/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/types"
)

// TestPublicSignalsMatchCircuit proves one ballot per field count and checks
// that PublicSignals is exactly the circuit's public-signal vector, padded
// fields included.
func TestPublicSignalsMatchCircuit(t *testing.T) {
	if ballotproof.NumberOfPublicInputs != 71 {
		t.Fatalf("NumberOfPublicInputs = %d, want 71", ballotproof.NumberOfPublicInputs)
	}
	key := ballotprooftest.GenDeterministicEncryptionKeyForTest(7)
	pid := types.NewProcessID([20]byte{0xaa, 1, 2}, [4]byte{0, 0, 0, 1}, 9)
	for _, nf := range []uint8{1, 8, 16} {
		mode := spec.BallotMode{NumFields: nf, GroupSize: nf, CostExponent: 1, MaxValue: 7, MaxValueSum: 7 * uint64(nf)}
		var fields []*types.BigInt
		for i := range int(nf) {
			fields = append(fields, types.NewInt(i%7))
		}
		in := &ballotproof.BallotProofInputs{
			ProcessID:     pid,
			Address:       types.HexBytes{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05},
			EncryptionKey: types.SliceOf(key.BigInts(), types.BigIntConverter),
			K:             types.NewInt(12345 + int(nf)),
			BallotMode:    mode,
			Weight:        types.NewInt(3),
			FieldValues:   fields,
		}
		res, err := ballotproof.GenerateBallotProofInputs(in)
		if err != nil {
			t.Fatalf("nf=%d: %v", nf, err)
		}
		raw, err := json.Marshal(res.CircomInputs)
		if err != nil {
			t.Fatal(err)
		}
		_, pubJSON, err := ballotprooftest.CompileAndGenerateProofForTest(raw)
		if err != nil {
			t.Fatalf("nf=%d prove: %v", nf, err)
		}
		var circuit []string
		if err := json.Unmarshal([]byte(pubJSON), &circuit); err != nil {
			t.Fatal(err)
		}
		// res.Ballot is in TE form; PublicSignals takes the gnark form.
		got, err := ballotproof.PublicSignals(pid, mode, key, in.Address, res.VoteID, res.Ballot.FromTEtoRTE(), in.Weight)
		if err != nil {
			t.Fatalf("nf=%d: %v", nf, err)
		}
		if len(got) != len(circuit) {
			t.Fatalf("nf=%d: %d signals, circuit has %d", nf, len(got), len(circuit))
		}
		for i := range got {
			if got[i].String() != circuit[i] {
				t.Errorf("nf=%d signal %d: got %s, circuit %s", nf, i, got[i], circuit[i])
			}
		}
		// Padded fields carry the twisted Edwards identity (0, 1), (0, 1).
		for f := int(nf); f < 16; f++ {
			for j, want := range []int64{0, 1, 0, 1} {
				if got[7+4*f+j].Cmp(big.NewInt(want)) != 0 {
					t.Errorf("nf=%d field %d coord %d = %s, want %d", nf, f, j, got[7+4*f+j], want)
				}
			}
		}
	}
}
