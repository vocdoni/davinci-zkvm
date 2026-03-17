package davinci

import (
	"encoding/binary"
	"testing"
)

func TestStarkPublicValuesRoundTrip(t *testing.T) {
	var pv StarkPublicValues
	for i := range pv.InputsHash {
		pv.InputsHash[i] = uint64(i + 1)
	}
	for i := range pv.Address {
		pv.Address[i] = uint64(10 + i)
	}
	pv.VoteID = 42
	for i := range pv.InputsPreimage {
		pv.InputsPreimage[i] = uint64(100 + i)
	}
	decoded, err := DecodeStarkPublicValues(pv.Encode())
	if err != nil {
		t.Fatalf("DecodeStarkPublicValues failed: %v", err)
	}
	if decoded != pv {
		t.Fatalf("public values mismatch\n got: %#v\nwant: %#v", decoded, pv)
	}
}

func TestDecodeStarkProofBundle(t *testing.T) {
	var pv StarkPublicValues
	pv.VoteID = 99
	proof := []byte{1, 2, 3, 4, 5}
	blob := make([]byte, 4+len(proof)+StarkPublicValueBytes)
	binary.LittleEndian.PutUint32(blob[:4], uint32(len(proof)))
	copy(blob[4:], proof)
	copy(blob[4+len(proof):], pv.Encode())
	bundle, err := DecodeStarkProofBundle(blob)
	if err != nil {
		t.Fatalf("DecodeStarkProofBundle failed: %v", err)
	}
	if bundle.PublicValues.VoteID != pv.VoteID {
		t.Fatalf("VoteID = %d, want %d", bundle.PublicValues.VoteID, pv.VoteID)
	}
	if len(bundle.ProofBytes) != len(proof) {
		t.Fatalf("proof length = %d, want %d", len(bundle.ProofBytes), len(proof))
	}
}
