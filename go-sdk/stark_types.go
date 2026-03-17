package davinci

import (
	"encoding/binary"
	"fmt"
)

const (
	StarkInputsHashLimbs      = 4
	StarkAddressLimbs         = 4
	StarkInputsPreimageLimbs  = 114
	StarkPublicValueCount     = StarkInputsHashLimbs + StarkAddressLimbs + 1 + StarkInputsPreimageLimbs
	StarkPublicValueBytes     = StarkPublicValueCount * 8
	StarkInputsHashOffset     = 0
	StarkAddressOffset        = 4
	StarkVoteIDOffset         = 8
	StarkInputsPreimageOffset = 9
)

// StarkPublicValues is the canonical public statement exposed by davinci-stark.
type StarkPublicValues struct {
	InputsHash     [StarkInputsHashLimbs]uint64
	Address        [StarkAddressLimbs]uint64
	VoteID         uint64
	InputsPreimage [StarkInputsPreimageLimbs]uint64
}

// StarkProofBundle is the davinci-stark WASM wire format split into proof bytes and decoded public values.
type StarkProofBundle struct {
	ProofBytes   []byte
	PublicValues StarkPublicValues
}

// DecodeStarkPublicValues decodes the raw u64-LE davinci-stark public-value blob.
func DecodeStarkPublicValues(raw []byte) (StarkPublicValues, error) {
	var pv StarkPublicValues
	if len(raw) != StarkPublicValueBytes {
		return pv, fmt.Errorf("invalid stark public value length: got %d, want %d", len(raw), StarkPublicValueBytes)
	}
	for i := 0; i < StarkInputsHashLimbs; i++ {
		pv.InputsHash[i] = binary.LittleEndian.Uint64(raw[(StarkInputsHashOffset+i)*8:])
	}
	for i := 0; i < StarkAddressLimbs; i++ {
		pv.Address[i] = binary.LittleEndian.Uint64(raw[(StarkAddressOffset+i)*8:])
	}
	pv.VoteID = binary.LittleEndian.Uint64(raw[StarkVoteIDOffset*8:])
	for i := 0; i < StarkInputsPreimageLimbs; i++ {
		pv.InputsPreimage[i] = binary.LittleEndian.Uint64(raw[(StarkInputsPreimageOffset+i)*8:])
	}
	return pv, nil
}

// Encode serializes the canonical davinci-stark public statement as u64-LE bytes.
func (pv StarkPublicValues) Encode() []byte {
	out := make([]byte, StarkPublicValueBytes)
	for i, v := range pv.InputsHash {
		binary.LittleEndian.PutUint64(out[(StarkInputsHashOffset+i)*8:], v)
	}
	for i, v := range pv.Address {
		binary.LittleEndian.PutUint64(out[(StarkAddressOffset+i)*8:], v)
	}
	binary.LittleEndian.PutUint64(out[StarkVoteIDOffset*8:], pv.VoteID)
	for i, v := range pv.InputsPreimage {
		binary.LittleEndian.PutUint64(out[(StarkInputsPreimageOffset+i)*8:], v)
	}
	return out
}

// DecodeStarkProofBundle decodes the davinci-stark WASM wire format.
func DecodeStarkProofBundle(raw []byte) (*StarkProofBundle, error) {
	if len(raw) < 4 {
		return nil, fmt.Errorf("stark proof blob too short")
	}
	proofLen := int(binary.LittleEndian.Uint32(raw[:4]))
	if len(raw) != 4+proofLen+StarkPublicValueBytes {
		return nil, fmt.Errorf("invalid stark proof blob length: got %d, want %d", len(raw), 4+proofLen+StarkPublicValueBytes)
	}
	pv, err := DecodeStarkPublicValues(raw[4+proofLen:])
	if err != nil {
		return nil, err
	}
	proofBytes := make([]byte, proofLen)
	copy(proofBytes, raw[4:4+proofLen])
	return &StarkProofBundle{ProofBytes: proofBytes, PublicValues: pv}, nil
}

// ProcessID returns the 4-limb process identifier from the public preimage.
func (pv StarkPublicValues) ProcessID() [4]uint64 {
	var out [4]uint64
	copy(out[:], pv.InputsPreimage[0:4])
	return out
}

// PackedBallotMode returns the 4-limb packed ballot configuration from the public preimage.
func (pv StarkPublicValues) PackedBallotMode() [4]uint64 {
	var out [4]uint64
	copy(out[:], pv.InputsPreimage[4:8])
	return out
}

// ElectionPublicKeyEncoding returns the 20-limb ecgfp5 public-key encoding from the public preimage.
func (pv StarkPublicValues) ElectionPublicKeyEncoding() [20]uint64 {
	var out [20]uint64
	copy(out[:], pv.InputsPreimage[8:28])
	return out
}

// CiphertextEncodings returns the 16 encoded ciphertext limbs in public-preimage order.
func (pv StarkPublicValues) CiphertextEncodings() [16][5]uint64 {
	var out [16][5]uint64
	base := 33
	for i := 0; i < 16; i++ {
		copy(out[i][:], pv.InputsPreimage[base+i*5:base+(i+1)*5])
	}
	return out
}

// Weight returns the final weight limb from the public preimage.
func (pv StarkPublicValues) Weight() uint64 {
	return pv.InputsPreimage[113]
}
