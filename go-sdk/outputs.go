package davinci

import (
	"fmt"
	"math/big"
	"strings"
)

// PublicOutputs holds the public outputs of a ZisK circuit execution,
// matching the on-chain public inputs of davinci-node's StateTransitionCircuit.
//
// These values are extracted from the 46 u32 output registers produced by the
// ZisK prover/emulator. Use ParseOutputs to decode raw register values.
type PublicOutputs struct {
	// OK is true when all circuit checks passed (output[0] == 1).
	OK bool
	// FailMask is a bitfield indicating which checks failed (output[1]).
	// Individual bits correspond to FAIL_* constants.
	FailMask uint32

	// RootHashBefore is the 256-bit Arbo SHA-256 state root before the batch.
	RootHashBefore *big.Int
	// RootHashAfter is the 256-bit Arbo SHA-256 state root after the batch.
	RootHashAfter *big.Int
	// VotersCount is the number of non-dummy votes in this batch.
	VotersCount int
	// OverwrittenVotesCount is the number of votes that overwrote an earlier ballot.
	OverwrittenVotesCount int
	// CensusRoot is the 256-bit lean-IMT Poseidon BN254 census root.
	CensusRoot *big.Int
	// BlobCommitmentLimbs holds the 3 × 128-bit KZG blob commitment limbs.
	BlobCommitmentLimbs [3]*big.Int

	// Diagnostics (not public inputs for on-chain verification)
	BatchOk bool   // Groth16 batch verification passed
	ECDSAOk bool   // ECDSA signature batch passed
	NProofs uint32 // number of Groth16 proofs verified
	NPublic uint32 // public inputs per proof
	LogN    uint32 // log₂ aggregation tree depth
}

// Fail mask bit constants, matching circuit/src/types.rs.
const (
	FailCurve       = 1 << 0   // Groth16 BN254 verification
	FailPairing     = 1 << 1   // BN254 pairing check
	FailECDSA       = 1 << 2   // ECDSA signature verification
	FailSMTVoteID   = 1 << 10  // VoteID chain
	FailSMTBallot   = 1 << 11  // Ballot chain
	FailSMTResults  = 1 << 12  // Results chain
	FailSMTProcess  = 1 << 13  // Process read-proofs
	FailConsistency = 1 << 14  // VoteID/ballot namespace binding
	FailBallotNS    = 1 << 15  // Ballot namespace check
	FailCensus      = 1 << 16  // Census membership proof
	FailReenc       = 1 << 17  // ElGamal re-encryption
	FailKZG         = 1 << 18  // KZG blob evaluation
	FailParse       = 1 << 31  // Input parsing error
)

// ParseOutputs decodes the 46 u32 output registers from the ZisK circuit
// into a structured PublicOutputs.
//
// The outputs slice must have at least 46 elements.
func ParseOutputs(outputs []uint32) (*PublicOutputs, error) {
	if len(outputs) < 46 {
		return nil, fmt.Errorf("expected at least 46 output registers, got %d", len(outputs))
	}

	o := &PublicOutputs{
		OK:                    outputs[OutputOverallOk] == 1,
		FailMask:              outputs[OutputFailMask],
		RootHashBefore:        u32SliceToBigInt(outputs[OutputOldRoot : OutputOldRoot+8]),
		RootHashAfter:         u32SliceToBigInt(outputs[OutputNewRoot : OutputNewRoot+8]),
		VotersCount:           int(outputs[OutputVotersCount]),
		OverwrittenVotesCount: int(outputs[OutputOverwrittenCount]),
		CensusRoot:            u32SliceToBigInt(outputs[OutputCensusRoot : OutputCensusRoot+8]),
		BatchOk:               outputs[OutputBatchOk] == 1,
		ECDSAOk:               outputs[OutputECDSAOk] == 1,
		NProofs:               outputs[OutputNProofs],
		NPublic:               outputs[OutputNPublic],
		LogN:                  outputs[OutputLogN],
	}

	// BlobCommitment: 3 × 128-bit limbs, each stored as 4 × u32 LE.
	for i := 0; i < 3; i++ {
		base := OutputBlobCommitment + i*4
		o.BlobCommitmentLimbs[i] = u32SliceToBigInt(outputs[base : base+4])
	}

	return o, nil
}

// u32SliceToBigInt reconstructs a big.Int from a slice of u32 values in LE order.
// The first element contains the least-significant 32 bits.
func u32SliceToBigInt(words []uint32) *big.Int {
	result := new(big.Int)
	for i := len(words) - 1; i >= 0; i-- {
		result.Lsh(result, 32)
		result.Or(result, new(big.Int).SetUint64(uint64(words[i])))
	}
	return result
}

// ABIEncode packs the public outputs into the uint256[8] ABI encoding used
// by the on-chain state-transition verifier contract.
//
// The layout matches davinci-node's StateTransitionBatchProofInputs.ABIEncode():
//
//	[0] = RootHashBefore
//	[1] = RootHashAfter
//	[2] = VotersCount
//	[3] = OverwrittenVotesCount
//	[4] = CensusRoot
//	[5] = BlobCommitmentLimbs[0]
//	[6] = BlobCommitmentLimbs[1]
//	[7] = BlobCommitmentLimbs[2]
//
// Each value is left-padded to 32 bytes (standard ABI uint256).
// The result is 256 bytes (8 × 32).
func (o *PublicOutputs) ABIEncode() []byte {
	values := [8]*big.Int{
		o.RootHashBefore,
		o.RootHashAfter,
		big.NewInt(int64(o.VotersCount)),
		big.NewInt(int64(o.OverwrittenVotesCount)),
		o.CensusRoot,
		o.BlobCommitmentLimbs[0],
		o.BlobCommitmentLimbs[1],
		o.BlobCommitmentLimbs[2],
	}

	buf := make([]byte, 256) // 8 × 32 bytes
	for i, v := range values {
		if v == nil {
			continue // slot stays zero
		}
		b := v.Bytes()
		offset := i*32 + (32 - len(b))
		if len(b) <= 32 {
			copy(buf[offset:], b)
		} else {
			copy(buf[i*32:], b[len(b)-32:])
		}
	}
	return buf
}

// ABIValues returns the 8 public input values as a [8]*big.Int array,
// suitable for passing directly to go-ethereum ABI encoding.
func (o *PublicOutputs) ABIValues() [8]*big.Int {
	return [8]*big.Int{
		new(big.Int).Set(o.RootHashBefore),
		new(big.Int).Set(o.RootHashAfter),
		big.NewInt(int64(o.VotersCount)),
		big.NewInt(int64(o.OverwrittenVotesCount)),
		new(big.Int).Set(o.CensusRoot),
		new(big.Int).Set(o.BlobCommitmentLimbs[0]),
		new(big.Int).Set(o.BlobCommitmentLimbs[1]),
		new(big.Int).Set(o.BlobCommitmentLimbs[2]),
	}
}

// FailString returns a human-readable description of the fail mask bits.
// Returns "ok" when FailMask is zero.
func (o *PublicOutputs) FailString() string {
	if o.FailMask == 0 {
		return "ok"
	}
	var parts []string
	flags := []struct {
		bit  uint32
		name string
	}{
		{FailCurve, "groth16_curve"},
		{FailPairing, "pairing"},
		{FailECDSA, "ecdsa"},
		{FailSMTVoteID, "smt_voteid"},
		{FailSMTBallot, "smt_ballot"},
		{FailSMTResults, "smt_results"},
		{FailSMTProcess, "smt_process"},
		{FailConsistency, "consistency"},
		{FailBallotNS, "ballot_ns"},
		{FailCensus, "census"},
		{FailReenc, "reencryption"},
		{FailKZG, "kzg"},
		{FailParse, "parse_error"},
	}
	for _, f := range flags {
		if o.FailMask&f.bit != 0 {
			parts = append(parts, f.name)
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("unknown(0x%08x)", o.FailMask)
	}
	return strings.Join(parts, "|")
}

// String returns a one-line summary of the circuit execution result.
func (o *PublicOutputs) String() string {
	status := "PASS"
	if !o.OK {
		status = "FAIL"
	}
	return fmt.Sprintf("%s voters=%d overwrites=%d old_root=0x%x new_root=0x%x fail=%s",
		status, o.VotersCount, o.OverwrittenVotesCount,
		o.RootHashBefore, o.RootHashAfter, o.FailString())
}
