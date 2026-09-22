package davinci

import (
	"encoding/binary"
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
	// BlobsDigest is SHA-256(com_0 || y_0 || ... || com_{n-1} || y_{n-1})
	// over the DA blobs bound by this transition (32 bytes, zero if the
	// batch shipped no KZG block).
	BlobsDigest [32]byte
	// NBlobs is the number of blobs the guest bound (0..=MaxBlobs).
	NBlobs uint32
	// OccupiedBefore is the batch's claimed count of occupied ballot slots
	// before it ran; it bounds the silent-refresh minimum the guest enforced,
	// so the consumer must check it against its running votes − overwrites.
	OccupiedBefore uint32

	// Diagnostics (not public inputs for on-chain verification)
	BatchOk bool   // Groth16 batch verification passed
	ECDSAOk bool   // ECDSA signature batch passed
	NProofs uint32 // number of Groth16 proofs verified
	NPublic uint32 // public inputs per proof
	LogN    uint32 // log₂ aggregation tree depth
}

// Fail mask bit constants, matching circuit/src/types.rs.
const (
	FailCurve        = 1 << 1  // Groth16 BN254 curve check
	FailPairing      = 1 << 2  // BN254 pairing check
	FailECDSA        = 1 << 3  // ECDSA signature verification
	FailSMTVoteID    = 1 << 10 // VoteID chain
	FailSMTBallot    = 1 << 11 // Ballot chain
	FailSMTResults   = 1 << 12 // Results chain
	FailSMTProcess   = 1 << 13 // Process config proofs
	FailConsistency  = 1 << 14 // VoteID/ballot namespace binding
	FailBallotNS     = 1 << 15 // Ballot namespace check
	FailCensus       = 1 << 16 // Census membership proof
	FailReenc        = 1 << 17 // ElGamal re-encryption
	FailKZG          = 1 << 18 // KZG blob evaluation
	FailMissingBlock = 1 << 19 // Mandatory block absent
	FailResultAccum  = 1 << 20 // Result accumulator mismatch
	FailLeafHash     = 1 << 21 // Ballot SMT leaf hash mismatch
	FailBinding      = 1 << 22 // Cross-block binding mismatch
	FailRefresh      = 1 << 24 // Silent-refresh chain: count, keys, chain or re-randomization
	FailCSP          = 1 << 23 // CSP ECDSA census attestation
	FailParse        = 1 << 31 // Input parsing error
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
		NBlobs:                outputs[OutputNBlobs],
		OccupiedBefore:        outputs[OutputOccupiedBefore],
		BatchOk:               outputs[OutputBatchOk] == 1,
		ECDSAOk:               outputs[OutputECDSAOk] == 1,
		NProofs:               outputs[OutputNProofs],
		NPublic:               outputs[OutputNPublic],
		LogN:                  outputs[OutputLogN],
	}

	// BlobsDigest: 8 × u32 LE at slots [28..35]. Words are LE, so bytes are
	// emitted little-end first — write them into the byte slice in that
	// order so the caller gets the same 32-byte value the guest sha256'd.
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(o.BlobsDigest[i*4:(i+1)*4], outputs[OutputBlobsDigest+i])
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

// ABIEncode packs the parsed public outputs into a uint256[7] ABI encoding
// for Go-side consumers. It is not what DavinciSettlement takes: the
// contract consumes the raw 512-byte publicValues string of the SNARK.
//
// Layout:
//
//	[0] = RootHashBefore
//	[1] = RootHashAfter
//	[2] = VotersCount
//	[3] = OverwrittenVotesCount
//	[4] = CensusRoot
//	[5] = BlobsDigest    (SHA-256 over ordered (commitment, y) pairs)
//	[6] = NBlobs
//
// Each value is left-padded to 32 bytes (standard ABI uint256). The result
// is 224 bytes (7 × 32).
func (o *PublicOutputs) ABIEncode() []byte {
	values := o.ABIValues()
	buf := make([]byte, len(values)*32)
	for i, v := range values {
		if v != nil {
			// FillBytes zero-extends v into the slot; panics if it overflows
			// uint256, which is a caller bug worth surfacing loudly.
			v.FillBytes(buf[i*32 : (i+1)*32])
		}
	}
	return buf
}

// ABIValues returns the 7 public input values as a [7]*big.Int array,
// suitable for passing directly to go-ethereum ABI encoding.
// Nil fields become zero.
func (o *PublicOutputs) ABIValues() [7]*big.Int {
	set := func(v *big.Int) *big.Int {
		if v == nil {
			return new(big.Int)
		}
		return new(big.Int).Set(v)
	}
	return [7]*big.Int{
		set(o.RootHashBefore),
		set(o.RootHashAfter),
		big.NewInt(int64(o.VotersCount)),
		big.NewInt(int64(o.OverwrittenVotesCount)),
		set(o.CensusRoot),
		new(big.Int).SetBytes(o.BlobsDigest[:]),
		new(big.Int).SetUint64(uint64(o.NBlobs)),
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
		{FailMissingBlock, "missing_block"},
		{FailResultAccum, "result_accum"},
		{FailLeafHash, "leaf_hash"},
		{FailBinding, "binding"},
		{FailCSP, "csp"},
		{FailRefresh, "refresh"},
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
