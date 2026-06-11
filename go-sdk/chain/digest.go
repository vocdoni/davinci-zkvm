// Package chain implements the sequencer side of the chained (fully
// ZisK-verified) election mode: the process state tree, batch assembly,
// fold cadence and finalize orchestration over the davinci-zkvm service,
// plus parsing of the aggregator public digest and the external
// vk-binding checks that complete the proof's soundness argument.
package chain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Aggregator digest modes (word [1]).
const (
	ModeFold     = 1
	ModeFinalize = 2
)

// digestWords is the number of u32 words in the aggregator public digest.
const digestWords = 53

// Digest is the parsed aggregator public digest: 53 little-endian u32
// words committed by the circuit-aggregator guest.
type Digest struct {
	Mode uint32
	// StepCount is the number of fold steps; one fold may cover
	// several batch proofs.
	StepCount        uint32
	TotalVoters      uint32
	TotalOverwrites  uint32
	ConfigCommitment []byte // 32 bytes
	StateRoot        []byte // 32 bytes, arbo LE
	BatchVK          string // 0x-prefixed BE hex
	FoldVK           string // 0x-prefixed BE hex
	Results          [8]uint64
}

// ParseDigest decodes the public values blob of a fold or finalize job.
func ParseDigest(publics []byte) (*Digest, error) {
	if len(publics) < digestWords*4 {
		return nil, fmt.Errorf("publics too short: %d bytes, want >= %d", len(publics), digestWords*4)
	}
	if string(publics[0:4]) != "DAG1" {
		return nil, fmt.Errorf("bad digest magic: %x", publics[0:4])
	}
	w := func(i int) uint32 { return binary.LittleEndian.Uint32(publics[i*4:]) }
	vkHex := func(off int) string {
		b := make([]byte, 32)
		for i := 0; i < 4; i++ {
			v := uint64(w(off+i*2)) | uint64(w(off+i*2+1))<<32
			binary.BigEndian.PutUint64(b[i*8:], v)
		}
		return "0x" + hex.EncodeToString(b)
	}
	d := &Digest{
		Mode:             w(1),
		StepCount:        w(2),
		TotalVoters:      w(3),
		TotalOverwrites:  w(4),
		ConfigCommitment: publics[5*4 : 13*4],
		StateRoot:        publics[13*4 : 21*4],
		BatchVK:          vkHex(21),
		FoldVK:           vkHex(29),
	}
	for i := 0; i < 8; i++ {
		d.Results[i] = uint64(w(37+i*2)) | uint64(w(37+i*2+1))<<32
	}
	return d, nil
}

// VerifyBinding performs the external vk-binding checks that close the
// self-recursion loop. After the final proof verifies, the verifier must
// also assert that the fold_vk the chain committed to equals the
// program_vk the proof itself verifies under, and that the committed
// batch_vk equals the known vote-batch circuit vk.
func (d *Digest) VerifyBinding(proofProgramVK, expectedBatchVK string) error {
	if d.FoldVK != proofProgramVK {
		return fmt.Errorf("fold_vk binding: digest commits %s but proof program_vk is %s",
			d.FoldVK, proofProgramVK)
	}
	if d.BatchVK != expectedBatchVK {
		return fmt.Errorf("batch_vk binding: digest commits %s, want %s",
			d.BatchVK, expectedBatchVK)
	}
	return nil
}

// StateRootHex returns the digest state root as 0x-prefixed arbo LE hex,
// the same encoding State.Root uses.
func (d *Digest) StateRootHex() string {
	return "0x" + hex.EncodeToString(d.StateRoot)
}

// SameChain reports whether o belongs to the same proof chain: identical
// config commitment and vk pair.
func (d *Digest) SameChain(o *Digest) bool {
	return bytes.Equal(d.ConfigCommitment, o.ConfigCommitment) &&
		d.BatchVK == o.BatchVK && d.FoldVK == o.FoldVK
}
