package davinci

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// stateMagic is "STATETX!" as a little-endian uint64 (matches circuit/src/types.rs STATE_MAGIC).
var stateMagic = []byte("STATETX!")

// EncodeStateBlock serializes a StateTransitionData into the STATETX binary block
// that must be appended after the ECDSA block in the ZisK input.
//
// The returned bytes are ready to append to the output of EncodeInput / generate_input.
// Returns an error if any hex field is malformed or sibling counts are inconsistent.
func EncodeStateBlock(sd *StateTransitionData) ([]byte, error) {
	if sd == nil {
		return nil, nil
	}
	var buf []byte

	// Magic
	buf = append(buf, stateMagic...)

	// Metadata
	buf = appendU64(buf, sd.VotersCount)
	buf = appendU64(buf, sd.OverwrittenCount)

	// Process ID, old/new roots
	for _, field := range []string{sd.ProcessID, sd.OldStateRoot, sd.NewStateRoot} {
		fr, err := leHexToFr(field)
		if err != nil {
			return nil, fmt.Errorf("state field: %w", err)
		}
		buf = appendFr(buf, fr)
	}

	// VoteID chain
	chain, err := encodeSMTChain(sd.VoteIDSmt)
	if err != nil {
		return nil, fmt.Errorf("vote_id_smt: %w", err)
	}
	buf = append(buf, chain...)

	// Ballot chain
	chain, err = encodeSMTChain(sd.BallotSmt)
	if err != nil {
		return nil, fmt.Errorf("ballot_smt: %w", err)
	}
	buf = append(buf, chain...)

	// ResultsAdd (0 or 1)
	resultsNLevels := 0
	if sd.ResultsAddSmt != nil {
		resultsNLevels = len(sd.ResultsAddSmt.Siblings)
	} else if sd.ResultsSubSmt != nil {
		resultsNLevels = len(sd.ResultsSubSmt.Siblings)
	}
	buf = appendU64(buf, boolToU64(sd.ResultsAddSmt != nil))
	buf = appendU64(buf, uint64(resultsNLevels))
	if sd.ResultsAddSmt != nil {
		e, err := encodeSMTEntry(*sd.ResultsAddSmt)
		if err != nil {
			return nil, fmt.Errorf("results_add_smt: %w", err)
		}
		buf = append(buf, e...)
	}

	// ResultsSub (0 or 1, same n_levels)
	buf = appendU64(buf, boolToU64(sd.ResultsSubSmt != nil))
	if sd.ResultsSubSmt != nil {
		e, err := encodeSMTEntry(*sd.ResultsSubSmt)
		if err != nil {
			return nil, fmt.Errorf("results_sub_smt: %w", err)
		}
		buf = append(buf, e...)
	}

	// Process read-proofs: write n (0 or 4), then n_levels + entries only when n>0.
	if len(sd.ProcessSmt) != 0 && len(sd.ProcessSmt) != 4 {
		return nil, fmt.Errorf("process_smt must have 0 or 4 entries, got %d", len(sd.ProcessSmt))
	}
	buf = appendU64(buf, uint64(len(sd.ProcessSmt))) // 0 or 4
	if len(sd.ProcessSmt) > 0 {
		procNLevels := len(sd.ProcessSmt[0].Siblings)
		buf = appendU64(buf, uint64(procNLevels))
		for i, p := range sd.ProcessSmt {
			e, err := encodeSMTEntry(p)
			if err != nil {
				return nil, fmt.Errorf("process_smt[%d]: %w", i, err)
			}
			buf = append(buf, e...)
		}
	}

	return buf, nil
}

// encodeSMTChain writes: n(u64) + n_levels(u64) + entries.
func encodeSMTChain(entries []SmtEntry) ([]byte, error) {
	var buf []byte
	nLevels := 0
	if len(entries) > 0 {
		nLevels = len(entries[0].Siblings)
	}
	buf = appendU64(buf, uint64(len(entries)))
	buf = appendU64(buf, uint64(nLevels))
	for i, e := range entries {
		if len(e.Siblings) != nLevels {
			return nil, fmt.Errorf("entry %d has %d siblings, expected %d", i, len(e.Siblings), nLevels)
		}
		body, err := encodeSMTEntry(e)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		buf = append(buf, body...)
	}
	return buf, nil
}

// encodeSMTEntry serializes one SmtEntry body (no length prefix).
func encodeSMTEntry(e SmtEntry) ([]byte, error) {
	var buf []byte
	for _, field := range []string{e.OldRoot, e.NewRoot, e.OldKey, e.OldValue} {
		fr, err := leHexToFr(field)
		if err != nil {
			return nil, err
		}
		buf = appendFr(buf, fr)
	}
	buf = appendU64(buf, uint64(e.IsOld0))
	for _, field := range []string{e.NewKey, e.NewValue} {
		fr, err := leHexToFr(field)
		if err != nil {
			return nil, err
		}
		buf = appendFr(buf, fr)
	}
	buf = appendU64(buf, uint64(e.Fnc0))
	buf = appendU64(buf, uint64(e.Fnc1))
	for _, sib := range e.Siblings {
		fr, err := leHexToFr(sib)
		if err != nil {
			return nil, fmt.Errorf("sibling: %w", err)
		}
		buf = appendFr(buf, fr)
	}
	return buf, nil
}

// zeroSMTEntry returns a zero-filled SMT entry binary (for padding).
func zeroSMTEntry(nLevels int) []byte {
	// 4 FrRaw (32 bytes each) + 5 u64 + nLevels FrRaw
	size := 4*32 + 5*8 + nLevels*32
	return make([]byte, size)
}

// leHexToFr parses a 0x-prefixed 32-byte little-endian hex string
// into 4 little-endian u64 words ([4]uint64, stored as 32 bytes LE).
func leHexToFr(s string) ([4]uint64, error) {
	var out [4]uint64
	h := strings.TrimPrefix(s, "0x")
	if len(h) == 0 {
		return out, nil // zero value
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return out, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d: %q", len(b), s)
	}
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(b[i*8 : i*8+8])
	}
	return out, nil
}

// appendFr appends a [4]uint64 as 4 × 8 little-endian bytes.
func appendFr(buf []byte, fr [4]uint64) []byte {
	var tmp [8]byte
	for _, w := range fr {
		binary.LittleEndian.PutUint64(tmp[:], w)
		buf = append(buf, tmp[:]...)
	}
	return buf
}

// appendU64 appends a uint64 as 8 little-endian bytes.
func appendU64(buf []byte, v uint64) []byte {
	var tmp [8]byte
	binary.LittleEndian.PutUint64(tmp[:], v)
	return append(buf, tmp[:]...)
}

func boolToU64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}

// censusMagic is "CENSUS!!" in little-endian.
var censusMagic = [8]byte{'C', 'E', 'N', 'S', 'U', 'S', '!', '!'}

// beHexToFrLE converts a 0x-prefixed big-endian hex string (e.g. from *big.Int)
// to a [4]uint64 little-endian circuit word representation.
// The census data comes from Go's math/big which uses big-endian byte order.
func beHexToFrLE(s string) ([4]uint64, error) {
	h := strings.TrimPrefix(s, "0x")
	if len(h) < 64 {
		h = strings.Repeat("0", 64-len(h)) + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return [4]uint64{}, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	if len(b) != 32 {
		return [4]uint64{}, fmt.Errorf("expected 32 bytes, got %d: %q", len(b), s)
	}
	// b is big-endian bytes [b31, b30, ..., b0]; convert to LE u64 limbs.
	var out [4]uint64
	for i := 0; i < 4; i++ {
		// limb i = bytes[(3-i)*8 .. (4-i)*8] interpreted as big-endian
		out[i] = binary.BigEndian.Uint64(b[(3-i)*8 : (4-i)*8])
	}
	return out, nil
}

// EncodeCensusBlock serializes a slice of CensusProof into the CENSUS binary block.
//
// CensusProof.Root, Leaf, and Siblings must be 32-byte big-endian hex strings
// (0x-prefixed), matching the output of math/big.Int.Bytes().
//
// Format:
//
//	magic:    u64 = "CENSUS!!"
//	n_proofs: u64
//	Per proof:
//	  root:       [u64; 4]  (LE limbs)
//	  leaf:       [u64; 4]
//	  index:      u64
//	  n_siblings: u64
//	  siblings:   [[u64; 4]; n_siblings]
func EncodeCensusBlock(proofs []CensusProof) ([]byte, error) {
	if len(proofs) == 0 {
		return nil, nil
	}
	buf := append([]byte{}, censusMagic[:]...)
	buf = appendU64(buf, uint64(len(proofs)))
	for _, p := range proofs {
		root, err := beHexToFrLE(p.Root)
		if err != nil {
			return nil, fmt.Errorf("census root: %w", err)
		}
		leaf, err := beHexToFrLE(p.Leaf)
		if err != nil {
			return nil, fmt.Errorf("census leaf: %w", err)
		}
		buf = appendFr(buf, root)
		buf = appendFr(buf, leaf)
		buf = appendU64(buf, p.Index)
		buf = appendU64(buf, uint64(len(p.Siblings)))
		for _, s := range p.Siblings {
			sib, err := beHexToFrLE(s)
			if err != nil {
				return nil, fmt.Errorf("census sibling: %w", err)
			}
			buf = appendFr(buf, sib)
		}
	}
	return buf, nil
}

// EncodeReencBlock serialises the REENCBLK for the ZisK circuit.
// Magic = "REENCBLK" (8 bytes LE u64), followed by n_voters, pub_key_x/y,
// then per-voter: k, then 8×(c1x,c1y,c2x,c2y) original, 8×(c1x,c1y,c2x,c2y) reencrypted.
func EncodeReencBlock(r *ReencryptionData) ([]byte, error) {
if r == nil || len(r.Entries) == 0 {
return nil, nil
}
const magic = uint64(0x4b4c434e45455200) // "REENCBLK" LE bytes -> magic value

// Build magic as literal bytes matching the Rust b"REENCBLK" interpretation
magicBytes := []byte("REENCBLK")
var magicU64 uint64
for i := 0; i < 8; i++ {
magicU64 |= uint64(magicBytes[i]) << (8 * i)
}
_ = magic

pKeyX, err := beHexToFrLE(r.EncryptionKeyX)
if err != nil {
return nil, fmt.Errorf("reenc pub_key_x: %w", err)
}
pKeyY, err := beHexToFrLE(r.EncryptionKeyY)
if err != nil {
return nil, fmt.Errorf("reenc pub_key_y: %w", err)
}

buf := appendU64(nil, magicU64)
buf = appendU64(buf, uint64(len(r.Entries)))
buf = appendFr(buf, pKeyX)
buf = appendFr(buf, pKeyY)

for i, entry := range r.Entries {
k, err := beHexToFrLE(entry.K)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] k: %w", i, err)
}
buf = appendFr(buf, k)

for j, ct := range entry.Original {
c1x, err := beHexToFrLE(ct.C1.X)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] original[%d] c1x: %w", i, j, err)
}
c1y, err := beHexToFrLE(ct.C1.Y)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] original[%d] c1y: %w", i, j, err)
}
c2x, err := beHexToFrLE(ct.C2.X)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] original[%d] c2x: %w", i, j, err)
}
c2y, err := beHexToFrLE(ct.C2.Y)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] original[%d] c2y: %w", i, j, err)
}
buf = appendFr(buf, c1x)
buf = appendFr(buf, c1y)
buf = appendFr(buf, c2x)
buf = appendFr(buf, c2y)
}
for j, ct := range entry.Reencrypted {
c1x, err := beHexToFrLE(ct.C1.X)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] reencrypted[%d] c1x: %w", i, j, err)
}
c1y, err := beHexToFrLE(ct.C1.Y)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] reencrypted[%d] c1y: %w", i, j, err)
}
c2x, err := beHexToFrLE(ct.C2.X)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] reencrypted[%d] c2x: %w", i, j, err)
}
c2y, err := beHexToFrLE(ct.C2.Y)
if err != nil {
return nil, fmt.Errorf("reenc entry[%d] reencrypted[%d] c2y: %w", i, j, err)
}
buf = appendFr(buf, c1x)
buf = appendFr(buf, c1y)
buf = appendFr(buf, c2x)
buf = appendFr(buf, c2y)
}
}
return buf, nil
}
