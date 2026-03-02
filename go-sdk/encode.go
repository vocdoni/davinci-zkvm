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

	// Result accumulator ballot data
	if sd.BallotProofs != nil {
		bp := sd.BallotProofs
		buf = appendU64(buf, 1) // has_ballot_data = true

		// OldResultsAdd: 32 Fr elements
		if len(bp.OldResultsAdd) != 32 {
			return nil, fmt.Errorf("old_results_add must have 32 elements, got %d", len(bp.OldResultsAdd))
		}
		for i, s := range bp.OldResultsAdd {
			fr, err := beHexToFrLE(s)
			if err != nil {
				return nil, fmt.Errorf("old_results_add[%d]: %w", i, err)
			}
			buf = appendFr(buf, fr)
		}

		// OldResultsSub: 32 Fr elements
		if len(bp.OldResultsSub) != 32 {
			return nil, fmt.Errorf("old_results_sub must have 32 elements, got %d", len(bp.OldResultsSub))
		}
		for i, s := range bp.OldResultsSub {
			fr, err := beHexToFrLE(s)
			if err != nil {
				return nil, fmt.Errorf("old_results_sub[%d]: %w", i, err)
			}
			buf = appendFr(buf, fr)
		}

		// VoterBallots: n_vb, then 32 Fr per ballot
		buf = appendU64(buf, uint64(len(bp.VoterBallots)))
		for i, vb := range bp.VoterBallots {
			if len(vb) != 32 {
				return nil, fmt.Errorf("voter_ballots[%d] must have 32 elements, got %d", i, len(vb))
			}
			for j, s := range vb {
				fr, err := beHexToFrLE(s)
				if err != nil {
					return nil, fmt.Errorf("voter_ballots[%d][%d]: %w", i, j, err)
				}
				buf = appendFr(buf, fr)
			}
		}

		// OverwrittenBallots: n_ob, then 32 Fr per ballot
		buf = appendU64(buf, uint64(len(bp.OverwrittenBallots)))
		for i, ob := range bp.OverwrittenBallots {
			if len(ob) != 32 {
				return nil, fmt.Errorf("overwritten_ballots[%d] must have 32 elements, got %d", i, len(ob))
			}
			for j, s := range ob {
				fr, err := beHexToFrLE(s)
				if err != nil {
					return nil, fmt.Errorf("overwritten_ballots[%d][%d]: %w", i, j, err)
				}
				buf = appendFr(buf, fr)
			}
		}
	} else {
		buf = appendU64(buf, 0) // has_ballot_data = false
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
// The input must be either empty/"0x" (zero) or exactly 64 hex characters
// (32 bytes) after stripping the "0x" prefix.
func leHexToFr(s string) ([4]uint64, error) {
	var out [4]uint64
	h := strings.TrimPrefix(s, "0x")
	if len(h) == 0 {
		// Treat empty or bare "0x" as zero.
		return out, nil
	}
	if len(h) != 64 {
		return out, fmt.Errorf("leHexToFr: expected 64 hex chars (32 bytes), got %d in %q", len(h), s)
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return out, fmt.Errorf("leHexToFr: invalid hex %q: %w", s, err)
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

// reencMagic matches Rust b"REENCBLK" interpreted as a LE u64.
var magicU64 uint64
for i, b := range []byte("REENCBLK") {
magicU64 |= uint64(b) << (8 * i)
}

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

// kzgMagic is "KZGBLK!!" as literal bytes (matches circuit/src/types.rs KZG_MAGIC).
var kzgMagic = []byte("KZGBLK!!")

// KZGEvalData holds all inputs needed to encode a KZG blob barycentric evaluation block.
type KZGEvalData struct {
// ProcessID is the BN254 Fr process identifier (big-endian bytes, up to 32).
ProcessID []byte
// RootHashBefore is the Arbo state root before the batch (big-endian bytes, up to 32).
RootHashBefore []byte
// Commitment is the 48-byte compressed BLS12-381 G1 KZG commitment.
Commitment [48]byte
// YClaimed is the 32-byte big-endian BLS12-381 Fr claimed evaluation result Y = P(Z).
YClaimed [32]byte
// Blob is the full EIP-4844 blob data (131072 bytes = 4096 × 32-byte big-endian cells).
Blob []byte
}

// EncodeKZGBlock encodes the KZG blob barycentric evaluation block.
//
// Block format (binary, appended after the last optional block):
//
//KZGBLK!! (8 bytes LE magic)
//processID       (32 bytes: 4×u64 LE words, converted from big-endian input)
//rootHashBefore  (32 bytes: 4×u64 LE words)
//commitment      (48 raw bytes, big-endian compressed BLS12-381 G1)
//y_claimed       (32 raw bytes, big-endian BLS12-381 Fr)
//blob            (131072 bytes = 4096 × 32-byte big-endian cells)
func EncodeKZGBlock(d *KZGEvalData) ([]byte, error) {
if len(d.Blob) != 4096*32 {
return nil, fmt.Errorf("blob must be exactly 131072 bytes, got %d", len(d.Blob))
}
if len(d.ProcessID) > 32 {
return nil, fmt.Errorf("processID too large: %d bytes", len(d.ProcessID))
}
if len(d.RootHashBefore) > 32 {
return nil, fmt.Errorf("rootHashBefore too large: %d bytes", len(d.RootHashBefore))
}

// Build magic u64 from literal bytes (LE interpretation matching Rust b"KZGBLK!!")
var magicU64 uint64
for i := 0; i < 8; i++ {
magicU64 |= uint64(kzgMagic[i]) << (8 * i)
}

pid := beBytes32ToFrLE(d.ProcessID)
rhb := beBytes32ToFrLE(d.RootHashBefore)

buf := appendU64(nil, magicU64)
buf = appendFr(buf, pid)
buf = appendFr(buf, rhb)
buf = append(buf, d.Commitment[:]...)
buf = append(buf, d.YClaimed[:]...)
buf = append(buf, d.Blob...)
return buf, nil
}

// beBytes32ToFrLE converts a big-endian byte slice (≤32 bytes) into the 4×u64
// little-endian FrRaw representation used by the Rust circuit.
// word[0] = least-significant 64 bits = bytes[24..32] read as a big-endian u64.
func beBytes32ToFrLE(b []byte) [4]uint64 {
var padded [32]byte
if len(b) <= 32 {
copy(padded[32-len(b):], b)
} else {
copy(padded[:], b[len(b)-32:])
}
var out [4]uint64
out[0] = binary.BigEndian.Uint64(padded[24:32])
out[1] = binary.BigEndian.Uint64(padded[16:24])
out[2] = binary.BigEndian.Uint64(padded[8:16])
out[3] = binary.BigEndian.Uint64(padded[0:8])
return out
}

// cspMagic is "CSPBLK!!" in little-endian.
var cspMagic = [8]byte{'C', 'S', 'P', 'B', 'L', 'K', '!', '!'}

// EncodeCspBlock serializes CSP ECDSA census data into the CSPBLK binary block.
//
// Format:
//
//	magic:         u64 = "CSPBLK!!"
//	n_entries:     u64
//	csp_pub_key_x: [u64; 4] (LE limbs)
//	csp_pub_key_y: [u64; 4] (LE limbs)
//	Per entry:
//	  r:              [u64; 4] (LE limbs)
//	  s:              [u64; 4] (LE limbs)
//	  voter_address:  [u64; 4] (LE limbs, uint160 zero-padded)
//	  weight:         [u64; 4] (LE limbs)
//	  index:          u64
func EncodeCspBlock(data *CspData) ([]byte, error) {
	if data == nil || len(data.Proofs) == 0 {
		return nil, nil
	}
	pkX, err := beHexToFrLE(data.CspPubKeyX)
	if err != nil {
		return nil, fmt.Errorf("csp pub_key_x: %w", err)
	}
	pkY, err := beHexToFrLE(data.CspPubKeyY)
	if err != nil {
		return nil, fmt.Errorf("csp pub_key_y: %w", err)
	}

	buf := append([]byte{}, cspMagic[:]...)
	buf = appendU64(buf, uint64(len(data.Proofs)))
	buf = appendFr(buf, pkX)
	buf = appendFr(buf, pkY)

	for i, p := range data.Proofs {
		r, err := beHexToFrLE(p.R)
		if err != nil {
			return nil, fmt.Errorf("csp proof[%d] r: %w", i, err)
		}
		s, err := beHexToFrLE(p.S)
		if err != nil {
			return nil, fmt.Errorf("csp proof[%d] s: %w", i, err)
		}
		// VoterAddress: 20-byte hex → pad to 32-byte BE → LE Fr
		addrFr, err := addressHexToFrLE(p.VoterAddress)
		if err != nil {
			return nil, fmt.Errorf("csp proof[%d] address: %w", i, err)
		}
		w, err := beHexToFrLE(p.Weight)
		if err != nil {
			return nil, fmt.Errorf("csp proof[%d] weight: %w", i, err)
		}
		buf = appendFr(buf, r)
		buf = appendFr(buf, s)
		buf = appendFr(buf, addrFr)
		buf = appendFr(buf, w)
		buf = appendU64(buf, p.Index)
	}
	return buf, nil
}

// addressHexToFrLE converts a 0x-prefixed Ethereum address hex string (20 bytes)
// to a [4]uint64 LE circuit word representation (uint160 in Fr).
func addressHexToFrLE(s string) ([4]uint64, error) {
	h := strings.TrimPrefix(s, "0x")
	if len(h) < 40 {
		h = strings.Repeat("0", 40-len(h)) + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return [4]uint64{}, fmt.Errorf("invalid address hex %q: %w", s, err)
	}
	if len(b) != 20 {
		return [4]uint64{}, fmt.Errorf("expected 20 bytes for address, got %d: %q", len(b), s)
	}
	// b is big-endian 20 bytes: [b19, b18, ..., b0]
	// Pack into 32-byte big-endian (12 zero prefix bytes + 20 address bytes)
	var padded [32]byte
	copy(padded[12:], b)
	var out [4]uint64
	out[0] = binary.BigEndian.Uint64(padded[24:32])
	out[1] = binary.BigEndian.Uint64(padded[16:24])
	out[2] = binary.BigEndian.Uint64(padded[8:16])
	out[3] = binary.BigEndian.Uint64(padded[0:8])
	return out, nil
}
