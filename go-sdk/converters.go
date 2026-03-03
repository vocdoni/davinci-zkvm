package davinci

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

// BigIntToHex32BE converts a *big.Int to a 0x-prefixed 64-character big-endian
// hex string (32 bytes zero-padded). This is the standard encoding for all
// 256-bit field values in the go-sdk API. Exported for use by callers that
// need to build custom hex-encoded data.
func BigIntToHex32BE(v *big.Int) string {
	return bigIntToHex32BE(v)
}

// bigIntToHex32BE converts a *big.Int to a 0x-prefixed 64-character big-endian
// hex string (32 bytes zero-padded). This is the standard encoding for all
// 256-bit field values in the go-sdk API.
func bigIntToHex32BE(v *big.Int) string {
	if v == nil {
		return "0x" + zeroHex64
	}
	b := v.Bytes() // big-endian, variable length
	var padded [32]byte
	if len(b) <= 32 {
		copy(padded[32-len(b):], b)
	} else {
		copy(padded[:], b[len(b)-32:])
	}
	return "0x" + hex.EncodeToString(padded[:])
}

const zeroHex64 = "0000000000000000000000000000000000000000000000000000000000000000"

// ECDSA Signatures

// EcdsaSignature holds the secp256k1 ECDSA signature components needed by the
// ZisK circuit. This matches the Rust EcdsaSig struct in input-gen.
// R, S are signature components. PubKeyX, PubKeyY are the uncompressed public
// key coordinates. VoteID is the vote identifier. Address is the Ethereum
// address as a decimal uint160 string.
type EcdsaSignature struct {
	R       *big.Int
	S       *big.Int
	PubKeyX *big.Int
	PubKeyY *big.Int
	VoteID  uint64
	Address *big.Int
}

// MarshalJSON produces the JSON expected by the Rust service.
func (e *EcdsaSignature) MarshalJSON() ([]byte, error) {
	addr := "0"
	if e.Address != nil {
		addr = e.Address.Text(10)
	}
	return []byte(fmt.Sprintf(`{`+
		`"public_key_x":%q,`+
		`"public_key_y":%q,`+
		`"signature_r":%q,`+
		`"signature_s":%q,`+
		`"vote_id":%d,`+
		`"address":%q}`,
		bigIntToHex32BE(e.PubKeyX),
		bigIntToHex32BE(e.PubKeyY),
		bigIntToHex32BE(e.R),
		bigIntToHex32BE(e.S),
		e.VoteID,
		addr,
	)), nil
}

// Groth16 BN254 Proofs

// Groth16Proof is a BN254 Groth16 proof in snarkjs format.
// The three elliptic curve points (A ∈ G1, B ∈ G2, C ∈ G1) use the same
// string-array encoding as snarkjs/circom JSON output.
type Groth16Proof struct {
	A        [3]string    // G1 point: [x, y, "1"]
	B        [3][2]string // G2 point: [[x0,x1], [y0,y1], ["1","0"]]
	C        [3]string    // G1 point: [x, y, "1"]
	Protocol string
}

// MarshalJSON produces snarkjs-compatible proof JSON.
func (p *Groth16Proof) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{`+
		`"pi_a":[%q,%q,%q],`+
		`"pi_b":[[%q,%q],[%q,%q],[%q,%q]],`+
		`"pi_c":[%q,%q,%q],`+
		`"protocol":%q}`,
		p.A[0], p.A[1], p.A[2],
		p.B[0][0], p.B[0][1], p.B[1][0], p.B[1][1], p.B[2][0], p.B[2][1],
		p.C[0], p.C[1], p.C[2],
		p.Protocol,
	)), nil
}

// VerificationKey is a BN254 Groth16 verification key in snarkjs format.
type VerificationKey struct {
	Protocol string
	Curve    string
	NPublic  int
	Alpha1   [3]string     // vk_alpha_1: G1
	Beta2    [3][2]string  // vk_beta_2: G2
	Gamma2   [3][2]string  // vk_gamma_2: G2
	Delta2   [3][2]string  // vk_delta_2: G2
	IC       [][3]string   // IC: array of G1 points
}

// MarshalJSON produces snarkjs-compatible VK JSON.
func (vk *VerificationKey) MarshalJSON() ([]byte, error) {
	// Build IC array
	icParts := ""
	for i, ic := range vk.IC {
		if i > 0 {
			icParts += ","
		}
		icParts += fmt.Sprintf("[%q,%q,%q]", ic[0], ic[1], ic[2])
	}

	g2 := func(p [3][2]string) string {
		return fmt.Sprintf("[[%q,%q],[%q,%q],[%q,%q]]",
			p[0][0], p[0][1], p[1][0], p[1][1], p[2][0], p[2][1])
	}

	return []byte(fmt.Sprintf(`{`+
		`"protocol":%q,`+
		`"curve":%q,`+
		`"nPublic":%d,`+
		`"vk_alpha_1":[%q,%q,%q],`+
		`"vk_beta_2":%s,`+
		`"vk_gamma_2":%s,`+
		`"vk_delta_2":%s,`+
		`"IC":[%s]}`,
		vk.Protocol,
		vk.Curve,
		vk.NPublic,
		vk.Alpha1[0], vk.Alpha1[1], vk.Alpha1[2],
		g2(vk.Beta2),
		g2(vk.Gamma2),
		g2(vk.Delta2),
		icParts,
	)), nil
}

// Public Inputs

// PublicInput holds the public inputs for a single Groth16 ballot proof.
// The circuit expects Fr elements as decimal strings.
type PublicInput struct {
	// Values holds the public signal values in order: [address, voteID, ballotInputsHash, ...]
	Values []*big.Int
}

// toStrings converts the public input values to decimal strings for JSON.
func (pi *PublicInput) toStrings() []string {
	result := make([]string, len(pi.Values))
	for i, v := range pi.Values {
		if v == nil {
			result[i] = "0"
		} else {
			result[i] = v.Text(10)
		}
	}
	return result
}

// SMT Converters

// ArboTransition holds an Arbo SMT state transition in native Go types,
// mirroring state.ArboTransition from davinci-node.
type ArboTransition struct {
	OldRoot  *big.Int
	NewRoot  *big.Int
	OldKey   *big.Int
	OldValue *big.Int
	NewKey   *big.Int
	NewValue *big.Int
	IsOld0   int
	Fnc0     int
	Fnc1     int
	Siblings []*big.Int
}

// SmtEntryFromArboTransition converts a native ArboTransition into the
// SmtEntry format expected by the API.
// nLevels specifies the Merkle tree depth; siblings are zero-padded to
// this length. The hex encoding uses big-endian format (arbo convention).
func SmtEntryFromArboTransition(t *ArboTransition, nLevels int) SmtEntry {
	sibs := make([]string, nLevels)
	for i := 0; i < nLevels; i++ {
		if i < len(t.Siblings) && t.Siblings[i] != nil {
			sibs[i] = bigIntToHex32BE(t.Siblings[i])
		} else {
			sibs[i] = "0x" + zeroHex64
		}
	}
	isOld0 := uint8(0)
	if t.IsOld0 != 0 {
		isOld0 = 1
	}
	return SmtEntry{
		OldRoot:  bigIntToHex32BE(t.OldRoot),
		NewRoot:  bigIntToHex32BE(t.NewRoot),
		OldKey:   bigIntToHex32BE(t.OldKey),
		OldValue: bigIntToHex32BE(t.OldValue),
		NewKey:   bigIntToHex32BE(t.NewKey),
		NewValue: bigIntToHex32BE(t.NewValue),
		IsOld0:   isOld0,
		Fnc0:     uint8(t.Fnc0),
		Fnc1:     uint8(t.Fnc1),
		Siblings: sibs,
	}
}

// SmtReadProof creates a NOOP SmtEntry (fnc0=0, fnc1=0) from an inclusion
// proof, for use as a process config read-proof.
func SmtReadProof(root, key, value *big.Int, siblings []*big.Int, nLevels int) SmtEntry {
	return SmtEntryFromArboTransition(&ArboTransition{
		OldRoot:  root,
		NewRoot:  root,
		OldKey:   key,
		OldValue: value,
		NewKey:   key,
		NewValue: value,
		IsOld0:   0,
		Fnc0:     0,
		Fnc1:     0,
		Siblings: siblings,
	}, nLevels)
}

// Re-encryption Converters

// BjjPointFromBigInts creates a BjjPoint from (x, y) big.Int coordinates.
func BjjPointFromBigInts(x, y *big.Int) BjjPoint {
	return BjjPoint{
		X: bigIntToHex32BE(x),
		Y: bigIntToHex32BE(y),
	}
}

// BjjCiphertextFromBigInts creates a BjjCiphertext from 4 big.Int coordinates
// in the order [C1.X, C1.Y, C2.X, C2.Y] => matching elgamal.Ciphertext layout.
func BjjCiphertextFromBigInts(c1x, c1y, c2x, c2y *big.Int) BjjCiphertext {
	return BjjCiphertext{
		C1: BjjPointFromBigInts(c1x, c1y),
		C2: BjjPointFromBigInts(c2x, c2y),
	}
}

// ReencryptionEntryFromBigInts builds a ReencryptionEntry from raw big.Int
// coordinates. Each ballot is 32 big.Int values (8 ciphertexts × 4 coords).
// k is the re-encryption random seed. original and reencrypted are each
// slices of 32 *big.Int in the order produced by elgamal.Ballot.BigInts():
// [ct0.c1x, ct0.c1y, ct0.c2x, ct0.c2y, ct1.c1x, ct1.c1y, ...]
func ReencryptionEntryFromBigInts(k *big.Int, original, reencrypted []*big.Int) (ReencryptionEntry, error) {
	if len(original) != 32 {
		return ReencryptionEntry{}, fmt.Errorf("original must have 32 values, got %d", len(original))
	}
	if len(reencrypted) != 32 {
		return ReencryptionEntry{}, fmt.Errorf("reencrypted must have 32 values, got %d", len(reencrypted))
	}
	var entry ReencryptionEntry
	entry.K = bigIntToHex32BE(k)
	for i := 0; i < 8; i++ {
		off := i * 4
		entry.Original[i] = BjjCiphertextFromBigInts(
			original[off], original[off+1], original[off+2], original[off+3])
		entry.Reencrypted[i] = BjjCiphertextFromBigInts(
			reencrypted[off], reencrypted[off+1], reencrypted[off+2], reencrypted[off+3])
	}
	return entry, nil
}

// Census Proof Converter

// CensusProofFromBigInts creates a CensusProof from native Go types.
// root and leaf are BN254 Fr elements. siblings are the non-empty
// Merkle path siblings in the lean-IMT.
func CensusProofFromBigInts(root, leaf *big.Int, index uint64, siblings []*big.Int) CensusProof {
	sibs := make([]string, len(siblings))
	for i, s := range siblings {
		sibs[i] = bigIntToHex32BE(s)
	}
	return CensusProof{
		Root:     bigIntToHex32BE(root),
		Leaf:     bigIntToHex32BE(leaf),
		Index:    index,
		Siblings: sibs,
	}
}

// KZG Converter

// NewKZGRequest creates a KZGRequest from native Go types.
// commitment is the 48-byte compressed BLS12-381 G1 point.
// yClaimed is the 32-byte BLS12-381 Fr evaluation result.
// blob is the 131072-byte raw blob data.
func NewKZGRequest(processID, rootHashBefore *big.Int,
	commitment [48]byte, yClaimed [32]byte, blob []byte) *KZGRequest {
	return &KZGRequest{
		ProcessID:      bigIntToHex32BE(processID),
		RootHashBefore: bigIntToHex32BE(rootHashBefore),
		Commitment:     "0x" + hex.EncodeToString(commitment[:]),
		YClaimed:       "0x" + hex.EncodeToString(yClaimed[:]),
		Blob:           "0x" + hex.EncodeToString(blob),
	}
}

// Re-encryption Data Constructor

// NewReencryptionData creates a ReencryptionData block from the encryption
// public key coordinates and a slice of per-voter entries.
func NewReencryptionData(encKeyX, encKeyY *big.Int, entries []ReencryptionEntry) *ReencryptionData {
	return &ReencryptionData{
		EncryptionKeyX: bigIntToHex32BE(encKeyX),
		EncryptionKeyY: bigIntToHex32BE(encKeyY),
		Entries:        entries,
	}
}

// State Transition Data Constructor

// NewStateTransitionData creates a StateTransitionData block from native Go types.
// The processID, oldRoot, and newRoot must be 256-bit values. SMT proof slices
// are taken as-is and should be constructed using SmtEntryFromArboTransition or
// SmtReadProof.
func NewStateTransitionData(
	votersCount uint64,
	overwrittenCount uint64,
	processID *big.Int,
	oldStateRoot *big.Int,
	newStateRoot *big.Int,
	voteIDSmt []SmtEntry,
	ballotSmt []SmtEntry,
	processSmtReadProofs []SmtEntry,
	resultsAddSmt *SmtEntry,
	resultsSubSmt *SmtEntry,
) *StateTransitionData {
	return &StateTransitionData{
		VotersCount:      votersCount,
		OverwrittenCount: overwrittenCount,
		ProcessID:        bigIntToHex32BE(processID),
		OldStateRoot:     bigIntToHex32BE(oldStateRoot),
		NewStateRoot:     bigIntToHex32BE(newStateRoot),
		VoteIDSmt:        voteIDSmt,
		BallotSmt:        ballotSmt,
		ProcessSmt:       processSmtReadProofs,
		ResultsAddSmt:    resultsAddSmt,
		ResultsSubSmt:    resultsSubSmt,
	}
}

// NewBallotProofData creates BallotProofData from native Go types.
// Each Fr element is a *big.Int in the BN254 scalar field. The slices
// oldResultsAdd and oldResultsSub must each have exactly 32 elements.
// Each inner slice of voterBallots and overwrittenBallots must also have
// exactly 32 elements (8 ciphertexts × 4 coordinates).
func NewBallotProofData(
	oldResultsAdd []*big.Int,
	oldResultsSub []*big.Int,
	voterBallots [][]*big.Int,
	overwrittenBallots [][]*big.Int,
) *BallotProofData {
	toHex := func(vals []*big.Int) []string {
		out := make([]string, len(vals))
		for i, v := range vals {
			out[i] = bigIntToHex32BE(v)
		}
		return out
	}
	toHex2D := func(vals [][]*big.Int) [][]string {
		out := make([][]string, len(vals))
		for i, row := range vals {
			out[i] = toHex(row)
		}
		return out
	}
	return &BallotProofData{
		OldResultsAdd:      toHex(oldResultsAdd),
		OldResultsSub:      toHex(oldResultsSub),
		VoterBallots:       toHex2D(voterBallots),
		OverwrittenBallots: toHex2D(overwrittenBallots),
	}
}
