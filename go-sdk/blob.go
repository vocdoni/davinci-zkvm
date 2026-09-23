package davinci

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	blsfr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// MaxBlobs mirrors the guest's MAX_BLOBS: the guest rejects any KZG block
// carrying more than this many blob commitments. Raising the cap requires
// bumping the constant in both places (and in the settlement contract).
const MaxBlobs = 32

// MaxBlobsPerTx is the EIP-7594 cap on blobs in one Ethereum transaction.
// DavinciSettlement reads every blob of a transition from the transaction
// that submits it, so a transition spanning more blobs cannot be settled.
const MaxBlobsPerTx = 6

// TransitionBlobCount is the number of blobs a transition with nVotes new
// vote identifiers and nUpdates slot updates (votes plus refreshes) spans at
// numFields active fields.
func TransitionBlobCount(nVotes, nUpdates, numFields int) int {
	return (totalCells(nVotes, nUpdates, numFields) + cellsPerBlob - 1) / cellsPerBlob
}

// MaxSingleTxBatch is the largest steady-state batch at numFields whose
// transition fits in MaxBlobsPerTx blobs: n votes plus the RefreshTarget(n, 0,
// many) silent refreshes a batch with few overwrites carries, capped at
// MaxBatchSize. A ballot is 2*numFields incompressible curve points, so this
// is a hard limit of the data-availability channel, not of the prover; a
// sequencer settling on Ethereum should size its batches by it. The
// throughput-optimal batches (512 at 2 fields, 256 at 16) fit.
func MaxSingleTxBatch(numFields int) int {
	for n := MaxBatchSize; n > 0; n-- {
		refreshes := RefreshTarget(n, 0, MaxBatchSize+MaxRefresh)
		if TransitionBlobCount(n, n+refreshes, numFields) <= MaxBlobsPerTx {
			return n
		}
	}
	return 0
}

// cellsPerBlob is the EIP-4844 fixed cell count per blob (matches
// da_blob::CELLS_PER_BLOB and kzg::N in the guest).
const cellsPerBlob = 4096

// blobBytes is the EIP-4844 fixed blob size in bytes (4096 × 32).
const blobBytes = cellsPerBlob * 32

// SlotUpdate is one (ballot key, ballot) update fed into the DA blob layout.
// Ballot carries BallotFields big-endian hex coords in the canonical
// [c1x, c1y, c2x, c2y] × NumFields order — same shape as the entries in
// BallotProofData.VoterBallots / RefreshedBallots. Padded fields
// (i >= numFields) are dropped by TransitionCells / BuildTransitionBlobs;
// the caller may still leave the entries filled with TE identity.
type SlotUpdate struct {
	Key    uint64
	Ballot []string
}

// TransitionBlobs is the DA-blob-side output of BuildTransitionBlobs.
//
// Fields mirror the parallel go-sdk/solidity TransitionBlobs so the
// settlement helper can be fed by direct field copy. Digest binds the whole
// ordered (Commitments[i], Ys[i]) list — the guest publishes the same
// SHA-256 in publics registers 28..35.
type TransitionBlobs struct {
	// Cells is the full ordered list of 32-byte BLS12-381 Fr big-endian cells
	// (n_blobs × 4096, with zero-padding in the tail of the last blob).
	Cells [][32]byte
	// Blobs is the per-blob EIP-4844 blob buffer (each cellsPerBlob × 32
	// bytes) filled from Cells in order.
	Blobs []kzg4844.Blob
	// Commitments are the 48-byte KZG commitments, one per Blob, in the
	// order the guest hashes them into Digest.
	Commitments []kzg4844.Commitment
	// VersionedHashes is the EIP-4844 versioned blob hash for each
	// Commitment: sha256(commitment) with the version byte set to 0x01.
	VersionedHashes [][32]byte
	// Zs is the 32-byte big-endian bound evaluation point per blob:
	// SHA-256(processIDBE32 || rootBeforeBE32 || commitment) mod r_bls.
	Zs [][32]byte
	// Ys is the 32-byte big-endian claimed evaluation P_b(Zs[b]) per blob.
	Ys [][32]byte
	// Proofs is the 48-byte KZG opening proof per blob at Zs[b] (feeds the
	// point-evaluation precompile in the settlement contract).
	Proofs []kzg4844.Proof
	// Digest is sha256(com_0 || y_0 || ... || com_{n-1} || y_{n-1}), the
	// exact value the guest emits in publicValues[28..35].
	Digest [32]byte
}

// TransitionCells rebuilds the DA blob cell stream — the same byte-exact
// layout the guest constructs in circuit_primitives::da_blob::build_cells.
// The caller passes:
//   - numFields: the election's declared num_fields (1..=NumFields);
//   - voteIDs: the batch's new vote-id chain first-limbs (u64), any order;
//     they are sorted ascending in place;
//   - updates: (key, ballot) pairs for every batch ballot + every silent
//     refresh, in ballot-chain-then-refresh order; stable-sorted by key.
//     Each Ballot must be exactly BallotFields big-endian hex coords, but
//     only the first 4·numFields entries are consumed;
//   - accumulator: the NEW net Results accumulator, BallotFields BE hex
//     coords; only the first 4·numFields consumed.
//
// The last blob is NOT padded here — pad up to cellsPerBlob when packing
// into blob buffers. Kept as its own function so tests can lock the byte
// layout without needing a KZG trusted setup.
func TransitionCells(numFields int, voteIDs []uint64, updates []SlotUpdate, accumulator []string) ([][32]byte, error) {
	if numFields < 1 || numFields > NumFields {
		return nil, fmt.Errorf("num_fields out of range: got %d, want 1..=%d", numFields, NumFields)
	}
	if len(accumulator) != BallotFields {
		return nil, fmt.Errorf("accumulator must have %d coords, got %d", BallotFields, len(accumulator))
	}
	for i, u := range updates {
		if len(u.Ballot) != BallotFields {
			return nil, fmt.Errorf("updates[%d].Ballot must have %d coords, got %d", i, BallotFields, len(u.Ballot))
		}
	}

	// Sort inputs the same way the guest does.
	sortedVIDs := append([]uint64(nil), voteIDs...)
	sortUint64Asc(sortedVIDs)

	sortedUpdates := append([]SlotUpdate(nil), updates...)
	stableSortByKey(sortedUpdates)

	t := totalCells(len(sortedVIDs), len(sortedUpdates), numFields)
	cells := make([][32]byte, 0, t)

	cells = append(cells, encU64(uint64(len(sortedVIDs))))
	for _, v := range sortedVIDs {
		cells = append(cells, encU64(v))
	}
	cells = append(cells, encU64(uint64(len(sortedUpdates))))
	for i, u := range sortedUpdates {
		cells = append(cells, encU64(u.Key))
		for f := 0; f < numFields; f++ {
			base := f * 4
			c, err := packTeHex(u.Ballot[base], u.Ballot[base+1])
			if err != nil {
				return nil, fmt.Errorf("updates[%d] field %d c1: %w", i, f, err)
			}
			cells = append(cells, c)
			c, err = packTeHex(u.Ballot[base+2], u.Ballot[base+3])
			if err != nil {
				return nil, fmt.Errorf("updates[%d] field %d c2: %w", i, f, err)
			}
			cells = append(cells, c)
		}
	}
	for f := 0; f < numFields; f++ {
		base := f * 4
		c, err := packTeHex(accumulator[base], accumulator[base+1])
		if err != nil {
			return nil, fmt.Errorf("accumulator field %d c1: %w", f, err)
		}
		cells = append(cells, c)
		c, err = packTeHex(accumulator[base+2], accumulator[base+3])
		if err != nil {
			return nil, fmt.Errorf("accumulator field %d c2: %w", f, err)
		}
		cells = append(cells, c)
	}
	if len(cells) != t {
		return nil, fmt.Errorf("internal: expected %d cells, got %d", t, len(cells))
	}
	return cells, nil
}

// BuildTransitionBlobs rebuilds the same cell stream as the guest, splits it
// into EIP-4844 blobs (padding the tail of the last blob with zero cells),
// commits, and opens each blob at the guest-bound point
// z_b = SHA-256(processID || rootBefore || commitment_b) mod r_bls.
// Returns a fully populated TransitionBlobs plus the SHA-256 pair digest
// that must match publicValues[28..35].
func BuildTransitionBlobs(
	numFields int,
	processIDBE32, rootBeforeBE32 [32]byte,
	voteIDs []uint64,
	updates []SlotUpdate,
	accumulator []string,
) (*TransitionBlobs, error) {
	cells, err := TransitionCells(numFields, voteIDs, updates, accumulator)
	if err != nil {
		return nil, err
	}
	nBlobs := (len(cells) + cellsPerBlob - 1) / cellsPerBlob
	if nBlobs < 1 {
		return nil, fmt.Errorf("empty transition: at least one blob required (got 0 cells)")
	}
	if nBlobs > MaxBlobs {
		return nil, fmt.Errorf("transition too large: %d blobs, MaxBlobs=%d", nBlobs, MaxBlobs)
	}

	tb := &TransitionBlobs{
		Cells:           cells,
		Blobs:           make([]kzg4844.Blob, nBlobs),
		Commitments:     make([]kzg4844.Commitment, nBlobs),
		VersionedHashes: make([][32]byte, nBlobs),
		Zs:              make([][32]byte, nBlobs),
		Ys:              make([][32]byte, nBlobs),
		Proofs:          make([]kzg4844.Proof, nBlobs),
	}

	hasher := sha256.New()
	pairsBuf := make([]byte, 0, nBlobs*(48+32))

	for b := 0; b < nBlobs; b++ {
		start := b * cellsPerBlob
		end := start + cellsPerBlob
		if end > len(cells) {
			end = len(cells)
		}
		for i, cell := range cells[start:end] {
			copy(tb.Blobs[b][i*32:(i+1)*32], cell[:])
		}
		// Tail of last blob is already zeroed by allocation.

		commitment, err := kzg4844.BlobToCommitment(&tb.Blobs[b])
		if err != nil {
			return nil, fmt.Errorf("blob %d commitment: %w", b, err)
		}
		tb.Commitments[b] = commitment
		tb.VersionedHashes[b] = kzg4844.CalcBlobHashV1(hasher, &commitment)

		z := computeZ(processIDBE32, rootBeforeBE32, commitment)
		tb.Zs[b] = z

		var point kzg4844.Point
		copy(point[:], z[:])
		proof, claim, err := kzg4844.ComputeProof(&tb.Blobs[b], point)
		if err != nil {
			return nil, fmt.Errorf("blob %d open: %w", b, err)
		}
		tb.Proofs[b] = proof
		tb.Ys[b] = [32]byte(claim)

		pairsBuf = append(pairsBuf, commitment[:]...)
		pairsBuf = append(pairsBuf, tb.Ys[b][:]...)
	}

	tb.Digest = sha256.Sum256(pairsBuf)
	return tb, nil
}

// Request packages the commitments (and only the commitments) for the
// service's /prove endpoint. processIDHex and rootBeforeHex are 32-byte
// big-endian hex (with or without 0x prefix) — the same convention the
// guest reads via be_hex32_to_fr_le.
func (t *TransitionBlobs) Request(processIDHex, rootBeforeHex string) *KZGRequest {
	commits := make([]string, len(t.Commitments))
	for i, c := range t.Commitments {
		commits[i] = "0x" + hex.EncodeToString(c[:])
	}
	return &KZGRequest{
		ProcessID:      processIDHex,
		RootHashBefore: rootBeforeHex,
		Commitments:    commits,
	}
}

// computeZ mirrors circuit/src/kzg.rs::compute_z: SHA-256 over the 112-byte
// preimage (processID BE32 || rootBefore BE32 || commitment(48)), reduced
// mod r_bls (the KZG scalar field). Returns the reduced value as 32-byte
// big-endian, ready to hand to kzg4844.ComputeProof.
func computeZ(processIDBE32, rootBeforeBE32 [32]byte, commitment [48]byte) [32]byte {
	var preimage [112]byte
	copy(preimage[0:32], processIDBE32[:])
	copy(preimage[32:64], rootBeforeBE32[:])
	copy(preimage[64:112], commitment[:])
	sum := sha256.Sum256(preimage[:])

	// Reduce mod BLS12-381 Fr. The guest applies bls_fr::from_be32_mod which
	// interprets the 32 BE bytes as an integer and reduces once.
	z := new(big.Int).SetBytes(sum[:])
	z.Mod(z, blsFrModulus)

	var out [32]byte
	z.FillBytes(out[:])
	return out
}

// blsFrModulus is the BLS12-381 scalar field order, taken from the field
// implementation so it cannot drift from the guest and the contract.
var blsFrModulus = blsfr.Modulus()

// bn254FrModulus is the BN254 scalar field order.
var bn254FrModulus, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// packTeHex packs a TE point (x, y) into a 32-byte BE cell. Mirrors
// da_blob::pack_te: reduce both coords mod BN254 Fr, write y_canon BE, set
// bit 254 (out[0] |= 0x40) if x_canon is odd. Fits in BLS12-381 Fr since
// r_bn254 < 2^254 < r_bls.
func packTeHex(xHex, yHex string) ([32]byte, error) {
	x, err := parseHex32BE(xHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("x: %w", err)
	}
	y, err := parseHex32BE(yHex)
	if err != nil {
		return [32]byte{}, fmt.Errorf("y: %w", err)
	}
	xc := new(big.Int).Mod(x, bn254FrModulus)
	yc := new(big.Int).Mod(y, bn254FrModulus)

	var out [32]byte
	yc.FillBytes(out[:])
	if xc.Bit(0) == 1 {
		out[0] |= 0x40
	}
	return out, nil
}

// parseHex32BE parses a 0x-prefixed (or bare) hex string into a big.Int.
// Empty / "0x" is zero. Rejects >32 bytes.
func parseHex32BE(s string) (*big.Int, error) {
	h := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if h == "" {
		return new(big.Int), nil
	}
	if len(h)%2 == 1 {
		h = "0" + h
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, fmt.Errorf("invalid hex %q: %w", s, err)
	}
	if len(b) > 32 {
		return nil, fmt.Errorf("hex too long: %d bytes in %q", len(b), s)
	}
	return new(big.Int).SetBytes(b), nil
}

// encU64 encodes v as a 32-byte big-endian integer.
func encU64(v uint64) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[24:32], v)
	return out
}

// totalCells matches da_blob::total_cells.
func totalCells(nVids, nUpdates, nf int) int {
	return 2 + nVids + nUpdates*(1+2*nf) + 2*nf
}

// sortUint64Asc sorts in-place, ascending. Small (<= few hundred) slices,
// so insertion-sort keeps things dependency-free.
func sortUint64Asc(s []uint64) {
	for i := 1; i < len(s); i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j] > v {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
}

// stableSortByKey stable-sorts by SlotUpdate.Key ascending (insertion sort;
// stable, and the batch cap keeps len small).
func stableSortByKey(s []SlotUpdate) {
	for i := 1; i < len(s); i++ {
		v := s[i]
		j := i - 1
		for j >= 0 && s[j].Key > v.Key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = v
	}
}
