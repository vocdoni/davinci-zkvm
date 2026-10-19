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
	// Zs is the 32-byte big-endian bound evaluation point per blob, see
	// EvaluationPoint.
	Zs [][32]byte
	// Ys is the 32-byte big-endian claimed evaluation P_b(Zs[b]) per blob.
	Ys [][32]byte
	// Proofs is the 48-byte KZG opening proof per blob at Zs[b] (feeds the
	// point-evaluation precompile in the settlement contract).
	Proofs []kzg4844.Proof
	// Digest is sha256(com_0 || y_0 || ... || com_{n-1} || y_{n-1}), the
	// exact value the guest emits in publicValues[28..35].
	Digest [32]byte
	// CellsDigest is D over Cells (see CellsDigest), the value the guest
	// emits in publicValues[46..53] and every Zs entry is derived from.
	CellsDigest [32]byte
}

// cellsTag and pointTag are the domain tags of D and of the evaluation
// points (circuit/src/kzg.rs CELLS_TAG, POINT_TAG).
const (
	cellsTag = "davinci/cells/v1"
	pointTag = "davinci/point/v1"
)

// CellsDigest is D = SHA-256(cellsTag || u64_be(numFields) || u64_be(T) ||
// cell_0 || ... || cell_{T-1}) over the unpadded stream TransitionCells
// returns. It is computed from the cells before any evaluation point, so the
// points depend on the exact polynomials.
func CellsDigest(numFields int, cells [][32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(cellsTag))
	var w [8]byte
	binary.BigEndian.PutUint64(w[:], uint64(numFields))
	h.Write(w[:])
	binary.BigEndian.PutUint64(w[:], uint64(len(cells)))
	h.Write(w[:])
	for i := range cells {
		h.Write(cells[i][:])
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// TransitionCells rebuilds the DA blob cell stream, byte-identical to the
// guest's circuit_primitives::da_blob::build_cells:
//
//	header               nVids*2^64 + nUpdates (bits 128 and up zero)
//	ceil((V+U)/4) cells  [vid & (2^63-1) ..., key ...], four per cell, the
//	                     first in the top 63-bit slot
//	U*2*numFields cells  per update in key order: pack(c1_0) pack(c2_0) ...
//
// The caller passes:
//   - numFields: the election's declared num_fields (1..=NumFields);
//   - voteIDs: the batch's new vote-id chain first-limbs (u64), any order;
//     a sorted copy is laid out;
//   - updates: (key, ballot) pairs for every batch ballot + every silent
//     refresh, in ballot-chain-then-refresh order; stable-sorted by key.
//     Each Ballot must be exactly BallotFields big-endian hex coords, but
//     only the first 4·numFields entries are consumed.
//
// The Results accumulator is not in the stream: a follower recomputes it
// from the ballots it already holds. The last blob is NOT padded here — pad
// up to cellsPerBlob when packing into blob buffers. Kept as its own
// function so tests can lock the byte layout without a KZG trusted setup.
func TransitionCells(numFields int, voteIDs []uint64, updates []SlotUpdate) ([][32]byte, error) {
	if numFields < 1 || numFields > NumFields {
		return nil, fmt.Errorf("num_fields out of range: got %d, want 1..=%d", numFields, NumFields)
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

	cells = append(cells, headerCell(len(sortedVIDs), len(sortedUpdates)))
	ints := make([]uint64, 0, len(sortedVIDs)+len(sortedUpdates)+3)
	for _, v := range sortedVIDs {
		ints = append(ints, v&low63)
	}
	for _, u := range sortedUpdates {
		ints = append(ints, u.Key)
	}
	for len(ints)%4 != 0 {
		ints = append(ints, 0)
	}
	for i := 0; i < len(ints); i += 4 {
		cells = append(cells, pack4(ints[i], ints[i+1], ints[i+2], ints[i+3]))
	}
	for i, u := range sortedUpdates {
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
	if len(cells) != t {
		return nil, fmt.Errorf("internal: expected %d cells, got %d", t, len(cells))
	}
	return cells, nil
}

// BuildTransitionBlobs rebuilds the same cell stream as the guest, splits it
// into EIP-4844 blobs (padding the tail of the last blob with zero cells),
// commits, and opens each blob at the guest-bound point EvaluationPoint.
// The returned TransitionBlobs carries the SHA-256 pair digest that must
// match publicValues[28..35] and D for publicValues[46..53].
func BuildTransitionBlobs(
	numFields int,
	processIDBE32, rootBeforeBE32 [32]byte,
	voteIDs []uint64,
	updates []SlotUpdate,
) (*TransitionBlobs, error) {
	cells, err := TransitionCells(numFields, voteIDs, updates)
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
		CellsDigest:     CellsDigest(numFields, cells),
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

		z := EvaluationPoint(processIDBE32, rootBeforeBE32, tb.CellsDigest, nBlobs, b, commitment)
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

// EvaluationPoint mirrors circuit/src/kzg.rs::compute_z for blob index of
// nBlobs: SHA-256 over the 176-byte preimage pointTag(16) || processID BE32
// || rootBefore BE32 || cellsDigest(32) || u64_be(nBlobs) || u64_be(index)
// || commitment(48), reduced mod r_bls (the KZG scalar field). Returns the
// reduced value as 32-byte big-endian, ready to hand to kzg4844.ComputeProof.
func EvaluationPoint(processIDBE32, rootBeforeBE32, cellsDigest [32]byte, nBlobs, index int, commitment [48]byte) [32]byte {
	var preimage [176]byte
	copy(preimage[0:16], pointTag)
	copy(preimage[16:48], processIDBE32[:])
	copy(preimage[48:80], rootBeforeBE32[:])
	copy(preimage[80:112], cellsDigest[:])
	binary.BigEndian.PutUint64(preimage[112:120], uint64(nBlobs))
	binary.BigEndian.PutUint64(preimage[120:128], uint64(index))
	copy(preimage[128:176], commitment[:])
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

// low63 masks a vote id to its packed form (its top bit is implied); it is
// also every integer slot's width.
const low63 = 1<<63 - 1

// headerCell is nVids*2^64 + nUpdates as a 32-byte big-endian cell.
func headerCell(nVids, nUpdates int) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[16:24], uint64(nVids))
	binary.BigEndian.PutUint64(out[24:32], uint64(nUpdates))
	return out
}

// pack4 is a*2^189 + b*2^126 + c*2^63 + d for integers below 2^63, built
// from the cell's four 64-bit words. Mirrors da_blob::pack4.
func pack4(a, b, c, d uint64) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[0:8], a>>3)
	binary.BigEndian.PutUint64(out[8:16], b>>2|a<<61)
	binary.BigEndian.PutUint64(out[16:24], c>>1|b<<62)
	binary.BigEndian.PutUint64(out[24:32], d|c<<63)
	return out
}

// totalCells matches da_blob::total_cells: 1 + ceil((V+U)/4) + 2*nf*U.
func totalCells(nVids, nUpdates, nf int) int {
	return 1 + (nVids+nUpdates+3)/4 + 2*nf*nUpdates
}

// sortUint64Asc sorts s in place, ascending (insertion sort).
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
