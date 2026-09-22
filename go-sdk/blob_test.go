package davinci

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

// identityBallot returns a BallotFields-wide slice of BE hex TE identity
// coords ((0,1), (0,1)) — the padding shape the guest expects.
func identityBallot() []string {
	b := make([]string, BallotFields)
	for i := 0; i < NumFields; i++ {
		base := i * 4
		b[base+0] = "0x" + zeroHex64                                                     // c1x
		b[base+1] = "0x0000000000000000000000000000000000000000000000000000000000000001" // c1y
		b[base+2] = "0x" + zeroHex64                                                     // c2x
		b[base+3] = "0x0000000000000000000000000000000000000000000000000000000000000001" // c2y
	}
	return b
}

func encU64BE32(v uint64) [32]byte {
	var out [32]byte
	binary.BigEndian.PutUint64(out[24:32], v)
	return out
}

func TestTransitionCellsMirrorsGuestLayout(t *testing.T) {
	nf := 2
	vids := []uint64{0x8000_0000_0000_0001}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x10, Ballot: ballot},
		{Key: 0x11, Ballot: ballot},
	}
	cells, err := TransitionCells(nf, vids, updates, ballot)
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// T = 2 + 1 + 2*(1 + 2*2) + 2*2 = 17
	if len(cells) != 17 {
		t.Fatalf("len(cells) = %d, want 17", len(cells))
	}
	if cells[0] != encU64BE32(1) {
		t.Errorf("cells[0] (n_vids) = %x", cells[0])
	}
	if cells[1] != encU64BE32(0x8000_0000_0000_0001) {
		t.Errorf("cells[1] (vid) = %x", cells[1])
	}
	if cells[2] != encU64BE32(2) {
		t.Errorf("cells[2] (n_updates) = %x", cells[2])
	}
	if cells[3] != encU64BE32(0x10) {
		t.Errorf("cells[3] (key 0) = %x", cells[3])
	}
	// Each identity pack cell = enc_u64(1) (TE identity packs to 1).
	oneCell := encU64BE32(1)
	for i := 0; i < 4; i++ {
		if cells[4+i] != oneCell {
			t.Errorf("update0 pack cell %d = %x", i, cells[4+i])
		}
	}
	if cells[8] != encU64BE32(0x11) {
		t.Errorf("cells[8] (key 1) = %x", cells[8])
	}
	for i := 0; i < 4; i++ {
		if cells[9+i] != oneCell {
			t.Errorf("update1 pack cell %d = %x", i, cells[9+i])
		}
	}
	for i := 0; i < 4; i++ {
		if cells[13+i] != oneCell {
			t.Errorf("acc pack cell %d = %x", i, cells[13+i])
		}
	}
}

func TestTransitionCellsSortsInputs(t *testing.T) {
	nf := 1
	// Unsorted inputs: vids reverse, updates reverse.
	vids := []uint64{5, 3, 9, 1}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x20, Ballot: ballot},
		{Key: 0x10, Ballot: ballot},
	}
	cells, err := TransitionCells(nf, vids, updates, ballot)
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// cells[1..5] = vids ascending
	wantVids := []uint64{1, 3, 5, 9}
	for i, v := range wantVids {
		if cells[1+i] != encU64BE32(v) {
			t.Errorf("cells[%d] = %x, want vid %d", 1+i, cells[1+i], v)
		}
	}
	// n_updates
	if cells[5] != encU64BE32(2) {
		t.Errorf("n_updates cell = %x", cells[5])
	}
	// Update keys ascending: 0x10 then 0x20.
	// After the n_updates cell we have: key + 2*nf pack cells per update.
	if cells[6] != encU64BE32(0x10) {
		t.Errorf("update0 key = %x, want 0x10", cells[6])
	}
	// 6 + 1 (key) + 2*nf = 6 + 1 + 2 = 9
	if cells[9] != encU64BE32(0x20) {
		t.Errorf("update1 key = %x, want 0x20", cells[9])
	}
}

func TestTransitionCellsStableByKey(t *testing.T) {
	nf := 1
	// Two updates with the same key: input order must be preserved (stable).
	ballot0 := identityBallot()
	ballot1 := identityBallot()
	// Make ballot1 distinguishable by using a non-identity y for field 0 c1.
	ballot1[1] = "0x0000000000000000000000000000000000000000000000000000000000000002"
	updates := []SlotUpdate{
		{Key: 0x42, Ballot: ballot0},
		{Key: 0x42, Ballot: ballot1},
	}
	cells, err := TransitionCells(nf, nil, updates, identityBallot())
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// Layout: [n_vids=0, n_updates=2, key0, c1_0, c2_0, key0, c1_1, c2_1, acc_c1, acc_c2].
	// First update's c1 should pack identity y=1 → 1; second's should pack y=2 → 2.
	got0 := cells[3]
	got1 := cells[6]
	if got0 != encU64BE32(1) {
		t.Errorf("first (ballot0) c1 pack = %x, want enc(1)", got0)
	}
	if got1 != encU64BE32(2) {
		t.Errorf("second (ballot1) c1 pack = %x, want enc(2)", got1)
	}
}

func TestPackTeHexIdentityAndParity(t *testing.T) {
	// TE identity (0,1) packs to enc_u64(1).
	got, err := packTeHex("0x00", "0x01")
	if err != nil {
		t.Fatalf("packTeHex identity: %v", err)
	}
	if got != encU64BE32(1) {
		t.Errorf("identity pack = %x, want enc(1)", got)
	}

	// x odd → bit 254 set.
	got, err = packTeHex("0x01", "0x01")
	if err != nil {
		t.Fatalf("packTeHex x-odd: %v", err)
	}
	want := encU64BE32(1)
	want[0] |= 0x40
	if got != want {
		t.Errorf("x-odd pack = %x, want %x", got, want)
	}

	// x even → bit 254 clear.
	got, err = packTeHex("0x02", "0x01")
	if err != nil {
		t.Fatalf("packTeHex x-even: %v", err)
	}
	if got != encU64BE32(1) {
		t.Errorf("x-even pack = %x, want enc(1)", got)
	}
}

func TestTotalCellsFormula(t *testing.T) {
	cases := []struct {
		nVids, nUpd, nf int
		want            int
	}{
		{0, 0, 1, 2 + 0 + 0 + 2*1},
		{1, 2, 2, 2 + 1 + 2*(1+2*2) + 2*2},
		{10, 128, 16, 2 + 10 + 128*(1+2*16) + 2*16},
	}
	for _, c := range cases {
		if got := totalCells(c.nVids, c.nUpd, c.nf); got != c.want {
			t.Errorf("totalCells(%d,%d,%d) = %d, want %d", c.nVids, c.nUpd, c.nf, got, c.want)
		}
	}
}

// TestBuildTransitionBlobsSingleBlob is the end-to-end host build + open loop
// on a tiny (fits-in-one-blob) transition. Verifies:
//   - one blob out
//   - kzg4844.VerifyProof round-trips each opening
//   - digest matches manual sha256(com_0 || y_0 || ...)
//   - Request() returns commitments-only KZGRequest
func TestBuildTransitionBlobsSingleBlob(t *testing.T) {
	nf := 2
	vids := []uint64{1, 2, 3}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x10, Ballot: ballot},
		{Key: 0x11, Ballot: ballot},
	}
	var pid, rhb [32]byte
	pid[31] = 0x42
	rhb[31] = 0x01

	tb, err := BuildTransitionBlobs(nf, pid, rhb, vids, updates, ballot)
	if err != nil {
		t.Fatalf("BuildTransitionBlobs: %v", err)
	}
	if len(tb.Blobs) != 1 {
		t.Fatalf("n_blobs = %d, want 1", len(tb.Blobs))
	}
	if len(tb.Commitments) != 1 || len(tb.Zs) != 1 || len(tb.Ys) != 1 || len(tb.Proofs) != 1 || len(tb.VersionedHashes) != 1 {
		t.Fatalf("parallel arrays not sized 1")
	}

	// KZG verify each opening.
	for b, blob := range tb.Blobs {
		var point kzg4844.Point
		copy(point[:], tb.Zs[b][:])
		var claim kzg4844.Claim
		copy(claim[:], tb.Ys[b][:])
		if err := kzg4844.VerifyProof(tb.Commitments[b], point, claim, tb.Proofs[b]); err != nil {
			t.Errorf("kzg VerifyProof blob %d: %v", b, err)
		}
		// Belt-and-braces: BlobToCommitment must reproduce the same commitment.
		got, err := kzg4844.BlobToCommitment(&blob)
		if err != nil {
			t.Fatalf("BlobToCommitment: %v", err)
		}
		if got != tb.Commitments[b] {
			t.Errorf("commitment blob %d not stable", b)
		}
	}

	// Digest = sha256(com_0 || y_0 || ...).
	var buf bytes.Buffer
	for b := range tb.Commitments {
		buf.Write(tb.Commitments[b][:])
		buf.Write(tb.Ys[b][:])
	}
	want := sha256.Sum256(buf.Bytes())
	if tb.Digest != want {
		t.Errorf("digest mismatch:\n got  %x\n want %x", tb.Digest, want)
	}

	// Request() returns commitments-only KZGRequest.
	req := tb.Request("0x00000000000000000000000000000000000000000000000000000000deadbeef", "0x00")
	if req == nil || len(req.Commitments) != 1 {
		t.Fatalf("Request commitments count = %v", req)
	}
	// Commitment hex round-trips.
	raw, err := hex.DecodeString(req.Commitments[0][2:])
	if err != nil || len(raw) != 48 {
		t.Fatalf("commitment hex decode: %v", err)
	}
	if !bytes.Equal(raw, tb.Commitments[0][:]) {
		t.Errorf("commitment hex differs from raw bytes")
	}
}

// TestBuildTransitionBlobsMultipleBlobs forces T > cellsPerBlob to exercise
// the multi-blob path. n_updates chosen so total_cells lands just above 4096.
func TestBuildTransitionBlobsMultipleBlobs(t *testing.T) {
	// Compute how many updates it takes to overflow one blob at nf=16.
	// T = 2 + n_vids + n_updates*(1 + 2*nf) + 2*nf
	// Solve: n_updates > (4096 - 2 - 0 - 2*16) / (1 + 32) = 4062/33 ≈ 123.09
	// So 124 updates crosses into a 2nd blob.
	nf := 16
	nUpd := 124
	ballot := identityBallot()
	updates := make([]SlotUpdate, nUpd)
	for i := 0; i < nUpd; i++ {
		updates[i] = SlotUpdate{Key: uint64(0x10 + i), Ballot: ballot}
	}
	var pid, rhb [32]byte
	rhb[31] = 0x01

	tb, err := BuildTransitionBlobs(nf, pid, rhb, nil, updates, ballot)
	if err != nil {
		t.Fatalf("BuildTransitionBlobs: %v", err)
	}
	if len(tb.Blobs) != 2 {
		t.Fatalf("n_blobs = %d, want 2 (T=%d)", len(tb.Blobs), totalCells(0, nUpd, nf))
	}
	for b := range tb.Blobs {
		var point kzg4844.Point
		copy(point[:], tb.Zs[b][:])
		var claim kzg4844.Claim
		copy(claim[:], tb.Ys[b][:])
		if err := kzg4844.VerifyProof(tb.Commitments[b], point, claim, tb.Proofs[b]); err != nil {
			t.Errorf("kzg VerifyProof blob %d: %v", b, err)
		}
	}
}
