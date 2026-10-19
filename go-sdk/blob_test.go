package davinci

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
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
	vids := []uint64{1<<63 | 1}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x11, Ballot: ballot},
		{Key: 0x10, Ballot: ballot},
	}
	cells, err := TransitionCells(nf, vids, updates)
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// T = 1 + ceil((1 + 2)/4) + 2*2*2 = 10
	if len(cells) != 10 {
		t.Fatalf("len(cells) = %d, want 10", len(cells))
	}
	if got := hex.EncodeToString(cells[0][:]); got != "0000000000000000000000000000000000000000000000010000000000000002" {
		t.Errorf("header = %s", got)
	}
	// vid & (2^63-1) = 1 on top, then the keys ascending, one slot unused.
	if got := hex.EncodeToString(cells[1][:]); got != "0000000000000000200000000000000400000000000000088000000000000000" {
		t.Errorf("integer cell = %s", got)
	}
	// Each identity pack cell = enc_u64(1) (TE identity packs to 1).
	oneCell := encU64BE32(1)
	for i := 2; i < 10; i++ {
		if cells[i] != oneCell {
			t.Errorf("pack cell %d = %x", i, cells[i])
		}
	}
}

func TestPack4MatchesBigInt(t *testing.T) {
	const m = 1<<63 - 1
	for _, e := range [][4]uint64{{0, 0, 0, 0}, {1, 0x10, 0x11, m}, {m, m, m, m}, {m, 0, m, 0}, {0, m, 0, m}, {5, m - 2, 0x11, 0x30}} {
		want := new(big.Int)
		for _, x := range e {
			want.Lsh(want, 63)
			want.Or(want, new(big.Int).SetUint64(x))
		}
		var w [32]byte
		want.FillBytes(w[:])
		if got := pack4(e[0], e[1], e[2], e[3]); got != w {
			t.Errorf("pack4(%x) = %x, want %x", e, got, w)
		}
		if w[0]>>4 != 0 {
			t.Errorf("pack4(%x) at or above 2^252", e)
		}
	}
}

func TestTransitionCellsSortsInputs(t *testing.T) {
	nf := 1
	// Unsorted inputs: vids reverse, updates reverse.
	vids := []uint64{1<<63 | 9, 1<<63 | 5, 1<<63 | 3, 1<<63 | 1}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x20, Ballot: ballot},
		{Key: 0x10, Ballot: ballot},
	}
	cells, err := TransitionCells(nf, vids, updates)
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// Vote ids ascending fill the first integer cell, the keys the second.
	if cells[1] != pack4(1, 3, 5, 9) {
		t.Errorf("vote id cell = %x", cells[1])
	}
	if cells[2] != pack4(0x10, 0x20, 0, 0) {
		t.Errorf("key cell = %x", cells[2])
	}
	if len(cells) != 1+2+2*2 {
		t.Errorf("len(cells) = %d", len(cells))
	}
}

func TestTransitionCellsMasksVoteIDs(t *testing.T) {
	// The guest packs vid & (2^63-1), so an id without the top bit (which
	// it rejects elsewhere) lays out like the same id with it.
	updates := []SlotUpdate{{Key: 0x10, Ballot: identityBallot()}}
	low, err := TransitionCells(1, []uint64{5}, updates)
	if err != nil {
		t.Fatal(err)
	}
	high, err := TransitionCells(1, []uint64{1<<63 | 5}, updates)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(flat(low), flat(high)) {
		t.Errorf("masked vote id lays out differently")
	}
}

func flat(cells [][32]byte) []byte {
	var out []byte
	for _, c := range cells {
		out = append(out, c[:]...)
	}
	return out
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
	cells, err := TransitionCells(nf, nil, updates)
	if err != nil {
		t.Fatalf("TransitionCells: %v", err)
	}
	// Layout: [header, keys, c1_0, c2_0, c1_1, c2_1].
	if got0 := cells[2]; got0 != encU64BE32(1) {
		t.Errorf("first (ballot0) c1 pack = %x, want enc(1)", got0)
	}
	if got1 := cells[4]; got1 != encU64BE32(2) {
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
		{0, 0, 1, 1},
		{1, 2, 2, 1 + 1 + 2*2*2},
		{0, 4, 1, 1 + 1 + 2*4},
		{1, 4, 1, 1 + 2 + 2*4},
		{10, 128, 16, 1 + 35 + 2*16*128},
		{126, 126, 16, 4096},
		{1, 127, 16, 4097},
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
	vids := []uint64{1<<63 | 1, 1<<63 | 2}
	ballot := identityBallot()
	updates := []SlotUpdate{
		{Key: 0x10, Ballot: ballot},
		{Key: 0x11, Ballot: ballot},
	}
	var pid, rhb [32]byte
	pid[31] = 0x42
	rhb[31] = 0x01

	tb, err := BuildTransitionBlobs(nf, pid, rhb, vids, updates)
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

// TestBuildTransitionBlobsMultipleBlobs crosses the blob boundary at 16
// fields: 126 votes fill one blob exactly (T = 4096), one vote with 126
// refreshes puts a single cell in a second blob (T = 4097).
func TestBuildTransitionBlobsMultipleBlobs(t *testing.T) {
	nf := 16
	ballot := identityBallot()
	for _, c := range []struct{ nVids, nUpd, blobs int }{{126, 126, 1}, {1, 127, 2}} {
		vids := make([]uint64, c.nVids)
		for i := range vids {
			vids[i] = 1<<63 | uint64(i)
		}
		updates := make([]SlotUpdate, c.nUpd)
		for i := range updates {
			updates[i] = SlotUpdate{Key: uint64(0x10 + i), Ballot: ballot}
		}
		var pid, rhb [32]byte
		rhb[31] = 0x01
		tb, err := BuildTransitionBlobs(nf, pid, rhb, vids, updates)
		if err != nil {
			t.Fatalf("BuildTransitionBlobs: %v", err)
		}
		if len(tb.Blobs) != c.blobs || TransitionBlobCount(c.nVids, c.nUpd, nf) != c.blobs {
			t.Fatalf("n_blobs = %d, want %d (T=%d)", len(tb.Blobs), c.blobs, totalCells(c.nVids, c.nUpd, nf))
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
}

// Known-answer inputs shared with rust-sdk tests/blob.rs and the registry's
// forge tests: every byte distinct, so a reversed or shifted field shows up.
func katPointInputs() (pid, rootBE, d [32]byte, com [48]byte) {
	for i := range pid {
		pid[i] = byte(i) // 31-byte process id: top byte zero
		rootBE[i] = byte(0x3f - i)
		d[i] = byte(0x40 + i)
	}
	for i := range com {
		com[i] = byte(0x60 + i)
	}
	return
}

func TestEvaluationPointKnownAnswers(t *testing.T) {
	pid, rootBE, d, com := katPointInputs()
	for _, c := range []struct {
		n, b int
		want string
	}{
		{3, 2, "2e68404174db9baf4868d118f11d7785ab9229ff6ca34ff9f13a2e9b5b28c858"},
		{32, 31, "380120e02ac40876fbff01e9c74d852999b7dcd028c008fb5898b8f64236a5f7"},
		// The raw hash is above r_bls here: the reduction is exercised.
		{1, 0, "1b5d86841b7b84d14f182c18852689813b81270252cb91c62467600f1e924f71"},
	} {
		z := EvaluationPoint(pid, rootBE, d, c.n, c.b, com)
		if got := hex.EncodeToString(z[:]); got != c.want {
			t.Errorf("z(n=%d, b=%d) = %s, want %s", c.n, c.b, got, c.want)
		}
	}
	cells := [][32]byte{{}, {}, {}}
	for i := range cells {
		for j := range cells[i] {
			cells[i][j] = byte(i + 1)
		}
	}
	d2 := CellsDigest(2, cells)
	if got := hex.EncodeToString(d2[:]); got != "68aa598b4b224849460be6b385c0a75f409f16a2546ba18c864fd069a97d5a8c" {
		t.Errorf("CellsDigest = %s", got)
	}
}

// TestEvaluationPointPreimage locks the field order and widths against a
// hand-assembled preimage, and that index, count and D each move the point.
func TestEvaluationPointPreimage(t *testing.T) {
	pid, rootBE, d, com := katPointInputs()
	var pre []byte
	pre = append(pre, "davinci/point/v1"...)
	pre = append(pre, pid[:]...)
	pre = append(pre, rootBE[:]...)
	pre = append(pre, d[:]...)
	pre = binary.BigEndian.AppendUint64(pre, 5)
	pre = binary.BigEndian.AppendUint64(pre, 4)
	pre = append(pre, com[:]...)
	sum := sha256.Sum256(pre)
	var want [32]byte
	new(big.Int).Mod(new(big.Int).SetBytes(sum[:]), blsFrModulus).FillBytes(want[:])
	if got := EvaluationPoint(pid, rootBE, d, 5, 4, com); got != want {
		t.Fatalf("EvaluationPoint = %x, want %x", got, want)
	}
	seen := map[[32]byte]bool{want: true}
	d2 := d
	d2[31] ^= 1
	for _, z := range [][32]byte{
		EvaluationPoint(pid, rootBE, d, 5, 3, com),
		EvaluationPoint(pid, rootBE, d, 6, 4, com),
		EvaluationPoint(pid, rootBE, d2, 5, 4, com),
	} {
		if seen[z] {
			t.Errorf("point did not move: %x", z)
		}
		seen[z] = true
	}
}

// TestCellsDigestPreimage: D = sha256(tag || u64_be(nf) || u64_be(T) ||
// cells), and a trailing zero cell (padding) is not absorbed silently.
func TestCellsDigestPreimage(t *testing.T) {
	ballot := identityBallot()
	cells, err := TransitionCells(2, []uint64{1<<63 | 9}, []SlotUpdate{{Key: 0x10, Ballot: ballot}, {Key: 0x11, Ballot: ballot}})
	if err != nil {
		t.Fatal(err)
	}
	var pre []byte
	pre = append(pre, "davinci/cells/v1"...)
	pre = binary.BigEndian.AppendUint64(pre, 2)
	pre = binary.BigEndian.AppendUint64(pre, uint64(len(cells)))
	pre = append(pre, flat(cells)...)
	if got, want := CellsDigest(2, cells), sha256.Sum256(pre); got != want {
		t.Fatalf("CellsDigest = %x, want %x", got, want)
	}
	if CellsDigest(2, append(cells, [32]byte{})) == CellsDigest(2, cells) {
		t.Error("a zero cell appended leaves D unchanged")
	}
	if CellsDigest(3, cells) == CellsDigest(2, cells) {
		t.Error("D ignores num_fields")
	}
}

// TestChallengeBindsRefreshSelection is the regression for the evaluation
// point fixed before the content: two valid refresh selections (one slot of
// an adjacent occupied pair, same position in the sorted stream), the same
// old root and the same sequencer-supplied commitments must give different
// points. Under sha256(pid || root || C) they were equal, which let a
// sequencer fit the content to a wrong blob's value at a known point.
func TestChallengeBindsRefreshSelection(t *testing.T) {
	const nf = 2
	vids := []uint64{1<<63 | 77}
	vote := SlotUpdate{Key: 0x40, Ballot: identityBallot()}
	refreshed := identityBallot()
	refreshed[1] = "0x0000000000000000000000000000000000000000000000000000000000000002"
	var pid, rootBE [32]byte
	pid[30], pid[31] = 0x12, 0x34
	rootBE[0], rootBE[31] = 0x56, 0x78

	build := func(refreshKey uint64) *TransitionBlobs {
		tb, err := BuildTransitionBlobs(nf, pid, rootBE, vids,
			[]SlotUpdate{vote, {Key: refreshKey, Ballot: refreshed}})
		if err != nil {
			t.Fatal(err)
		}
		return tb
	}
	a, b := build(0x20), build(0x21)
	if len(a.Cells) != len(b.Cells) || len(a.Blobs) != 1 || len(b.Blobs) != 1 {
		t.Fatal("selections must give the same layout shape")
	}
	if a.CellsDigest == b.CellsDigest {
		t.Fatal("D equal for different refresh selections")
	}
	// The same supplied commitment for both: the points must still differ.
	c := [48]byte(a.Commitments[0])
	za := EvaluationPoint(pid, rootBE, a.CellsDigest, 1, 0, c)
	zb := EvaluationPoint(pid, rootBE, b.CellsDigest, 1, 0, c)
	if za == zb {
		t.Fatal("same point for two refresh selections under one commitment")
	}
	if za != a.Zs[0] {
		t.Fatal("BuildTransitionBlobs did not open at EvaluationPoint")
	}
}

// TestBuildTransitionBlobsPointsPerBlob: in a multi-blob transition every
// blob is opened at its own point from the shared D, count and index.
func TestBuildTransitionBlobsPointsPerBlob(t *testing.T) {
	ballot := identityBallot()
	updates := make([]SlotUpdate, 127)
	for i := range updates {
		updates[i] = SlotUpdate{Key: uint64(0x10 + i), Ballot: ballot}
	}
	var pid, rootBE [32]byte
	pid[31], rootBE[0] = 7, 9
	tb, err := BuildTransitionBlobs(16, pid, rootBE, []uint64{1 << 63}, updates)
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Blobs) != 2 {
		t.Fatalf("n_blobs = %d, want 2", len(tb.Blobs))
	}
	if tb.CellsDigest != CellsDigest(16, tb.Cells) {
		t.Fatal("CellsDigest not over the unpadded cells")
	}
	for b := range tb.Blobs {
		if want := EvaluationPoint(pid, rootBE, tb.CellsDigest, 2, b, [48]byte(tb.Commitments[b])); tb.Zs[b] != want {
			t.Errorf("blob %d opened at %x, want %x", b, tb.Zs[b], want)
		}
	}
}
