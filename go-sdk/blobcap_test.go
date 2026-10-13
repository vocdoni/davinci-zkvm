package davinci

import "testing"

// TestMaxSingleTxBatch pins the single-transaction capacity table: a steady
// batch of n votes carries n refreshes, each update is 2*nf point cells plus
// a quarter of an integer cell, six blobs hold 24576 cells.
func TestMaxSingleTxBatch(t *testing.T) {
	want := map[int]int{1: 1024, 2: 1024, 4: 1024, 5: 1024, 6: 992, 8: 750, 12: 504, 16: 379}
	for nf, n := range want {
		if got := MaxSingleTxBatch(nf); got != n {
			t.Errorf("MaxSingleTxBatch(%d) = %d, want %d", nf, got, n)
		}
	}
	if got := TransitionBlobCount(512, 1024, 16); got != 9 {
		t.Errorf("512 votes + 512 refreshes at 16 fields = %d blobs, want 9", got)
	}
	if got := TransitionBlobCount(1024, 2048, 2); got != 3 {
		t.Errorf("1024 votes + 1024 refreshes at 2 fields = %d blobs, want 3", got)
	}
}
