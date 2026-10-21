package davinci

import "testing"

// BUG: CSPSlotKey wraps or leaves the ballot namespace for an index >= 2^63 - 16, where rust-sdk slot_key_csp errors and the guest refuses the batch; there is no checked variant.
func TestCSPSlotKeyCheckedBounds(t *testing.T) {
	for _, idx := range []uint64{0, 1, 1<<63 - 17} {
		got, err := CSPSlotKeyChecked(idx)
		if err != nil || got != BallotMin+idx || got > BallotMax {
			t.Errorf("CSPSlotKeyChecked(%d) = %#x, %v; want %#x", idx, got, err, BallotMin+idx)
		}
	}
	for _, idx := range []uint64{1<<63 - 16, 1 << 63, ^uint64(0) - 15, ^uint64(0)} {
		if got, err := CSPSlotKeyChecked(idx); err == nil {
			t.Errorf("CSPSlotKeyChecked(%#x) = %#x, want an error", idx, got)
		}
	}
}
