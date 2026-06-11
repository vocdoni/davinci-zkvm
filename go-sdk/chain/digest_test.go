package chain

import (
	"encoding/binary"
	"testing"
)

// buildPublics assembles a synthetic 53-word digest blob.
func buildPublics(mode, steps, voters, overwrites uint32, batchVK, foldVK [4]uint64, results [8]uint64) []byte {
	b := make([]byte, digestWords*4)
	copy(b[0:4], "DAG1")
	put := func(i int, v uint32) { binary.LittleEndian.PutUint32(b[i*4:], v) }
	put(1, mode)
	put(2, steps)
	put(3, voters)
	put(4, overwrites)
	for i := 0; i < 8; i++ {
		put(5+i, uint32(0xc0+i))  // config commitment words
		put(13+i, uint32(0x50+i)) // state root words
	}
	putVK := func(off int, vk [4]uint64) {
		for i, v := range vk {
			put(off+i*2, uint32(v))
			put(off+i*2+1, uint32(v>>32))
		}
	}
	putVK(21, batchVK)
	putVK(29, foldVK)
	for i, r := range results {
		put(37+i*2, uint32(r))
		put(37+i*2+1, uint32(r>>32))
	}
	return b
}

func TestParseDigest(t *testing.T) {
	batchVK := [4]uint64{0x1122334455667788, 0x99aabbccddeeff00, 1, 2}
	foldVK := [4]uint64{0xdeadbeefcafe0123, 3, 4, 5}
	results := [8]uint64{50, 18, 38, 22, 26, 26, 0, 1 << 40}
	pub := buildPublics(ModeFinalize, 7, 14, 2, batchVK, foldVK, results)

	d, err := ParseDigest(pub)
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if d.Mode != ModeFinalize || d.StepCount != 7 || d.TotalVoters != 14 || d.TotalOverwrites != 2 {
		t.Errorf("header mismatch: %+v", d)
	}
	if d.BatchVK != "0x1122334455667788"+"99aabbccddeeff00"+
		"0000000000000001"+"0000000000000002" {
		t.Errorf("batch_vk = %s", d.BatchVK)
	}
	if d.FoldVK != "0xdeadbeefcafe0123"+"0000000000000003"+
		"0000000000000004"+"0000000000000005" {
		t.Errorf("fold_vk = %s", d.FoldVK)
	}
	if d.Results != results {
		t.Errorf("results = %v, want %v", d.Results, results)
	}
	if len(d.StateRoot) != 32 || len(d.ConfigCommitment) != 32 {
		t.Errorf("root/commitment lengths: %d, %d", len(d.StateRoot), len(d.ConfigCommitment))
	}

	if err := d.VerifyBinding(d.FoldVK, d.BatchVK); err != nil {
		t.Errorf("VerifyBinding (matching): %v", err)
	}
	if err := d.VerifyBinding(d.BatchVK, d.BatchVK); err == nil {
		t.Error("VerifyBinding accepted a wrong fold_vk")
	}
	if err := d.VerifyBinding(d.FoldVK, d.FoldVK); err == nil {
		t.Error("VerifyBinding accepted a wrong batch_vk")
	}

	if !d.SameChain(d) {
		t.Error("SameChain(self) = false")
	}

	if _, err := ParseDigest(pub[:52]); err == nil {
		t.Error("ParseDigest accepted a short blob")
	}
	pub[0] = 'X'
	if _, err := ParseDigest(pub); err == nil {
		t.Error("ParseDigest accepted a bad magic")
	}
}
