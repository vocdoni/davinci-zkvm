package davinci

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"
)

// TestEncodeReencBlockLayout asserts the REENCBLK binary layout: the batch
// seed sits right after pub_key_y, each voter body is exactly 2 * NumFields
// ciphertexts (4 Fr words each), and bodies are back to back.
func TestEncodeReencBlockLayout(t *testing.T) {
	// Two voters: a per-voter seed word would shift the second body.
	entries := make([]ReencryptionEntry, 2)
	entries[1].Original[0].C1.X = "0x11"
	rd := NewReencryptionData(big.NewInt(0xAA), big.NewInt(0xBB), big.NewInt(0xCC), entries)

	buf, err := EncodeReencBlock(rd)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}

	// Header: magic(8) + n_voters(8) + pub_key_x(32) + pub_key_y(32) + seed(32) = 112.
	const headerLen = 8 + 8 + 32 + 32 + 32
	// Per voter: (original 16 + reencrypted 16) ciphertexts * 4 Fr words * 32 bytes.
	const perVoterLen = NumFields * 2 * 4 * 32
	want := headerLen + perVoterLen*len(entries)
	if len(buf) != want {
		t.Fatalf("REENCBLK length = %d, want %d (per-voter k word must be gone)", len(buf), want)
	}

	// Magic
	if !bytes.Equal(buf[0:8], []byte("REENCBLK")) {
		t.Errorf("magic = %q, want REENCBLK", buf[0:8])
	}

	// n_voters
	if got := binary.LittleEndian.Uint64(buf[8:16]); got != 2 {
		t.Errorf("n_voters = %d, want 2", got)
	}
	// Second voter's first word sits right after the first voter's body.
	if got := binary.LittleEndian.Uint64(buf[headerLen+perVoterLen : headerLen+perVoterLen+8]); got != 0x11 {
		t.Errorf("entry[1] first word = 0x%x, want 0x11", got)
	}

	// Seed sits at offset 8 + 8 + 32 + 32 = 80 and reads back as our value.
	const seedOff = 8 + 8 + 32 + 32
	seedLo := binary.LittleEndian.Uint64(buf[seedOff : seedOff+8])
	if seedLo != 0xCC {
		t.Errorf("seed low word = 0x%x, want 0xCC", seedLo)
	}
	// Upper three seed words must be zero for this small value.
	for i := 1; i < 4; i++ {
		w := binary.LittleEndian.Uint64(buf[seedOff+i*8 : seedOff+(i+1)*8])
		if w != 0 {
			t.Errorf("seed word[%d] = 0x%x, want 0", i, w)
		}
	}

	// pub_key_x low word.
	if got := binary.LittleEndian.Uint64(buf[16:24]); got != 0xAA {
		t.Errorf("pub_key_x low word = 0x%x, want 0xAA", got)
	}
	// pub_key_y low word.
	if got := binary.LittleEndian.Uint64(buf[48:56]); got != 0xBB {
		t.Errorf("pub_key_y low word = 0x%x, want 0xBB", got)
	}
}

// TestEncodeReencBlockNil returns nil for nil / empty inputs.
func TestEncodeReencBlockNil(t *testing.T) {
	if buf, err := EncodeReencBlock(nil); err != nil || buf != nil {
		t.Errorf("nil input: got (%v, %v), want (nil, nil)", buf, err)
	}
	rd := &ReencryptionData{}
	if buf, err := EncodeReencBlock(rd); err != nil || buf != nil {
		t.Errorf("empty entries: got (%v, %v), want (nil, nil)", buf, err)
	}
}
