package chain

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// h32 returns a 32-byte arbo-LE hex field with byte i = base+i, distinct per
// field so a wrong frame offset shows up.
func h32(base byte) string {
	var b [32]byte
	for i := range b {
		b[i] = base + byte(i)
	}
	return hex.EncodeToString(b[:])
}

func wireConfig() *davinci.ChainConfig {
	return &davinci.ChainConfig{
		ProcessID:    h32(0x10),
		BallotMode:   h32(0x40),
		EncX:         h32(0x70),
		EncY:         h32(0xa0),
		CensusOrigin: 0x0102030405060708,
		CensusRoot:   h32(0xc0),
	}
}

// TestConfigFrameLayout pins the 168-byte frame layout: four 32-byte LE fields,
// then census_origin as u64 LE, then census_root.
func TestConfigFrameLayout(t *testing.T) {
	c := wireConfig()
	frame, err := ConfigFrame(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) != configFrameLen {
		t.Fatalf("frame len = %d, want %d", len(frame), configFrameLen)
	}
	dec := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	var want []byte
	want = append(want, dec(c.ProcessID)...)
	want = append(want, dec(c.BallotMode)...)
	want = append(want, dec(c.EncX)...)
	want = append(want, dec(c.EncY)...)
	want = binary.LittleEndian.AppendUint64(want, c.CensusOrigin)
	want = append(want, dec(c.CensusRoot)...)
	if !bytesEqual(frame, want) {
		t.Fatalf("frame mismatch:\n got %x\nwant %x", frame, want)
	}
}

// TestVKWordsRoundTrip checks the BE-hex → 4×u64 decode matches a manual split.
func TestVKWordsRoundTrip(t *testing.T) {
	vk := "0x" + CircuitRelease.AggVK[2:]
	w, err := VKWords(vk)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(vk, "0x"))
	for i := 0; i < 4; i++ {
		if w[i] != binary.BigEndian.Uint64(raw[i*8:]) {
			t.Fatalf("word %d = %x, want %x", i, w[i], binary.BigEndian.Uint64(raw[i*8:]))
		}
	}
}

// TestCanonicalConfigCommitment recomputes the commitment independently
// (sha256 over frame ‖ batchVK LE ‖ foldVK LE) and checks the helper agrees.
func TestCanonicalConfigCommitment(t *testing.T) {
	c := wireConfig()
	batch, err := CircuitRelease.BatchWords()
	if err != nil {
		t.Fatal(err)
	}
	fold, err := CircuitRelease.AggWords()
	if err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalConfigCommitment(c, batch, fold)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := ConfigFrame(c)
	h := sha256.New()
	h.Write(frame)
	for _, x := range batch {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], x)
		h.Write(b[:])
	}
	for _, x := range fold {
		var b [8]byte
		binary.LittleEndian.PutUint64(b[:], x)
		h.Write(b[:])
	}
	var want [32]byte
	copy(want[:], h.Sum(nil))
	if got != want {
		t.Fatalf("commitment = %x, want %x", got, want)
	}
}

// TestReleaseVerify checks the release manifest accepts its own vks and rejects
// a mismatch in either position.
func TestReleaseVerify(t *testing.T) {
	if err := CircuitRelease.Verify(CircuitRelease.AggVK, CircuitRelease.BatchVK); err != nil {
		t.Fatalf("self-verify failed: %v", err)
	}
	bad := "0x" + strings.Repeat("00", 32)
	if CircuitRelease.Verify(bad, CircuitRelease.BatchVK) == nil {
		t.Fatal("expected agg vk mismatch")
	}
	if CircuitRelease.Verify(CircuitRelease.AggVK, bad) == nil {
		t.Fatal("expected batch vk mismatch")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
