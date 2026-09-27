package davinci

import (
	"fmt"
	"math/big"
	"testing"
)

func TestSlotKey(t *testing.T) {
	// Cross-checked with Python hashlib (rust-sdk/testdata/slot.json).
	if got := SlotKey([20]byte{}); got != 2427519085662816786 {
		t.Fatalf("zero address slot %d", got)
	}
	var addr [20]byte
	for i := range addr {
		addr[i] = byte(0xa0 + i)
	}
	want := SlotKey(addr)
	if want < BallotMin || want > BallotMax {
		t.Fatalf("slot %#x outside the ballot namespace", want)
	}
	leaf := PackAddressWeight(new(big.Int).SetBytes(addr[:]), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 88), big.NewInt(1)))
	// Bits above 247 are not part of the address the guest binds.
	junk := new(big.Int).Add(leaf, new(big.Int).Lsh(big.NewInt(1), 248))
	for _, l := range []*big.Int{leaf, junk} {
		got, err := CensusProof{Leaf: fmt.Sprintf("0x%064x", l)}.SlotKey()
		if err != nil || got != want {
			t.Fatalf("leaf %x: slot %#x, %v; want %#x", l, got, err, want)
		}
	}
	if _, err := (CensusProof{Leaf: "0xzz"}).SlotKey(); err == nil {
		t.Fatal("bad leaf hex accepted")
	}
}
