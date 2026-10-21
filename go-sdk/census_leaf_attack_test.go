package davinci

import (
	"math/big"
	"testing"
)

// BUG: PackAddressWeight ORs an over-wide weight into the address bits, so (a, 2^88 + 5) silently becomes the member (a | 1, 5); rust-sdk census_leaf refuses it.
func TestPackAddressWeightRefusesOverWideInputs(t *testing.T) {
	one := big.NewInt(1)
	pow := func(n uint) *big.Int { return new(big.Int).Lsh(one, n) }
	odd := new(big.Int).SetUint64(0xDEADBEEF) // bit 0 set: the bleed is invisible
	for name, in := range map[string][2]*big.Int{
		"weight 2^88":          {odd, pow(88)},
		"weight 2^88 + 5":      {odd, new(big.Int).Add(pow(88), big.NewInt(5))},
		"weight 2^255":         {odd, pow(255)},
		"address 2^160":        {pow(160), one},
		"negative weight":      {odd, big.NewInt(-1)},
		"negative address":     {big.NewInt(-1), one},
		"address 2^160 + addr": {new(big.Int).Add(pow(160), odd), one},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: want panic, got a leaf", name)
				}
			}()
			PackAddressWeight(in[0], in[1])
		}()
	}
	// The widest legal inputs still pack.
	maxA := new(big.Int).Sub(pow(160), one)
	maxW := new(big.Int).Sub(pow(88), one)
	if got, want := PackAddressWeight(maxA, maxW), new(big.Int).Sub(pow(248), one); got.Cmp(want) != 0 {
		t.Errorf("max leaf = %x, want %x", got, want)
	}
}
