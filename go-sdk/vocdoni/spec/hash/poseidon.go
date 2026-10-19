package hash

import (
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// PoseidonHash hashes the provided inputs with iden3 Poseidon.
func PoseidonHash(inputs ...*big.Int) (*big.Int, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs provided")
	}
	for i, v := range inputs {
		if v == nil {
			return nil, fmt.Errorf("nil input at index %d", i)
		}
	}
	return poseidon.Hash(inputs)
}
