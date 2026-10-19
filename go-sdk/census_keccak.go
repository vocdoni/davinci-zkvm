package davinci

import (
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// KeccakHasher is the census lean-IMT node hash: keccak256(be32(a) || be32(b))
// read as a big-endian integer, which is Solidity's
// keccak256(abi.encode(a, b)). Nodes and roots are full 256-bit values and are
// never reduced mod the BN254 field. Use it with lean-imt-go:
// leanimt.New(davinci.KeccakHasher, ...). Panics on a negative or
// wider-than-256-bit input, a caller bug.
func KeccakHasher(a, b *big.Int) *big.Int {
	if a.Sign() < 0 || b.Sign() < 0 {
		panic("KeccakHasher: negative input")
	}
	var buf [64]byte
	a.FillBytes(buf[:32])
	b.FillBytes(buf[32:])
	return new(big.Int).SetBytes(crypto.Keccak256(buf[:]))
}
