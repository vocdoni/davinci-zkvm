// teadd_test.go checks the local TE affine point addition against the
// gnark BabyJubJub implementation used by davinci-node.
package integration

import (
	"math/big"
	"testing"

	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
)

func TestTeAddMatchesGnark(t *testing.T) {
	curve := bjjgnark.New()
	toTE := func(p interface{ Point() (*big.Int, *big.Int) }) (*big.Int, *big.Int) {
		rx, ry := p.Point()
		return format.FromRTEtoTE(rx, ry)
	}

	for _, pair := range [][2]int64{{1, 1}, {2, 3}, {7, 11}, {123456, 654321}} {
		a := curve.New()
		a.ScalarBaseMult(big.NewInt(pair[0]))
		b := curve.New()
		b.ScalarBaseMult(big.NewInt(pair[1]))
		sum := curve.New()
		sum.SafeAdd(a, b)

		ax, ay := toTE(a)
		bx, by := toTE(b)
		wantX, wantY := toTE(sum)
		gotX, gotY := teAdd(ax, ay, bx, by)
		if gotX.Cmp(wantX) != 0 || gotY.Cmp(wantY) != 0 {
			t.Fatalf("teAdd(%d*G, %d*G) mismatch:\n got (%s, %s)\nwant (%s, %s)",
				pair[0], pair[1], gotX, gotY, wantX, wantY)
		}
		// Identity: (0,1) + P == P.
		idX, idY := teAdd(new(big.Int), big.NewInt(1), ax, ay)
		if idX.Cmp(ax) != 0 || idY.Cmp(ay) != 0 {
			t.Fatalf("identity + %d*G mismatch", pair[0])
		}
	}
}
