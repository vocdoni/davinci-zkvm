// results_te_test.go: raw affine BabyJubJub arithmetic and hand-built
// Chaum-Pedersen proofs for results_cheat_test.go. The gnark types only build
// prime-subgroup points with honest commitments; the attacks need torsion
// points, extra terms in A1/A2 and challenges hashed the wrong way.
package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/hash/poseidon"
)

// tePt is an affine point in standard twisted Edwards coordinates, the form
// the guest reads.
type tePt struct{ x, y *big.Int }

var (
	teB8 = tePt{bigDec("5299619240641551281634865583518297030282874472190772894086521144482721001553"),
		bigDec("16950150798460657717958625567821834550301663161624707787222815936182638968203")}
)

func bigDec(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad decimal " + s)
	}
	return v
}

func teIdentity() tePt { return tePt{big.NewInt(0), big.NewInt(1)} }

func fmod(v *big.Int) *big.Int { return v.Mod(v, bn254ScalarField) }

func fmul(a, b *big.Int) *big.Int { return fmod(new(big.Int).Mul(a, b)) }

func finv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(fmod(new(big.Int).Set(a)), bn254ScalarField)
}

// ptAdd adds two points with helpers.go's teAdd.
func ptAdd(p, q tePt) tePt {
	x, y := teAdd(p.x, p.y, q.x, q.y)
	return tePt{x, y}
}

func teNeg(p tePt) tePt { return tePt{fmod(new(big.Int).Neg(p.x)), new(big.Int).Set(p.y)} }

// teMul is double-and-add over the full scalar (no reduction).
func teMul(p tePt, k *big.Int) tePt {
	r := teIdentity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = ptAdd(r, r)
		if k.Bit(i) == 1 {
			r = ptAdd(r, p)
		}
	}
	return r
}

func teEq(p, q tePt) bool { return p.x.Cmp(q.x) == 0 && p.y.Cmp(q.y) == 0 }

func teOnCurve(p tePt) bool {
	x2, y2 := fmul(p.x, p.x), fmul(p.y, p.y)
	lhs := fmod(new(big.Int).Add(fmul(bjjTEA, x2), y2))
	rhs := fmod(new(big.Int).Add(big.NewInt(1), fmul(bjjTED, fmul(x2, y2))))
	return lhs.Cmp(rhs) == 0
}

func (p tePt) hex() (string, string) { return le32Hex(p.x), le32Hex(p.y) }

// tePtFromHex reads a point from two arbo-LE hex coordinates.
func tePtFromHex(t *testing.T, x, y string) tePt {
	t.Helper()
	return tePt{leHexInt(t, x), leHexInt(t, y)}
}

// teOrder2 is (0, -1).
func teOrder2() tePt { return tePt{big.NewInt(0), new(big.Int).Sub(bn254ScalarField, big.NewInt(1))} }

// teOrder4 is (1/sqrt(a), 0).
func teOrder4(t *testing.T) tePt {
	t.Helper()
	x := new(big.Int).ModSqrt(finv(bjjTEA), bn254ScalarField)
	if x == nil {
		t.Fatal("1/a is not a square")
	}
	return tePt{x, big.NewInt(0)}
}

// teOrder8 finds a point of order 8: l*Q for curve points Q until 4*(l*Q) != O.
func teOrder8(t *testing.T) tePt {
	t.Helper()
	for y := int64(2); y < 1000; y++ {
		yy := big.NewInt(y)
		y2 := fmul(yy, yy)
		num := fmod(new(big.Int).Sub(big.NewInt(1), y2))
		den := fmod(new(big.Int).Sub(bjjTEA, fmul(bjjTED, y2)))
		x := new(big.Int).ModSqrt(fmul(num, finv(den)), bn254ScalarField)
		if x == nil {
			continue
		}
		q := teMul(tePt{x, yy}, bjjSubOrder)
		if !teEq(teMul(q, big.NewInt(4)), teIdentity()) {
			return q
		}
	}
	t.Fatal("no order-8 point found")
	return tePt{}
}

// cpChallenge is the guest's Fiat-Shamir challenge: Poseidon over the RTE
// coordinates of (pk, pk, C1, D, A1, A2).
func cpChallenge(t *testing.T, pk, c1, d, a1, a2 tePt) *big.Int {
	t.Helper()
	in := make([]*big.Int, 0, 12)
	for _, p := range []tePt{pk, pk, c1, d, a1, a2} {
		rx, ry := format.FromTEtoRTE(p.x, p.y)
		in = append(in, rx, ry)
	}
	e, err := poseidon.MultiPoseidon(in...)
	if err != nil {
		t.Fatalf("poseidon: %v", err)
	}
	return e
}

// cpSpec describes a hand-built proof: A1 = w*B8 + a1Extra, A2 = w*C1 +
// a2Extra, e = chal(...) (the guest's challenge when nil), z = (w + e*s) mod l.
type cpSpec struct {
	s, w             *big.Int
	pk, c1, c2       tePt
	m                uint64
	a1Extra, a2Extra *tePt
	chal             func(t *testing.T, pk, c1, d, a1, a2 tePt) *big.Int
}

func cpHandmade(t *testing.T, sp cpSpec) davinci.CpProof {
	t.Helper()
	a1 := teMul(teB8, sp.w)
	if sp.a1Extra != nil {
		a1 = ptAdd(a1, *sp.a1Extra)
	}
	a2 := teMul(sp.c1, sp.w)
	if sp.a2Extra != nil {
		a2 = ptAdd(a2, *sp.a2Extra)
	}
	d := ptAdd(sp.c2, teNeg(teMul(teB8, new(big.Int).SetUint64(sp.m))))
	var e *big.Int
	if sp.chal != nil {
		e = sp.chal(t, sp.pk, sp.c1, d, a1, a2)
	} else {
		e = cpChallenge(t, sp.pk, sp.c1, d, a1, a2)
	}
	z := new(big.Int).Mul(e, sp.s)
	z.Add(z, sp.w).Mod(z, bjjSubOrder)
	return cpJSON(a1, a2, z)
}

func cpJSON(a1, a2 tePt, z *big.Int) davinci.CpProof {
	a1x, a1y := a1.hex()
	a2x, a2y := a2.hex()
	return davinci.CpProof{A1X: a1x, A1Y: a1y, A2X: a2x, A2Y: a2y, Z: le32Hex(z)}
}

// cpTorsionKey proves m = 0 for the identity ciphertext under pk = s*B8 + T,
// T of order k (k = 1 for T = O). z*B8 has no torsion, so A1 must carry
// -e*T: guess g = e mod k, set A1 = w*B8 - g*T and retry until the guess holds.
func cpTorsionKey(t *testing.T, s *big.Int, pk, tor tePt, k int64) davinci.CpProof {
	t.Helper()
	id := teIdentity()
	for w := int64(1); w < 1000; w++ {
		wb := teMul(teB8, big.NewInt(w))
		for g := int64(0); g < k; g++ {
			a1 := ptAdd(wb, teNeg(teMul(tor, big.NewInt(g))))
			e := cpChallenge(t, pk, id, id, a1, id)
			if new(big.Int).Mod(e, big.NewInt(k)).Int64() != g {
				continue
			}
			z := new(big.Int).Mul(e, s)
			z.Add(z, big.NewInt(w)).Mod(z, bjjSubOrder)
			return cpJSON(a1, id, z)
		}
	}
	t.Fatal("no challenge matched the torsion guess")
	return davinci.CpProof{}
}

// identityAccumulator is the empty-election accumulator: 16 x ((0,1),(0,1)).
func identityAccumulator() []*big.Int {
	out := make([]*big.Int, 0, davinci.BallotFields)
	for i := 0; i < davinci.NumFields; i++ {
		out = append(out, big.NewInt(0), big.NewInt(1), big.NewInt(0), big.NewInt(1))
	}
	return out
}

// teKeyLeaf is the 0x03 leaf value of an arbitrary point.
func teKeyLeaf(p tePt) *big.Int {
	var buf [64]byte
	p.x.FillBytes(buf[:32])
	p.y.FillBytes(buf[32:])
	d := sha256.Sum256(buf[:])
	return new(big.Int).SetBytes(d[:])
}

// rawResultsRequest commits pk and coords to a fresh tree and returns a request
// carrying them with the given tallies and proofs, plus the root.
func rawResultsRequest(t *testing.T, nf int, pk tePt, coords []*big.Int, results []uint64,
	proofs []davinci.CpProof) (resultsRequest, []byte) {
	t.Helper()
	root, siblings := buildResultsTree(t, nf, teKeyLeaf(pk), accLeafValue(coords))
	x, y := pk.hex()
	r := resultsRequest{
		StateRoot:   hex.EncodeToString(root),
		EncKeyX:     x,
		EncKeyY:     y,
		KeySiblings: siblings(0x03),
		AccSiblings: siblings(keyResults),
		Results:     append([]uint64(nil), results...),
		CpProofs:    append([]davinci.CpProof(nil), proofs...),
	}
	for _, c := range coords {
		r.Accumulator = append(r.Accumulator, le32Hex(c))
	}
	return r, root
}

// arboLeafHash is the arbo leaf hash sha256(key_le8 || value_le32 || 0x01).
func arboLeafHash(key uint64, value *big.Int) []byte {
	buf := append(arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(key)), arbo.BigIntToBytes(32, value)...)
	d := sha256.Sum256(append(buf, 0x01))
	return d[:]
}

// sibDepth returns the number of siblings up to the last non-zero one.
func sibDepth(t *testing.T, sibs []string) int {
	t.Helper()
	zero := hex.EncodeToString(make([]byte, 32))
	n := 0
	for i, s := range sibs {
		if s != zero {
			n = i + 1
		}
	}
	return n
}
