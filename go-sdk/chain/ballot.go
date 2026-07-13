// ballot.go holds the homomorphic results accumulator: NumFields ElGamal
// ciphertexts as BallotFields Twisted Edwards coordinates, accumulated by
// BabyJubJub point addition like davinci-node's Ballot.Add.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// bn254ScalarField is the BN254 scalar field order (Fr), the BabyJubJub
// base field.
var bn254ScalarField, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// Twisted Edwards parameters for BabyJubJub (standard form).
var (
	bjjTEA = big.NewInt(168700)
	bjjTED = big.NewInt(168696)
)

// accumBallot is a ballot as BallotFields TE coordinates: NumFields
// ciphertexts x [c1x, c1y, c2x, c2y].
type accumBallot [davinci.BallotFields]*big.Int

// newIdentityAccum returns the identity accumulator: every point is the
// TE identity (0, 1), matching davinci-node elgamal.NewBallot.
func newIdentityAccum() accumBallot {
	var b accumBallot
	for i := range b {
		if i%2 == 1 {
			b[i] = big.NewInt(1)
		} else {
			b[i] = new(big.Int)
		}
	}
	return b
}

// teAdd adds two BabyJubJub points in standard Twisted Edwards affine form:
//
//	x3 = (x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2)
//	y3 = (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2)
func teAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := bn254ScalarField
	x1y2 := new(big.Int).Mul(x1, y2)
	y1x2 := new(big.Int).Mul(y1, x2)
	y1y2 := new(big.Int).Mul(y1, y2)
	x1x2 := new(big.Int).Mul(x1, x2)
	dxy := new(big.Int).Mul(bjjTED, new(big.Int).Mul(x1x2, y1y2))
	dxy.Mod(dxy, p)
	num3 := new(big.Int).Add(x1y2, y1x2)
	den3 := new(big.Int).Add(big.NewInt(1), dxy)
	num4 := new(big.Int).Sub(y1y2, new(big.Int).Mul(bjjTEA, x1x2))
	den4 := new(big.Int).Sub(big.NewInt(1), dxy)
	x3 := new(big.Int).Mul(num3, new(big.Int).ModInverse(den3.Mod(den3, p), p))
	y3 := new(big.Int).Mul(num4, new(big.Int).ModInverse(den4.Mod(den4, p), p))
	return x3.Mod(x3, p), y3.Mod(y3, p)
}

// accumFromBallot converts an elgamal.Ballot to TE coordinates.
func accumFromBallot(ballot *elgamal.Ballot) accumBallot {
	var acc accumBallot
	for i := 0; i < davinci.NumFields; i++ {
		rx, ry := ballot.Ciphertexts[i].C1.Point()
		c1tx, c1ty := format.FromRTEtoTE(rx, ry)
		rx2, ry2 := ballot.Ciphertexts[i].C2.Point()
		c2tx, c2ty := format.FromRTEtoTE(rx2, ry2)
		acc[i*4] = c1tx
		acc[i*4+1] = c1ty
		acc[i*4+2] = c2tx
		acc[i*4+3] = c2ty
	}
	return acc
}

// accumAdd adds two ballots homomorphically: point addition of each of
// the BallotFields/2 (x, y) coordinate pairs.
func accumAdd(a, b accumBallot) accumBallot {
	var out accumBallot
	for i := 0; i < davinci.BallotFields/2; i++ {
		out[i*2], out[i*2+1] = teAdd(a[i*2], a[i*2+1], b[i*2], b[i*2+1])
	}
	return out
}

// accumSub subtracts b from a homomorphically: a + (-b), where the TE
// inverse of (x, y) is (-x, y). Matches davinci-node's Ballot.Neg + Add.
func accumSub(a, b accumBallot) accumBallot {
	p := bn254ScalarField
	var negB accumBallot
	for i := 0; i < davinci.BallotFields/2; i++ {
		negB[i*2] = new(big.Int).Mod(new(big.Int).Neg(b[i*2]), p)
		negB[i*2+1] = b[i*2+1]
	}
	return accumAdd(a, negB)
}

// accumLeafHash computes the SHA-256 leaf value of an accumulator:
// 32 coordinates as 32-byte big-endian words.
func accumLeafHash(acc accumBallot) *big.Int {
	h := sha256.New()
	buf := make([]byte, 32)
	for _, v := range acc {
		v.FillBytes(buf)
		h.Write(buf)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// accumToStrings converts an accumulator to BallotFields big-endian hex strings.
func accumToStrings(acc accumBallot) []string {
	out := make([]string, davinci.BallotFields)
	for i, v := range acc {
		out[i] = bigIntToFr32(v)
	}
	return out
}

// ballotLeafHash computes the SHA-256 arbo leaf value of a ballot stored
// in the state tree: BallotFields TE coordinates as 32-byte big-endian words.
func ballotLeafHash(b *elgamal.Ballot) *big.Int {
	h := sha256.New()
	buf := make([]byte, 32)
	for i := 0; i < davinci.NumFields; i++ {
		if b.Ciphertexts[i] == nil {
			zeroCoord := make([]byte, 32)
			oneCoord := make([]byte, 32)
			oneCoord[31] = 1
			h.Write(zeroCoord)
			h.Write(oneCoord)
			h.Write(zeroCoord)
			h.Write(oneCoord)
			continue
		}
		c1rx, c1ry := b.Ciphertexts[i].C1.Point()
		c1tx, c1ty := format.FromRTEtoTE(c1rx, c1ry)
		c2rx, c2ry := b.Ciphertexts[i].C2.Point()
		c2tx, c2ty := format.FromRTEtoTE(c2rx, c2ry)
		for _, coord := range []*big.Int{c1tx, c1ty, c2tx, c2ty} {
			coord.FillBytes(buf)
			h.Write(buf)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// ballotToFrStrings converts a ballot to BallotFields big-endian hex strings
// in TE coordinates, for BallotProofData.
func ballotToFrStrings(b *elgamal.Ballot) []string {
	out := make([]string, davinci.BallotFields)
	for i := 0; i < davinci.NumFields; i++ {
		if b.Ciphertexts[i] == nil {
			out[i*4] = bigIntToFr32(big.NewInt(0))
			out[i*4+1] = bigIntToFr32(big.NewInt(1))
			out[i*4+2] = bigIntToFr32(big.NewInt(0))
			out[i*4+3] = bigIntToFr32(big.NewInt(1))
			continue
		}
		c1x, c1y := bjjPointToFr32Hex(b.Ciphertexts[i].C1)
		c2x, c2y := bjjPointToFr32Hex(b.Ciphertexts[i].C2)
		out[i*4] = c1x
		out[i*4+1] = c1y
		out[i*4+2] = c2x
		out[i*4+3] = c2y
	}
	return out
}

// bigIntToFr32 converts v to a 0x-prefixed 32-byte big-endian hex string.
func bigIntToFr32(v *big.Int) string {
	b := v.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return "0x" + hex.EncodeToString(padded)
}

// bjjPointToFr32Hex converts a BabyJubJub point from RTE to TE and
// returns the coordinates as 0x-prefixed 32-byte big-endian hex.
func bjjPointToFr32Hex(p interface{ Point() (*big.Int, *big.Int) }) (xHex, yHex string) {
	rx, ry := p.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	return bigIntToFr32(tx), bigIntToFr32(ty)
}
