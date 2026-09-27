package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	bjj "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec/params"
)

// writePoseidonConstants extracts the optimized iden3 constants (C, S, M, P
// for t = 2..17) from go-iden3-crypto's constants.go and writes them as
//
//	per t: u32le t | u32le len(C) | C | u32le len(S) | S | M (t*t, row-major) | P (t*t)
//
// every value a 32-byte big-endian integer.
func writePoseidonConstants(path string) error {
	dirOut, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/iden3/go-iden3-crypto").Output()
	if err != nil {
		return fmt.Errorf("locate go-iden3-crypto: %w", err)
	}
	src := filepath.Join(strings.TrimSpace(string(dirOut)), "poseidon", "constants.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		return err
	}
	var lit *ast.CompositeLit
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "cs" {
			return true
		}
		lit, _ = vs.Values[0].(*ast.CompositeLit)
		return false
	})
	if lit == nil {
		return fmt.Errorf("cs literal not found in %s", src)
	}
	fields := map[string]ast.Expr{}
	for _, e := range lit.Elts {
		kv := e.(*ast.KeyValueExpr)
		fields[kv.Key.(*ast.Ident).Name] = kv.Value
	}
	c := strings2D(fields["C"])
	s := strings2D(fields["S"])
	m := strings3D(fields["M"])
	p := strings3D(fields["P"])
	if len(c) != 16 || len(s) != 16 || len(m) != 16 || len(p) != 16 {
		return fmt.Errorf("unexpected constant table sizes")
	}
	var buf bytes.Buffer
	u32 := func(v int) { _ = binary.Write(&buf, binary.LittleEndian, uint32(v)) }
	val := func(h string) {
		v, ok := new(big.Int).SetString(h, 16)
		if !ok || v.Cmp(fieldP) >= 0 {
			panic("bad poseidon constant " + h)
		}
		buf.Write(be32(v))
	}
	for i := 0; i < 16; i++ {
		t := i + 2
		u32(t)
		u32(len(c[i]))
		for _, h := range c[i] {
			val(h)
		}
		u32(len(s[i]))
		for _, h := range s[i] {
			val(h)
		}
		for _, mat := range [][][]string{m[i], p[i]} {
			if len(mat) != t {
				return fmt.Errorf("t=%d: matrix has %d rows", t, len(mat))
			}
			for _, row := range mat {
				if len(row) != t {
					return fmt.Errorf("t=%d: row has %d cols", t, len(row))
				}
				for _, h := range row {
					val(h)
				}
			}
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Println("wrote", path, buf.Len(), "bytes")
	return nil
}

func strings1D(e ast.Expr) []string {
	cl := e.(*ast.CompositeLit)
	out := make([]string, len(cl.Elts))
	for i, el := range cl.Elts {
		s, err := strconv.Unquote(el.(*ast.BasicLit).Value)
		if err != nil {
			panic(err)
		}
		out[i] = s
	}
	return out
}

func strings2D(e ast.Expr) [][]string {
	cl := e.(*ast.CompositeLit)
	out := make([][]string, len(cl.Elts))
	for i, el := range cl.Elts {
		out[i] = strings1D(el)
	}
	return out
}

func strings3D(e ast.Expr) [][][]string {
	cl := e.(*ast.CompositeLit)
	out := make([][][]string, len(cl.Elts))
	for i, el := range cl.Elts {
		out[i] = strings2D(el)
	}
	return out
}

// Poseidon: widths 1..16, inputs 1..n plus three random sets per width.
type poseidonVec struct {
	Inputs []string `json:"inputs"`
	Output string   `json:"output"`
}

func poseidonVectors() []poseidonVec {
	var out []poseidonVec
	for n := 1; n <= 16; n++ {
		sets := [][]*big.Int{}
		seq := make([]*big.Int, n)
		for i := range seq {
			seq[i] = big.NewInt(int64(i + 1))
		}
		sets = append(sets, seq)
		for r := 0; r < 3; r++ {
			in := make([]*big.Int, n)
			for i := range in {
				in[i] = randField()
			}
			sets = append(sets, in)
		}
		for _, in := range sets {
			h, err := poseidon.Hash(in)
			must(err)
			out = append(out, poseidonVec{Inputs: decs(in), Output: dec(h)})
		}
	}
	return out
}

// TE point as decimal coordinates, plus our compressed form and the RTE image.
type pointJSON struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type bjjPointVec struct {
	K          string    `json:"k,omitempty"`
	P          pointJSON `json:"p"`
	Compressed string    `json:"compressed"`
	Rte        pointJSON `json:"rte"`
}

type bjjAddVec struct {
	A   pointJSON `json:"a"`
	B   pointJSON `json:"b"`
	Sum pointJSON `json:"sum"`
}

func pj(x, y *big.Int) pointJSON { return pointJSON{X: dec(x), Y: dec(y)} }

// compressTE is the SDK's point encoding: BE32(y + ((x & 1) << 254)).
func compressTE(x, y *big.Int) string {
	v := new(big.Int).Set(y)
	if x.Bit(0) == 1 {
		v.SetBit(v, 254, 1)
	}
	return hex32(v)
}

func bjjPointVector(k *big.Int, p *babyjub.Point) bjjPointVec {
	rx, ry := format.FromTEtoRTE(p.X, p.Y)
	v := bjjPointVec{P: pj(p.X, p.Y), Compressed: compressTE(p.X, p.Y), Rte: pj(rx, ry)}
	if k != nil {
		v.K = dec(k)
	}
	return v
}

func bjjVectors() map[string]any {
	b8 := babyjub.B8
	var muls []bjjPointVec
	muls = append(muls, bjjPointVector(big.NewInt(0), babyjub.NewPoint().Mul(big.NewInt(0), b8)))
	for _, k := range []int64{1, 2, 3, 7, 1000} {
		kk := big.NewInt(k)
		muls = append(muls, bjjPointVector(kk, babyjub.NewPoint().Mul(kk, b8)))
	}
	for i := 0; i < 16; i++ {
		k := randBelow(babyjub.SubOrder)
		muls = append(muls, bjjPointVector(k, babyjub.NewPoint().Mul(k, b8)))
	}
	// Full-width scalars (above the subgroup order, as the guest's unreduced muls use).
	for i := 0; i < 4; i++ {
		k := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), 256))
		muls = append(muls, bjjPointVector(k, babyjub.NewPoint().Mul(k, b8)))
	}
	var adds []bjjAddVec
	for i := 0; i < 12; i++ {
		a := babyjub.NewPoint().Mul(randBelow(babyjub.SubOrder), b8)
		b := babyjub.NewPoint().Mul(randBelow(babyjub.SubOrder), b8)
		if i == 0 {
			b = a
		}
		sum := babyjub.NewPointProjective().Add(a.Projective(), b.Projective()).Affine()
		adds = append(adds, bjjAddVec{A: pj(a.X, a.Y), B: pj(b.X, b.Y), Sum: pj(sum.X, sum.Y)})
	}
	return map[string]any{
		"b8":        pj(b8.X, b8.Y),
		"sub_order": dec(babyjub.SubOrder),
		"muls":      muls,
		"adds":      adds,
	}
}

// gnark (RTE) point <-> TE helpers.
func teOf(p ecc.Point) (*big.Int, *big.Int) { return format.FromRTEtoTE(p.Point()) }

func pjOf(p ecc.Point) pointJSON { return pj(teOf(p)) }

func gnarkFromTE(x, y *big.Int) *bjj.BJJ {
	rx, ry := format.FromTEtoRTE(x, y)
	return new(bjj.BJJ).SetPoint(rx, ry).(*bjj.BJJ)
}

// Fixed election key used by several vector sets.
func fixedKey() (*big.Int, *bjj.BJJ) {
	sk, _ := new(big.Int).SetString("1234567890123456789012345678901234567890", 10)
	pk := bjj.New().(*bjj.BJJ)
	pk.ScalarBaseMult(sk)
	return sk, pk
}

type cipherJSON struct {
	C1 pointJSON `json:"c1"`
	C2 pointJSON `json:"c2"`
}

type encVec struct {
	M  string     `json:"m"`
	K  string     `json:"k"`
	Ct cipherJSON `json:"ct"`
}

type ballotEncVec struct {
	Nf     int      `json:"nf"`
	K      string   `json:"k"`
	Fields []uint64 `json:"fields"`
	Ballot []string `json:"ballot"` // 64 TE coords
}

func ctJSON(c *elgamal.Ciphertext) cipherJSON {
	return cipherJSON{C1: pjOf(c.C1), C2: pjOf(c.C2)}
}

func ballotTE(b *elgamal.Ballot) []string { return decs(b.FromRTEtoTE().BigInts()) }

// encryptBallot mirrors ballotproof.GenerateBallotProofInputs: the Poseidon
// k-chain over all 16 fields, then identity padding of fields >= nf.
func encryptBallot(pk *bjj.BJJ, fields []uint64, k *big.Int, nf int) *elgamal.Ballot {
	var msg [params.FieldsPerBallot]*big.Int
	for i := range msg {
		msg[i] = new(big.Int)
		if i < len(fields) {
			msg[i].SetUint64(fields[i])
		}
	}
	b, err := elgamal.NewBallot(pk).Encrypt(msg, pk, k)
	must(err)
	if nf > 0 && nf < params.FieldsPerBallot {
		for i := nf; i < params.FieldsPerBallot; i++ {
			b.Ciphertexts[i] = elgamal.NewCiphertext(pk)
		}
	}
	return b
}

func randFields(nf int, max int) []uint64 {
	out := make([]uint64, nf)
	for i := range out {
		out[i] = uint64(rng.Intn(max))
	}
	return out
}

func elgamalVectors() map[string]any {
	sk, pk := fixedKey()
	var encs []encVec
	for _, m := range []uint64{0, 1, 2, 5, 1000, 999999} {
		k := randBelow(pk.Order())
		c1, c2 := elgamal.EncryptWithK(pk, new(big.Int).SetUint64(m), k)
		encs = append(encs, encVec{M: fmt.Sprint(m), K: dec(k), Ct: cipherJSON{C1: pjOf(c1), C2: pjOf(c2)}})
	}
	var ballots []ballotEncVec
	for _, nf := range []int{1, 6, 16} {
		k := randField()
		fields := randFields(nf, 1<<16)
		b := encryptBallot(pk, fields, k, nf)
		ballots = append(ballots, ballotEncVec{Nf: nf, K: dec(k), Fields: fields, Ballot: ballotTE(b)})
	}
	return map[string]any{
		"sk":          dec(sk),
		"pk":          pjOf(pk),
		"encryptions": encs,
		"ballots":     ballots,
	}
}

type cpVec struct {
	M  string     `json:"m"`
	Ct cipherJSON `json:"ct"`
	R  string     `json:"r"`
	A1 pointJSON  `json:"a1"`
	A2 pointJSON  `json:"a2"`
	E  string     `json:"e"`
	Z  string     `json:"z"`
}

// buildCP is elgamal.BuildDecryptionProof with the nonce r injected.
func buildCP(sk *big.Int, pk ecc.Point, c1, c2 ecc.Point, msg, r *big.Int) (*elgamal.DecryptionProof, *big.Int) {
	order := pk.Order()
	a1 := pk.New()
	a1.ScalarBaseMult(r)
	a2 := pk.New()
	a2.ScalarMult(c1, r)
	m := new(big.Int).Mod(msg, order)
	mp := pk.New()
	mp.ScalarBaseMult(m)
	d := pk.New()
	d.Set(c2)
	neg := pk.New()
	neg.Neg(mp)
	d.Add(d, neg)
	e, err := elgamal.HashPointsToScalar(pk, pk, c1, d, a1, a2)
	must(err)
	z := new(big.Int).Mul(e, sk)
	z.Add(z, r)
	z.Mod(z, order)
	proof := &elgamal.DecryptionProof{A1: a1, A2: a2, Z: z}
	must(elgamal.VerifyDecryptionProof(pk, c1, c2, new(big.Int).Set(msg), proof))
	return proof, e
}

func cpVectorsGen() map[string]any {
	sk, pk := fixedKey()
	var out []cpVec
	for _, m := range []uint64{0, 1, 3, 77, 123456} {
		// Accumulate a few encryptions so the ciphertext is not a fresh one.
		c := elgamal.NewCiphertext(pk)
		left := m
		for j := 0; j < 3; j++ {
			part := left
			if j < 2 {
				part = left / 2
			}
			left -= part
			k := randBelow(pk.Order())
			c1, c2 := elgamal.EncryptWithK(pk, new(big.Int).SetUint64(part), k)
			c.Add(c, &elgamal.Ciphertext{C1: c1, C2: c2})
		}
		r := randBelow(pk.Order())
		proof, e := buildCP(sk, pk, c.C1, c.C2, new(big.Int).SetUint64(m), r)
		out = append(out, cpVec{
			M: fmt.Sprint(m), Ct: ctJSON(c), R: dec(r),
			A1: pjOf(proof.A1), A2: pjOf(proof.A2), E: dec(e), Z: dec(proof.Z),
		})
	}
	return map[string]any{"sk": dec(sk), "pk": pjOf(pk), "vectors": out}
}

type reencCase struct {
	Seed    string     `json:"seed"`     // BE32 hex, as on the wire
	OldRoot string     `json:"old_root"` // raw arbo root bytes, hex
	Nf      int        `json:"nf"`
	Pk      pointJSON  `json:"pk"`
	Scalars []string   `json:"scalars"` // first chain values
	Ballots [][]string `json:"ballots"`
	Reenc   [][]string `json:"reencrypted"`
}

func reencVectors() map[string]any {
	golden := elgamal.NewReencChain(big.NewInt(1), big.NewInt(2))
	var gold []string
	for i := 0; i < 3; i++ {
		gold = append(gold, hex32(golden.Next()))
	}
	_, pk := fixedKey()
	var cases []reencCase
	for _, nf := range []int{2, 5, 16} {
		seed := randBelow(pk.Order())
		rootBytes := randBytes(32)
		// arbo roots are little-endian integers.
		rootInt := new(big.Int).SetBytes(reverse(rootBytes))
		probe := elgamal.NewReencChain(seed, rootInt)
		var scalars []string
		for i := 0; i < 3; i++ {
			scalars = append(scalars, dec(probe.Next()))
		}
		chain := elgamal.NewReencChain(seed, rootInt)
		c := reencCase{Seed: hex32(seed), OldRoot: fmt.Sprintf("%x", rootBytes), Nf: nf, Pk: pjOf(pk), Scalars: scalars}
		for j := 0; j < 3; j++ {
			b := encryptBallot(pk, randFields(nf, 100), randField(), nf)
			rb, err := b.ReencryptChained(pk, chain, nf)
			must(err)
			c.Ballots = append(c.Ballots, ballotTE(b))
			c.Reenc = append(c.Reenc, ballotTE(rb))
		}
		cases = append(cases, c)
	}
	return map[string]any{"golden": gold, "cases": cases}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[i] = b[len(b)-1-i]
	}
	return out
}

type modeJSON struct {
	NumFields    uint8  `json:"num_fields"`
	GroupSize    uint8  `json:"group_size"`
	UniqueValues bool   `json:"unique_values"`
	CostExponent uint8  `json:"cost_exponent"`
	MaxValue     uint64 `json:"max_value"`
	MinValue     uint64 `json:"min_value"`
	MaxValueSum  uint64 `json:"max_value_sum"`
	MinValueSum  uint64 `json:"min_value_sum"`
	Packed       string `json:"packed"`
}

func modeOf(bm spec.BallotMode) modeJSON {
	p, err := bm.Pack()
	must(err)
	return modeJSON{bm.NumFields, bm.GroupSize, bm.UniqueValues, bm.CostExponent,
		bm.MaxValue, bm.MinValue, bm.MaxValueSum, bm.MinValueSum, dec(p)}
}

var ballotModes = []spec.BallotMode{
	{NumFields: 1, GroupSize: 1, MaxValue: 1, MinValue: 0, MaxValueSum: 1},
	{NumFields: 2, GroupSize: 1, UniqueValues: false, CostExponent: 1, MaxValue: 3, MinValue: 0, MaxValueSum: 6, MinValueSum: 0},
	{NumFields: 6, GroupSize: 6, UniqueValues: true, CostExponent: 2, MaxValue: 16, MinValue: 1, MaxValueSum: 1000, MinValueSum: 1},
	{NumFields: 16, GroupSize: 3, UniqueValues: true, CostExponent: 255, MaxValue: 1<<48 - 1, MinValue: 1<<48 - 2, MaxValueSum: 1<<63 - 1, MinValueSum: 1<<63 - 2},
	{NumFields: 8, GroupSize: 0, UniqueValues: false, CostExponent: 0, MaxValue: 0, MinValue: 0, MaxValueSum: 0, MinValueSum: 0},
}

func ballotModeVectors() []modeJSON {
	var out []modeJSON
	for _, bm := range ballotModes {
		out = append(out, modeOf(bm))
	}
	return out
}

// ballotLeafHash mirrors chain.ballotLeafHash on TE coordinates: sha256 of
// the 64 coords as BE32 words (raw digest).
func ballotLeafHash(coords []*big.Int) string {
	var buf []byte
	for _, c := range coords {
		buf = append(buf, be32(c)...)
	}
	return sha256Hex(buf)
}

func identityCoords() []*big.Int {
	out := make([]*big.Int, 64)
	for i := range out {
		out[i] = big.NewInt(int64(i % 2))
	}
	return out
}

func hashVectors() map[string]any {
	_, pk := fixedKey()
	type leaf struct {
		Ballot []string `json:"ballot"`
		Hash   string   `json:"hash"`
	}
	var leaves []leaf
	for _, nf := range []int{1, 7, 16} {
		b := encryptBallot(pk, randFields(nf, 50), randField(), nf)
		coords := b.FromRTEtoTE().BigInts()
		leaves = append(leaves, leaf{Ballot: decs(coords), Hash: ballotLeafHash(coords)})
	}
	x, y := teOf(pk)
	vkLocal, err := os.ReadFile(*vkAsset)
	must(err)
	return map[string]any{
		"ballot_leaves":     leaves,
		"enc_key":           map[string]any{"pk": pj(x, y), "hash": sha256Hex(append(be32(x), be32(y)...))},
		"identity_ballot":   ballotLeafHash(identityCoords()),
		"ballot_vk_leaf":    hex32(ballotVKLeaf(vkLocal)),
		"ballot_vk_leaf_v1": hex32(ballotVKLeaf(circomV1VK())),
	}
}
