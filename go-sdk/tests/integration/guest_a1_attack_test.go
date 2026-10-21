// guest_a1_attack_test.go is the hardening-campaign-2 malicious-host sweep of
// the vote-batch guest. Every case starts from an honest batch built by the
// cheat harness, tampers the smallest host-controlled value and runs the
// committed ELF on ziskemu. Cases that must be accepted say so: they pin a
// property the consumer (registry, fold guest) relies on. Same prerequisites
// as cheat_test.go (ziskemu, gen-input, the circuit ELF).
package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/ethereum/go-ethereum/crypto"
	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	leanimt "github.com/vocdoni/lean-imt-go"
)

// --- helpers ---------------------------------------------------------------

// leGet reads a 32-byte little-endian integer.
func leGet(b []byte) *big.Int {
	be := make([]byte, 32)
	for i := 0; i < 32; i++ {
		be[i] = b[31-i]
	}
	return new(big.Int).SetBytes(be)
}

// lePut writes v as a 32-byte little-endian integer; false if v >= 2^256.
func lePut(b []byte, v *big.Int) bool {
	if v.Sign() < 0 || v.BitLen() > 256 {
		return false
	}
	be := make([]byte, 32)
	v.FillBytes(be)
	for i := 0; i < 32; i++ {
		b[i] = be[31-i]
	}
	return true
}

// runGuest runs input and returns the registers, or nil and the emulator
// error when the guest aborts instead of committing.
func runGuest(t *testing.T, input []byte) ([]uint32, error) {
	t.Helper()
	out, err := runZiskEmu(input)
	if err == nil && len(out) < davinci.OutputRegisters {
		t.Fatalf("ziskemu returned %d registers", len(out))
	}
	return out, err
}

// proofOff is the offset of proof i's record (A ‖ B ‖ C) in the full input.
func proofOff(t *testing.T, base *cheatElectionInput, i int) int {
	t.Helper()
	off, n, _ := proofsSectionOffset(t, base.baseBin)
	if i >= n {
		t.Fatalf("proof %d of %d", i, n)
	}
	return off + i*proofRecordLen
}

// g2FromLE decodes a guest G2 point (x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1, LE words).
func g2FromLE(b []byte) bn254.G2Affine {
	var p bn254.G2Affine
	p.X.A0.SetBigInt(leGet(b[0:32]))
	p.X.A1.SetBigInt(leGet(b[32:64]))
	p.Y.A0.SetBigInt(leGet(b[64:96]))
	p.Y.A1.SetBigInt(leGet(b[96:128]))
	return p
}

// g2ToLE encodes p in the guest layout.
func g2ToLE(b []byte, p *bn254.G2Affine) {
	for i, e := range []*fp.Element{&p.X.A0, &p.X.A1, &p.Y.A0, &p.Y.A1} {
		lePut(b[i*32:(i+1)*32], e.BigInt(new(big.Int)))
	}
}

// g1FromLE / g1ToLE are the G1 counterparts (x ‖ y).
func g1FromLE(b []byte) bn254.G1Affine {
	var p bn254.G1Affine
	p.X.SetBigInt(leGet(b[0:32]))
	p.Y.SetBigInt(leGet(b[32:64]))
	return p
}

func g1ToLE(b []byte, p *bn254.G1Affine) {
	lePut(b[0:32], p.X.BigInt(new(big.Int)))
	lePut(b[32:64], p.Y.BigInt(new(big.Int)))
}

// twistB is the coefficient of the BN254 twist, 3 / (9 + u).
func twistB() bn254.E2 {
	var tw, b bn254.E2
	tw.A0.SetUint64(9)
	tw.A1.SetUint64(1)
	b.Inverse(&tw)
	var three fp.Element
	three.SetUint64(3)
	b.MulByElement(&b, &three)
	return b
}

// randomTwistPoint is a uniformly random point of E'(Fp2); it lies outside
// G2 except with probability 1/h.
func randomTwistPoint(t *testing.T) bn254.G2Affine {
	t.Helper()
	b := twistB()
	for {
		var x, y, rhs bn254.E2
		if _, err := x.SetRandom(); err != nil {
			t.Fatalf("SetRandom: %v", err)
		}
		rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &b)
		if rhs.Legendre() != 1 {
			continue
		}
		y.Sqrt(&rhs)
		p := bn254.G2Affine{X: x, Y: y}
		if !p.IsOnCurve() {
			t.Fatal("random twist point is off the curve")
		}
		return p
	}
}

// twistMul is double-and-add on any twist point (gnark's GLV multiplication
// assumes G2).
func twistMul(q *bn254.G2Affine, s *big.Int) bn254.G2Affine {
	var acc, base bn254.G2Jac
	acc.X.SetOne()
	acc.Y.SetOne()
	acc.Z.SetZero()
	base.FromAffine(q)
	for i := s.BitLen() - 1; i >= 0; i-- {
		acc.DoubleAssign()
		if s.Bit(i) == 1 {
			acc.AddAssign(&base)
		}
	}
	var out bn254.G2Affine
	out.FromJacobian(&acc)
	return out
}

// twistTorsion is a non-identity point of order dividing the twist cofactor
// h = 2p - r: [r] of a random twist point.
func twistTorsion(t *testing.T) bn254.G2Affine {
	t.Helper()
	for {
		r := randomTwistPoint(t)
		tor := twistMul(&r, fr.Modulus())
		if !tor.IsInfinity() {
			return tor
		}
	}
}

// --- §4 1.2–1.4: proof points ------------------------------------------------

// proofCoords are the eight Fp coordinates of a proof record.
var proofCoords = []struct {
	name string
	off  int // within the proof record
}{
	{"A.x", 0}, {"A.y", 32},
	{"B.x.c0", 64}, {"B.x.c1", 96}, {"B.y.c0", 128}, {"B.y.c1", 160},
	{"C.x", 192}, {"C.y", 224},
}

// plusQ returns full with the coordinate at o re-encoded as x + k·q, or nil
// when that does not fit 256 bits.
func plusQ(full []byte, o int, k int64) []byte {
	out := append([]byte(nil), full...)
	v := new(big.Int).Add(leGet(out[o:o+32]), new(big.Int).Mul(fp.Modulus(), big.NewInt(k)))
	if !lePut(out[o:o+32], v) {
		return nil
	}
	return out
}

// setCoord returns full with the coordinate at o replaced by v.
func setCoord(full []byte, o int, v *big.Int) []byte {
	out := append([]byte(nil), full...)
	lePut(out[o:o+32], v)
	return out
}

// onCurveWithX returns a G1 point whose x is the residue of raw (encoded raw,
// so x >= q for raw = q or 2^256 - 1), or nil when x^3 + 3 is not a square.
func onCurveWithX(raw *big.Int) (x, y *big.Int) {
	var fx, rhs, fy, three fp.Element
	fx.SetBigInt(raw)
	three.SetUint64(3)
	rhs.Square(&fx).Mul(&rhs, &fx).Add(&rhs, &three)
	if fy.Sqrt(&rhs) == nil {
		return nil, nil
	}
	return raw, fy.BigInt(new(big.Int))
}

// TestCheatAttackProofPointEncodings feeds every host-chosen encoding of the
// proof points, in a one-proof batch (r_0 = 1, no random coefficient) and
// for proofs 0 and 1 of a two-proof batch: each coordinate + q (B's four Fq
// limbs included), x exactly q and 2^256 - 1 (off-curve as they come, and
// re-solved onto the curve), the identity A, B and C, and twist points
// outside G2 as B. Each is refused with exactly FAIL_CURVE, before the
// transcript and before any precompile sees the point (1.2-1.4).
func TestCheatAttackProofPointEncodings(t *testing.T) {
	q := fp.Modulus()
	allOnes := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	one, _, _ := buildCheatInputN(t, 1)
	two, _, _ := buildCheatInput(t)
	for _, run := range []struct {
		name  string
		base  *cheatElectionInput
		proof int
	}{{"n1_p0", one, 0}, {"n2_p0", two, 0}, {"n2_p1", two, 1}} {
		full := run.base.fullInput()
		rec := proofOff(t, run.base, run.proof)
		label := func(s string) string { return run.name + "_" + s }

		for _, c := range proofCoords {
			if in := plusQ(full, rec+c.off, 1); in != nil {
				assertCircuitFailsExactly(t, in, failCurve, label(c.name+"_plus_q"))
			}
			for name, v := range map[string]*big.Int{"eq_q": q, "all_ones": allOnes} {
				in := setCoord(full, rec+c.off, v)
				assertCircuitFailsExactly(t, in, failCurve, label(c.name+"_"+name+"_off_curve"))
			}
		}
		// x = q or 2^256 - 1 with y solved: an on-curve point with a
		// non-canonical x that is not the proof's A or C.
		for _, pt := range []struct {
			name string
			off  int
		}{{"A", 0}, {"C", 192}} {
			for name, raw := range map[string]*big.Int{"eq_q": q, "all_ones": allOnes} {
				x, y := onCurveWithX(raw)
				if x == nil {
					t.Logf("%s: x^3 + 3 is not a square for x = %s, skipped", label(pt.name), name)
					continue
				}
				in := setCoord(setCoord(full, rec+pt.off, x), rec+pt.off+32, y)
				assertCircuitFailsExactly(t, in, failCurve, label(pt.name+"_x_"+name+"_on_curve"))
			}
		}
		// Identity points (all-zero encoding, the pairing's 𝒪).
		for _, pt := range []struct {
			name     string
			off, len int
		}{{"A", 0, 64}, {"B", 64, 128}, {"C", 192, 64}} {
			in := append([]byte(nil), full...)
			for i := rec + pt.off; i < rec+pt.off+pt.len; i++ {
				in[i] = 0
			}
			assertCircuitFailsExactly(t, in, failCurve, label("identity_"+pt.name))
		}
		// B outside G2: B + T keeps B's G2 component, a random twist point has
		// none in particular.
		b := g2FromLE(full[rec+64 : rec+192])
		if !b.IsInSubGroup() {
			t.Fatalf("%s: honest B is not in G2", run.name)
		}
		tor := twistTorsion(t)
		var bt bn254.G2Affine
		bt.Add(&b, &tor)
		rnd := randomTwistPoint(t)
		for name, p := range map[string]*bn254.G2Affine{"B_plus_torsion": &bt, "B_random_twist_point": &rnd} {
			if p.IsInSubGroup() || !p.IsOnCurve() {
				t.Fatalf("%s should be on the twist and outside G2", name)
			}
			in := append([]byte(nil), full...)
			g2ToLE(in[rec+64:rec+192], p)
			assertCircuitFailsExactly(t, in, failCurve, label(name))
		}
	}
}

// TestCheatAttackProofZeroNonCanonical: proof 0's A, and C of a one-proof
// batch, re-encoded as x + k·q. r_0 = 1 makes scalar_mul_bn254 return the raw
// point and the pairing reduces it, while the transcript hashes the raw limbs:
// the bound below q refuses them with exactly FAIL_CURVE.
func TestCheatAttackProofZeroNonCanonical(t *testing.T) {
	two, _, _ := buildCheatInput(t)
	one, _, _ := buildCheatInputN(t, 1)
	for _, c := range proofCoords {
		if c.name[0] == 'B' {
			continue
		}
		for _, k := range []int64{1, 5} {
			if full := plusQ(two.fullInput(), proofOff(t, two, 0)+c.off, k); full != nil && c.name[0] == 'A' {
				assertCircuitFailsExactly(t, full, failCurve, fmt.Sprintf("2_proofs_proof0_%s_plus_%dq", c.name, k))
			}
			if full := plusQ(one.fullInput(), proofOff(t, one, 0)+c.off, k); full != nil {
				assertCircuitFailsExactly(t, full, failCurve, fmt.Sprintf("1_proof_%s_plus_%dq", c.name, k))
			}
		}
	}
}

// TestCheatAttackProofMalleated re-randomises honest proofs: (-A, -B, C) and
// (k·A, k⁻¹·B, C) are valid proofs of the same statement. The guest accepts
// them with the same registers, so a proof's bytes are no identifier: no
// consumer may deduplicate or bind votes by proof encoding.
func TestCheatAttackProofMalleated(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	honest := runAccepted(t, base.fullInput(), "honest")
	k, err := rand.Int(rand.Reader, fr.Modulus())
	if err != nil {
		t.Fatal(err)
	}
	kInv := new(big.Int).ModInverse(k, fr.Modulus())
	for name, tamper := range map[string]func(a *bn254.G1Affine, b *bn254.G2Affine){
		"negate_A_B": func(a *bn254.G1Affine, b *bn254.G2Affine) { a.Neg(a); b.Neg(b) },
		"scale_A_B": func(a *bn254.G1Affine, b *bn254.G2Affine) {
			a.ScalarMultiplication(a, k)
			b.ScalarMultiplication(b, kInv)
		},
	} {
		full := base.fullInput()
		for proof := 0; proof < 2; proof++ {
			o := proofOff(t, base, proof)
			a := g1FromLE(full[o : o+64])
			b := g2FromLE(full[o+64 : o+192])
			tamper(&a, &b)
			g1ToLE(full[o:o+64], &a)
			g2ToLE(full[o+64:o+192], &b)
		}
		out := runAccepted(t, full, name)
		for i := 0; i < davinci.OutputRegisters; i++ {
			if out[i] != honest[i] {
				t.Errorf("[%s] register %d = %#x, honest %#x", name, i, out[i], honest[i])
			}
		}
	}
}

// --- §5: ECDSA encodings -------------------------------------------------------

// secp256k1N is the secp256k1 group order.
var secp256k1N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)

// TestCheatAttackECDSAEncodings tampers voter 0's signature record
// (r ‖ s ‖ recid, LE). Encodings that recover the same key over the same
// vote envelope are harmless; anything else must fail 2.5/2.6.
func TestCheatAttackECDSAEncodings(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	off, nproofs, _ := proofsSectionOffset(t, base.baseBin)
	sigOff := func(i int) int { return off + nproofs*proofRecordLen + i*72 }
	read := func(full []byte, i int) (r, s *big.Int, v uint64) {
		o := sigOff(i)
		return leGet(full[o : o+32]), leGet(full[o+32 : o+64]), binary.LittleEndian.Uint64(full[o+64 : o+72])
	}
	write := func(full []byte, i int, r, s *big.Int, v uint64) {
		o := sigOff(i)
		lePut(full[o:o+32], r)
		lePut(full[o+32:o+64], s)
		binary.LittleEndian.PutUint64(full[o+64:o+72], v)
	}

	t.Run("recid_high_bits_ignored", func(t *testing.T) {
		full := base.fullInput()
		r, s, v := read(full, 0)
		write(full, 0, r, s, v|0x100) // the guest reads the low byte only
		runAccepted(t, full, "recid_0x100")
	})
	t.Run("high_s_accepted", func(t *testing.T) {
		full := base.fullInput()
		r, s, v := read(full, 0)
		write(full, 0, r, new(big.Int).Sub(secp256k1N, s), v^1)
		runAccepted(t, full, "high_s")
	})
	for name, tamper := range map[string]func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64){
		"recid_2":    func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) { return r, s, 2 },
		"recid_flip": func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) { return r, s, v ^ 1 },
		"s_zero":     func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) { return r, new(big.Int), v },
		"s_equals_n": func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) { return r, secp256k1N, v },
		"r_zero":     func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) { return new(big.Int), s, v },
		"r_plus_n": func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) {
			return new(big.Int).Add(r, secp256k1N), s, v
		},
		"s_plus_n": func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) {
			return r, new(big.Int).Add(s, secp256k1N), v
		},
		"r_all_ones": func(r, s *big.Int, v uint64) (*big.Int, *big.Int, uint64) {
			return new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), s, v
		},
	} {
		full := base.fullInput()
		r, s, v := read(full, 0)
		r, s, v = tamper(r, s, v)
		if !lePut(make([]byte, 32), r) || !lePut(make([]byte, 32), s) {
			t.Logf("%s: does not fit 256 bits, skipped", name)
			continue
		}
		write(full, 0, r, s, v)
		assertCircuitFailsExactly(t, full, failECDSA, name)
	}
	t.Run("swapped_signatures", func(t *testing.T) {
		full := base.fullInput()
		r0, s0, v0 := read(full, 0)
		r1, s1, v1 := read(full, 1)
		write(full, 0, r1, s1, v1)
		write(full, 1, r0, s0, v0)
		assertCircuitFailsExactly(t, full, failECDSA, "swapped_signatures")
	})
}

// TestCheatAttackVoteEnvelope re-signs voter 0 with its own key over vote
// envelopes other than the one the guest derives: another process id, one
// original ciphertext changed, and the retired vote-id-only message. Each
// recovers another key, so 2.6 fails with exactly FAIL_ECDSA. Re-signing the
// right envelope is accepted, so the envelope is the only difference.
func TestCheatAttackVoteEnvelope(t *testing.T) {
	base, election, results := buildCheatInput(t)
	off, nproofs, _ := proofsSectionOffset(t, base.baseBin)
	rec := off + nproofs*proofRecordLen // voter 0: r ‖ s (LE) ‖ recid (u64)
	key := (*ecdsa.PrivateKey)(election.Voters[0].Signer)
	pid := election.ProcessID.MathBigInt()
	vid := results[0].VoteID
	coords := make([]*big.Int, davinci.BallotFields)
	for j := range coords {
		coords[j], _ = new(big.Int).SetString(results[0].PublicInputs[davinci.BallotPublicInputs-davinci.BallotFields+j], 10)
	}
	withSig := func(sig []byte) []byte {
		full := base.fullInput()
		lePut(full[rec:rec+32], new(big.Int).SetBytes(sig[:32]))
		lePut(full[rec+32:rec+64], new(big.Int).SetBytes(sig[32:64]))
		binary.LittleEndian.PutUint64(full[rec+64:rec+72], uint64(sig[64]))
		return full
	}
	sign := func(p *big.Int, id uint64, c []*big.Int) []byte {
		sig, err := davinci.SignVote(key, p, id, c)
		if err != nil {
			t.Fatalf("SignVote: %v", err)
		}
		return sig
	}

	runAccepted(t, withSig(sign(pid, vid, coords)), "same_envelope")
	assertCircuitFailsExactly(t, withSig(sign(new(big.Int).Add(pid, big.NewInt(1)), vid, coords)), failECDSA, "other_process_id")
	changed := append([]*big.Int(nil), coords...)
	changed[0] = new(big.Int).Add(changed[0], big.NewInt(1))
	assertCircuitFailsExactly(t, withSig(sign(pid, vid, changed)), failECDSA, "one_ciphertext_changed")
	var msg [32]byte
	binary.BigEndian.PutUint64(msg[24:], vid)
	old, err := crypto.Sign(crypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), msg[:]), key)
	if err != nil {
		t.Fatal(err)
	}
	assertCircuitFailsExactly(t, withSig(old), failECDSA, "vote_id_only_message")
}

// --- §6 3A: census proof shape ---------------------------------------------

// syntheticCensus re-roots a leaf under n random siblings and path bits.
func syntheticCensus(t *testing.T, leafHex string, n int) davinci.CensusProof {
	t.Helper()
	node, ok := new(big.Int).SetString(trimHex(leafHex), 16)
	if !ok {
		t.Fatalf("bad leaf %q", leafHex)
	}
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	var idx uint64
	sibs := make([]string, n)
	for i := 0; i < n; i++ {
		s, err := rand.Int(rand.Reader, two256)
		if err != nil {
			t.Fatal(err)
		}
		sibs[i] = bigIntToFr32(s)
		if s.Bit(0) == 1 { // reuse a sibling bit as the path bit
			idx |= 1 << uint(i)
			node = davinci.KeccakHasher(s, node)
		} else {
			node = davinci.KeccakHasher(node, s)
		}
	}
	return davinci.CensusProof{Root: bigIntToFr32(node), Leaf: leafHex, Index: idx, Siblings: sibs}
}

// frRegs lays a big-endian hex value out as the guest writes an FrRaw.
func frRegs(t *testing.T, beHex string) [8]uint32 {
	t.Helper()
	v, ok := new(big.Int).SetString(trimHex(beHex), 16)
	if !ok {
		t.Fatalf("bad hex %q", beHex)
	}
	var le [32]byte
	lePut(le[:], v)
	var r [8]uint32
	for i := range r {
		r[i] = binary.LittleEndian.Uint32(le[i*4:])
	}
	return r
}

// TestCheatAttackCensusDepth re-roots voter 0's real leaf under a synthetic
// path. Up to 61 siblings the guest proves membership under whatever root it
// is given and publishes it (the registry pins it, 13.6); 62 and above are
// refused (3A.4), and more than 64 siblings is a parse failure.
func TestCheatAttackCensusDepth(t *testing.T) {
	base, election, _ := buildCheatInputN(t, 1)
	proofs, err := election.BuildCensusProofs(election.Voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}
	if len(proofs[0].Siblings) != 0 || proofs[0].Root != proofs[0].Leaf {
		t.Fatalf("a one-member census must have root == leaf and no siblings")
	}
	for _, n := range []int{1, 2, 32, 61, 62, 63, 64, 65} {
		p := syntheticCensus(t, proofs[0].Leaf, n)
		census, err := davinci.EncodeCensusBlock([]davinci.CensusProof{p})
		if err != nil {
			t.Fatalf("EncodeCensusBlock: %v", err)
		}
		input := base.assembleWith(census)
		switch {
		case n <= 61:
			out := runAccepted(t, input, "depth")
			if got, want := censusRootRegs(out), frRegs(t, p.Root); got != want {
				t.Errorf("depth %d: census root registers %x, want %x", n, got, want)
			}
		case n <= 64:
			assertCircuitFailsExactly(t, input, failCensus, "depth_over_61")
		default:
			assertCircuitFails(t, input, failParse, "siblings_over_64")
		}
	}
}

// --- §6: eligibility block selection ----------------------------------------

// rebuildCensus recomputes the lean-IMT from e.censusLeaves.
func rebuildCensus(t *testing.T, e *Election) {
	t.Helper()
	imt, err := leanimt.New(davinci.KeccakHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		t.Fatalf("leanimt.New: %v", err)
	}
	for _, l := range e.censusLeaves {
		imt.Insert(l)
	}
	e.Census = imt
}

// cspBlockFor signs the CSP block for voters with key.
func cspBlockFor(t *testing.T, e *Election, key *ecdsa.PrivateKey, voters []*Voter) []byte {
	t.Helper()
	saved := e.CspKey
	e.CspKey = key
	defer func() { e.CspKey = saved }()
	csp, err := e.BuildCspData(voters)
	if err != nil {
		t.Fatalf("BuildCspData: %v", err)
	}
	b, err := davinci.EncodeCspBlock(csp)
	if err != nil {
		t.Fatalf("EncodeCspBlock: %v", err)
	}
	return b
}

// TestCheatAttackEligibilityBlocks feeds the eligibility block the config
// does not select, alone or next to the right one. censusOrigin (leaf 0x06)
// picks the block; the other one is ignored, never used in its place.
func TestCheatAttackEligibilityBlocks(t *testing.T) {
	t.Run("merkle", func(t *testing.T) {
		base, election, _ := buildCheatInput(t)
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		csp := cspBlockFor(t, election, key, election.Voters)
		assertCircuitFails(t, base.assembleWith(csp), failMissing, "merkle_csp_block_only")
		runAccepted(t, base.assembleWith(append(append([]byte(nil), base.censusBlock...), csp...)), "merkle_both_blocks")
	})
	t.Run("csp", func(t *testing.T) {
		election, err := NewCSPElection(2)
		if err != nil {
			t.Fatalf("NewCSPElection: %v", err)
		}
		base := buildCSPBatch(t, election, election.Voters)
		for _, v := range election.Voters {
			election.censusLeaves = append(election.censusLeaves, packAddressWeight(v.AddressBigInt, v.Weight))
		}
		rebuildCensus(t, election)
		proofs, err := election.BuildCensusProofs(election.Voters)
		if err != nil {
			t.Fatalf("BuildCensusProofs: %v", err)
		}
		census, err := davinci.EncodeCensusBlock(proofs)
		if err != nil {
			t.Fatalf("EncodeCensusBlock: %v", err)
		}
		assertCircuitFails(t, base.assembleWith(census), failMissing, "csp_census_block_only")
		out := runAccepted(t, base.assembleWith(append(census, base.censusBlock...)), "csp_both_blocks")
		addr := crypto.PubkeyToAddress(election.CspKey.PublicKey)
		if censusRootRegs(out) != addressRegs(addr[:]) {
			t.Errorf("census root is not the CSP address with both blocks present")
		}
	})
}

// --- 4.3.6: num_fields ------------------------------------------------------

// setBallotModeLowByte rewrites the BallotMode leaf's num_fields byte in the
// election's genesis tree, as a registry that skipped its 1..16 check would.
func setBallotModeLowByte(t *testing.T, e *Election, nf uint64) {
	t.Helper()
	leaf := new(big.Int).Rsh(e.configVals[1], 8)
	leaf.Lsh(leaf, 8).Or(leaf, new(big.Int).SetUint64(nf))
	bLen := arbo.HashFunctionSha256.Len()
	if err := e.ProcTree.Update(arbo.BigIntToBytes(keyLen, big.NewInt(0x02)), arbo.BigIntToBytes(bLen, leaf)); err != nil {
		t.Fatalf("update ballot mode leaf: %v", err)
	}
	e.configVals[1] = leaf
	root, err := e.ProcTree.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	e.OldRoot = "0x" + hex.EncodeToString(pad32(root))
}

// TestCheatAttackNumFieldsOutOfRange: a BallotMode leaf with num_fields 0,
// 17 or 255 must fail 4.3.6 (the guest falls back to 16 and flags it).
func TestCheatAttackNumFieldsOutOfRange(t *testing.T) {
	for _, nf := range []uint64{0, 17, 255} {
		election, err := NewElection(2)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		setBallotModeLowByte(t, election, nf)
		base, _, _ := buildCheatInputElection(t, election)
		assertCircuitFails(t, base.fullInput(), failReenc, "num_fields_out_of_range")
	}
}

// TestCheatAttackNumFieldsExtremes: honest batches with refreshes at the
// smallest and largest field counts are accepted (padding and IC₀' folds
// at their edges).
func TestCheatAttackNumFieldsExtremes(t *testing.T) {
	for _, nf := range []string{"1", "16"} {
		t.Run("nf_"+nf, func(t *testing.T) {
			t.Setenv("BALLOT_NUM_FIELDS", nf)
			base, election, _ := buildCheatInputTwoBatches(t)
			if fmt.Sprint(election.NumFields) != nf {
				t.Fatalf("election has %d fields, want %s", election.NumFields, nf)
			}
			runAccepted(t, base.fullInput(), "nf_"+nf)
		})
	}
}

// --- 4.1.4b / 4.2.12 / 4.2.P4 / 4.5.3: keys beyond limb 0 -------------------

// TestCheatAttackKeyHighLimbs sets limb 1 of a key. The leaf hash covers
// limb 0 only, while a 65-slot proof walks bit 64 (bit 0 of limb 1), so the
// processor refuses every key wider than 64 bits (CIRCUIT.md 4.2), and the
// chain-level rules name it too. old_key of an INSERT is a free witness, so it
// is covered as well as the keys the chains pin.
func TestCheatAttackKeyHighLimbs(t *testing.T) {
	t.Run("vote_id_old_key", func(t *testing.T) {
		base, _, _ := buildCheatInput(t)
		v := &base.stateData.VoteIDSmt[0]
		v.OldKey = withLimb1(t, v.OldKey)
		assertCircuitFailsExactly(t, base.reencodeState(t), failSMTVoteID, "vote_id_old_key_limb1")
	})
	t.Run("ballot_old_key", func(t *testing.T) {
		base, _, _ := buildCheatInput(t)
		b := &base.stateData.BallotSmt[0]
		b.OldKey = withLimb1(t, b.OldKey)
		assertCircuitFailsExactly(t, base.reencodeState(t), failSMTBallot, "ballot_old_key_limb1")
	})
	t.Run("results_key", func(t *testing.T) {
		base, _, _ := buildCheatInput(t)
		r := *base.stateData.ResultsSmt
		r.OldKey, r.NewKey = withLimb1(t, r.OldKey), withLimb1(t, r.NewKey)
		base.stateData.ResultsSmt = &r
		assertCircuitFailsExactly(t, base.reencodeState(t), failSMTResults, "results_key_limb1")
	})
	t.Run("process_key", func(t *testing.T) {
		base, _, _ := buildCheatInput(t)
		for i := range base.stateData.ProcessSmt {
			p := &base.stateData.ProcessSmt[i]
			honest := p.NewKey
			p.NewKey = withLimb1(t, p.NewKey)
			assertCircuitFailsExactly(t, base.reencodeState(t), failSMTProcess, "process_key_limb1")
			p.NewKey = honest
		}
	})
	t.Run("refresh_key", func(t *testing.T) {
		base, _, _ := buildCheatInputTwoBatches(t)
		r := &base.stateData.RefreshSmt[0]
		r.OldKey, r.NewKey = withLimb1(t, r.OldKey), withLimb1(t, r.NewKey)
		assertCircuitFailsExactly(t, base.reencodeState(t), failRefresh, "refresh_key_limb1")
	})
}

// --- 6.1 / 6.2: KZG block context -------------------------------------------

// TestCheatAttackKZGContext changes the KZG block's own copies of the
// process id and the root before. The evaluation points move with them, so
// only the cross-block binding can refuse a blob bound to another context.
func TestCheatAttackKZGContext(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	// KZGBLK: magic(8) process_id(32) root_hash_before(32) n(8) commitments.
	for name, off := range map[string]int{"process_id": 8, "root_hash_before": 40} {
		kzg := append([]byte(nil), base.kzgBlock...)
		kzg[off] ^= 0x01
		var full []byte
		full = append(full, base.baseBin...)
		full = append(full, base.stateBlock...)
		full = append(full, base.censusBlock...)
		full = append(full, base.reencBlock...)
		full = append(full, kzg...)
		assertCircuitFailsExactly(t, full, failBinding, "kzg_"+name)
	}
}

// --- §2: block layout ---------------------------------------------------------

// TestCheatAttackBlockLayout reorders and repeats blocks: the parser reads
// them in one fixed order, each at most once, and leaves the rest unread.
func TestCheatAttackBlockLayout(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	b := base
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for name, input := range map[string][]byte{
		"census_twice":        cat(b.baseBin, b.stateBlock, b.censusBlock, b.censusBlock, b.reencBlock, b.kzgBlock),
		"state_twice":         cat(b.baseBin, b.stateBlock, b.stateBlock, b.censusBlock, b.reencBlock, b.kzgBlock),
		"reenc_twice":         cat(b.baseBin, b.stateBlock, b.censusBlock, b.reencBlock, b.reencBlock, b.kzgBlock),
		"kzg_twice":           cat(b.baseBin, b.stateBlock, b.censusBlock, b.reencBlock, b.kzgBlock, b.kzgBlock),
		"reenc_before_census": cat(b.baseBin, b.stateBlock, b.reencBlock, b.censusBlock, b.kzgBlock),
		"census_before_state": cat(b.baseBin, b.censusBlock, b.stateBlock, b.reencBlock, b.kzgBlock),
		"kzg_before_reenc":    cat(b.baseBin, b.stateBlock, b.censusBlock, b.kzgBlock, b.reencBlock),
	} {
		assertCircuitFails(t, input, failParse, name)
	}
}

// --- 4.2 / 4.4: counts and the Results transition ----------------------------

// TestCheatAttackResultsTransitionDropped records the votes but leaves the
// tally leaf alone: no Results transition, NewStateRoot at the end of the
// ballot chain. Every chain still links, so only 4.4.8 (a batch with ballots
// must move the Results leaf) can refuse it.
func TestCheatAttackResultsTransitionDropped(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	sd := base.stateData
	sd.NewStateRoot = sd.ResultsSmt.OldRoot
	sd.ResultsSmt = nil
	assertCircuitFailsExactly(t, base.reencodeState(t), failResultAccum, "results_dropped")
}

// TestCheatAttackVoterCountLie declares fewer or more voters than the
// chains and proofs carry; one vote would go uncounted in the registry.
func TestCheatAttackVoterCountLie(t *testing.T) {
	for _, n := range []uint64{0, 1, 3} {
		base, _, _ := buildCheatInput(t)
		base.stateData.VotersCount = n
		assertCircuitFails(t, base.reencodeState(t), failSMTVoteID|failSMTBallot|failBinding, "voters_count_lie")
	}
}

// --- 3B / 4.1.6: CSP index and weight bounds ----------------------------------

// TestCheatAttackCSPIndexBoundary: the CSP-signed index maps to slot
// BallotMin + index, accepted up to BallotMax and refused above it or when
// the sum wraps, even with the ballot written at a valid slot.
func TestCheatAttackCSPIndexBoundary(t *testing.T) {
	build := func(t *testing.T, idx int, slot uint64) *cheatElectionInput {
		election, err := NewCSPElection(1)
		if err != nil {
			t.Fatalf("NewCSPElection: %v", err)
		}
		election.Voters[0].CensusIdx = idx
		if slot != 0 {
			election.SlotOverride = map[int]uint64{idx: slot}
		}
		return buildCSPBatch(t, election, election.Voters)
	}
	t.Run("at_ballot_max", func(t *testing.T) {
		base := build(t, 1<<63-17, 0)
		if k := leGet(mustHex(t, base.stateData.BallotSmt[0].NewKey)); k.Uint64() != davinci.BallotMax {
			t.Fatalf("slot %#x, want BallotMax", k)
		}
		runAccepted(t, base.fullInput(), "csp_index_at_ballot_max")
	})
	t.Run("above_ballot_max", func(t *testing.T) {
		assertCircuitFailsExactly(t, build(t, 1<<63-16, davinci.BallotMax).fullInput(), failBallotNS, "csp_index_above_max")
	})
	t.Run("wraps", func(t *testing.T) {
		assertCircuitFailsExactly(t, build(t, -1, davinci.BallotMax).fullInput(), failBallotNS, "csp_index_wraps")
	})
}

// mustHex decodes 0x-prefixed hex.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(trimHex(s))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestCheatAttackWeightBoundary: the widest weight a census leaf carries,
// 2^88 - 1, is accepted in both census modes (public input 6 is canonical).
func TestCheatAttackWeightBoundary(t *testing.T) {
	maxW := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 88), big.NewInt(1))
	t.Run("merkle", func(t *testing.T) {
		election, err := NewElection(2)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		v := election.Voters[0]
		v.Weight = maxW
		election.censusLeaves[0] = packAddressWeight(v.AddressBigInt, v.Weight)
		rebuildCensus(t, election)
		base, _, _ := buildCheatInputElection(t, election)
		runAccepted(t, base.fullInput(), "merkle_weight_2^88-1")
	})
	t.Run("csp", func(t *testing.T) {
		election, err := NewCSPElection(2)
		if err != nil {
			t.Fatalf("NewCSPElection: %v", err)
		}
		election.Voters[0].Weight = maxW
		runAccepted(t, buildCSPBatch(t, election, election.Voters).fullInput(), "csp_weight_2^88-1")
	})
}

// --- 4.5.8: occupied_before beyond 32 bits ------------------------------------

// TestCheatAttackOccupiedBeforeOverflow: with 16 refreshes the count rule
// holds for any occupied_before >= 16, and 2^32 + 16 truncates to the
// honest register value 16. Only the 32-bit overflow rule refuses it.
func TestCheatAttackOccupiedBeforeOverflow(t *testing.T) {
	election, err := NewElection(18)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	base, _, _ := buildCheatInputBatches(t, election, election.Voters[:16], election.Voters[16:18])
	if n := len(base.stateData.RefreshSmt); n != 16 || base.stateData.OccupiedBefore != 16 {
		t.Fatalf("expected 16 refreshes over 16 occupied slots, got %d over %d", n, base.stateData.OccupiedBefore)
	}
	out := runAccepted(t, base.fullInput(), "honest_16_refreshes")
	if out[davinci.OutputOccupiedBefore] != 16 {
		t.Fatalf("occupied_before register %d, want 16", out[davinci.OutputOccupiedBefore])
	}
	base.stateData.OccupiedBefore = 1<<32 + 16
	assertCircuitFailsExactly(t, base.reencodeState(t), failRefresh, "occupied_before_2^32+16")
}

// --- odds and ends: empty census, foreign CSP, swapped re-encryption ---------

// TestCheatAttackEmptyEligibility ships the census block with zero proofs
// and the CSP block with zero entries: a vote with no eligibility proof.
func TestCheatAttackEmptyEligibility(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	empty := binary.LittleEndian.AppendUint64([]byte("CENSUS!!"), 0)
	assertCircuitFails(t, base.assembleWith(empty), failMissing|failBinding, "empty_census")

	election, err := NewCSPElection(2)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	cspBase := buildCSPBatch(t, election, election.Voters)
	emptyCSP := binary.LittleEndian.AppendUint64([]byte("CSPBLK!!"), 0)
	assertCircuitFails(t, cspBase.assembleWith(emptyCSP), failBinding, "empty_csp")
}

// TestCheatAttackForeignCSP signs every entry of a CSP batch with the
// sequencer's own key. The guest cannot know the process's CSP: it accepts
// and publishes the signer's address as the census root, which the registry
// compares with the process census root (13.6).
func TestCheatAttackForeignCSP(t *testing.T) {
	election, err := NewCSPElection(2)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	base := buildCSPBatch(t, election, election.Voters)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	out := runAccepted(t, base.assembleWith(cspBlockFor(t, election, key, election.Voters)), "foreign_csp")
	forged := crypto.PubkeyToAddress(key.PublicKey)
	real := crypto.PubkeyToAddress(election.CspKey.PublicKey)
	if got := censusRootRegs(out); got != addressRegs(forged[:]) || got == addressRegs(real[:]) {
		t.Errorf("census root registers %x: want the foreign signer %x", got, forged)
	}
}

// TestCheatAttackSwappedReencEntries swaps voters 0 and 1 in the REENCBLK
// (originals and re-encryptions together). Each entry is a valid
// re-encryption of the other voter's ballot under the other position's
// scalars: the proofs see the wrong originals, the chain and the state
// binding break.
func TestCheatAttackSwappedReencEntries(t *testing.T) {
	base, _, _ := buildCheatInput(t)
	blk := append([]byte(nil), base.reencBlock...)
	const entry = 2 * 16 * 128
	e0 := append([]byte(nil), blk[112:112+entry]...)
	copy(blk[112:112+entry], blk[112+entry:112+2*entry])
	copy(blk[112+entry:112+2*entry], e0)
	base.reencBlock = blk
	assertCircuitFails(t, base.fullInput(), failPairing|failReenc|failBinding, "swapped_reenc_entries")
}

// --- 4.2: SMT leaves at depth 64 ---------------------------------------------

// buildBatchWithVoteIDs builds one batch for voters on election's current
// state, letting override rewrite the ballot results (vote ids) after the
// proofs are generated and before the state and DA blocks are built. The
// proofs keep their own vote ids, so an override fails the pairing and
// ECDSA, and every other check runs on the rewritten state.
func buildBatchWithVoteIDs(t *testing.T, election *Election, voters []*Voter, override func([]*BallotResult)) *cheatElectionInput {
	t.Helper()
	batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, 43)
	if err != nil {
		t.Fatalf("GenerateBallotBatch: %v", err)
	}
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "verification_key.json"), ballotproof.CircomVerificationKey, 0600); err != nil {
		t.Fatalf("write vk: %v", err)
	}
	for i, res := range batch.Results {
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", i+1)), res.ProofJSON, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", i+1)), res.SigJSON, 0600); err != nil {
			t.Fatal(err)
		}
	}
	outBin := filepath.Join(tmpDir, "input.bin")
	cmd := exec.Command(findGenInputBin(t), "--proofs-dir", tmpDir, "--output", outBin, "--nproofs", strconv.Itoa(len(voters)))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-input: %v\n%s", err, out)
	}
	baseBin, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatal(err)
	}
	if override != nil {
		override(batch.Results)
	}
	oldRoot := election.OldRoot
	reencData, reencBallots, err := election.BuildReencBlock(oldRoot, batch.Results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	stateData, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock: %v", err)
	}
	kzgReq, _, err := election.BuildKZGBlock(oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
	}
	stateBlock, err := davinci.EncodeStateBlock(stateData)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	reencBlock, err := davinci.EncodeReencBlock(reencData)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}
	kzgBlock, err := encodeKZGRequest(kzgReq)
	if err != nil {
		t.Fatalf("encodeKZGRequest: %v", err)
	}
	return &cheatElectionInput{
		baseBin:     baseBin,
		stateData:   stateData,
		stateBlock:  stateBlock,
		censusBlock: eligibilityBlock(t, election, voters),
		reencBlock:  reencBlock,
		kzgBlock:    kzgBlock,
		oldRoot:     oldRoot,
	}
}

// maskOf runs input and returns its fail mask (ok must be 0 or 1 with mask 0).
func maskOf(t *testing.T, input []byte) uint32 {
	t.Helper()
	out, err := runGuest(t, input)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	return out[davinci.OutputFailMask]
}

// TestCheatAttackVoteIDDepth64 inserts a vote id that agrees with an
// existing leaf key on its 63 low bits (bit 63 is the vote-id namespace
// bit), so both leaves land at depth 64. This test swaps the vote id in the
// state, so the pairing and ECDSA fail and the mask shows what the SMT
// chains did with it. Baseline: a vote id that collides with nothing; only
// the proof binding fails, and the next honest batch is accepted.
func TestCheatAttackVoteIDDepth64(t *testing.T) {
	t.Run("no_collision", func(t *testing.T) {
		e, mask := depth64Attack(t, depth64NS|0x5a5a5a5a5a5a5a5a)
		if mask != failPairing|failECDSA {
			t.Fatalf("baseline fail_mask=0x%08x, want pairing|ecdsa", mask)
		}
		runAccepted(t, depth64FollowUp(t, e), "follow_up_after_no_collision")
	})
}

// TestCheatAttackVoteIDDepth64ConfigKey: a vote id equal to a config key or
// the Results key in its 63 low bits pushes that leaf to depth 64. Proofs
// carry 65 sibling slots, so the attack batch's SMT chains accept the insert
// (and, for the Results key, the same batch's update of it), the next honest
// batch reads the displaced config leaf, and the results guest still proves
// keys 0x03 and 0x04 under the final root.
func TestCheatAttackVoteIDDepth64ConfigKey(t *testing.T) {
	for _, k := range append(append([]uint64(nil), configKeys...), keyResults) {
		t.Run(fmt.Sprintf("key_%#x", k), func(t *testing.T) {
			e, mask := depth64Attack(t, depth64NS|k)
			if mask != failPairing|failECDSA {
				t.Fatalf("fail_mask=0x%08x, want pairing|ecdsa: an SMT chain refused the leaf at depth 64", mask)
			}
			runAccepted(t, depth64FollowUp(t, e), "follow_up")
			depth64ResultsAccepted(t, e)
		})
	}
}

// depth64ResultsAccepted runs the results guest on e's current state: the
// key leaf 0x03 and the accumulator 0x04, each proven with 65 sibling slots,
// and the 16 plaintexts decrypted with the election key.
func depth64ResultsAccepted(t *testing.T, e *Election) {
	t.Helper()
	siblings := func(key uint64) []string {
		_, _, packed, exists, err := e.ProcTree.GenProof(arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(key)))
		if err != nil || !exists {
			t.Fatalf("GenProof(0x%02x): exists=%v err=%v", key, exists, err)
		}
		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packed)
		if err != nil {
			t.Fatalf("UnpackSiblings: %v", err)
		}
		out := make([]string, proofLevels)
		for i := range out {
			out[i] = hex.EncodeToString(make([]byte, 32))
		}
		for i, s := range sibs {
			out[i] = hex.EncodeToString(pad32(s))
		}
		return out
	}
	root, err := e.ProcTree.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}
	pkx, pky := teCoords(e.EncKey)
	req := resultsRequest{
		StateRoot:   hex.EncodeToString(pad32(root)),
		EncKeyX:     le32Hex(pkx),
		EncKeyY:     le32Hex(pky),
		KeySiblings: siblings(0x03),
		AccSiblings: siblings(keyResults),
	}
	point := func(x, y *big.Int) ecc.Point {
		rx, ry := format.FromTEtoRTE(x, y)
		return e.EncKey.New().SetPoint(rx, ry)
	}
	for f := 0; f < davinci.NumFields; f++ {
		c1 := point(e.Results[4*f], e.Results[4*f+1])
		c2 := point(e.Results[4*f+2], e.Results[4*f+3])
		_, m, err := elgamal.Decrypt(e.EncKey, e.EncPrivKey, c1, c2, 1<<20)
		if err != nil {
			t.Fatalf("decrypt field %d: %v", f, err)
		}
		req.Results = append(req.Results, m.Uint64())
		req.CpProofs = append(req.CpProofs, cpProofJSON(t, e.EncPrivKey, e.EncKey, c1, c2, m.Uint64()))
	}
	for _, c := range e.Results {
		req.Accumulator = append(req.Accumulator, le32Hex(c))
	}
	out := runResults(t, encodeResults(t, req))
	if out[rRegOk] != 1 || out[rRegMask] != 0 {
		t.Fatalf("results guest: ok=%d fail_mask=0x%02x", out[rRegOk], out[rRegMask])
	}
}

// depth64NS is the vote-id namespace bit, path bit 63.
const depth64NS = uint64(1) << 63

// depth64Attack applies a one-voter batch whose vote id is vid on a fresh
// two-voter election and returns the election and the batch's fail mask.
func depth64Attack(t *testing.T, vid uint64) (*Election, uint32) {
	t.Helper()
	election, err := NewElection(2)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	base := buildBatchWithVoteIDs(t, election, election.Voters[:1], func(r []*BallotResult) { r[0].VoteID = vid })
	return election, maskOf(t, base.fullInput())
}

// depth64FollowUp is the next honest batch (voter 1) on e.
func depth64FollowUp(t *testing.T, e *Election) []byte {
	t.Helper()
	base, _, _ := buildCheatInputBatchesHook(t, e, nil, e.Voters[1:2], nil)
	return base.fullInput()
}
