// results_cheat_test.go runs the circuit-results guest on ziskemu (no GPU, no
// service): one valid single-key tally, then one tampered input per rule of
// circuit-results/RESULTS.md, each of which must end with ok=0 and the named
// fail_mask bit.
//
// Prerequisites:
//   - ziskemu in PATH
//   - gen-results-input (cargo build --release -p davinci-zkvm-input-gen),
//     found via GEN_RESULTS_INPUT_BIN, target/release or PATH
//   - RESULTS_ELF_PATH or the default circuit-results/elf/results.elf
package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/hash/poseidon"
)

// circuit-results fail_mask bits and registers (RESULTS.md §3, §4).
const (
	rFailParse       = uint32(1 << 0)
	rFailKey         = uint32(1 << 1)
	rFailInclKey     = uint32(1 << 2)
	rFailInclResults = uint32(1 << 3)
	rFailCP          = uint32(1 << 4)
	rFailRange       = uint32(1 << 5)

	rRegOk      = 0
	rRegMask    = 1
	rRegRoot    = 2
	rRegResults = 10
	rRegCPIndex = 42
	rNumRegs    = 43

	// Byte offsets in the guest frame.
	rOffNKey = 104
	rOffNAcc = 4208
)

// bjjSubOrder is the BabyJubJub prime subgroup order l.
var bjjSubOrder, _ = new(big.Int).SetString(
	"2736030358979909402780800718157159386076813972158567259200215660948447373041", 10)

// resultsRequest mirrors input-gen ResultsJson / the POST /results body.
type resultsRequest struct {
	StateRoot   string            `json:"state_root"`
	EncKeyX     string            `json:"enc_key_x"`
	EncKeyY     string            `json:"enc_key_y"`
	KeySiblings []string          `json:"key_siblings"`
	Accumulator []string          `json:"accumulator"`
	AccSiblings []string          `json:"acc_siblings"`
	Results     []uint64          `json:"results"`
	CpProofs    []davinci.CpProof `json:"cp_proofs"`
}

// resultsElection is one election reduced to what the results guest reads:
// the key, the net accumulator, the final tree and the tally.
type resultsElection struct {
	pub   ecc.Point
	priv  *big.Int
	acc   [davinci.NumFields][2]ecc.Point // (C1, C2), gnark RTE form
	tally [davinci.NumFields]uint64
	root  []byte
	req   resultsRequest
}

func le32Hex(v *big.Int) string { return hex.EncodeToString(arbo.BigIntToBytes(32, v)) }

func leHexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return arbo.BytesToBigInt(b)
}

// teCoords returns the TE coordinates of a gnark (RTE) point.
func teCoords(p ecc.Point) (*big.Int, *big.Int) {
	x, y := p.Point()
	return format.FromRTEtoTE(x, y)
}

// cpProofJSON builds the CP proof for ciphertext (c1, c2) and plaintext m.
func cpProofJSON(t *testing.T, priv *big.Int, pub, c1, c2 ecc.Point, m uint64) davinci.CpProof {
	t.Helper()
	msg := new(big.Int).SetUint64(m)
	proof, err := elgamal.BuildDecryptionProof(priv, pub, c1, c2, new(big.Int).Set(msg))
	if err != nil {
		t.Fatalf("BuildDecryptionProof: %v", err)
	}
	a1x, a1y := teCoords(proof.A1)
	a2x, a2y := teCoords(proof.A2)
	return davinci.CpProof{
		A1X: le32Hex(a1x), A1Y: le32Hex(a1y),
		A2X: le32Hex(a2x), A2Y: le32Hex(a2y),
		Z: le32Hex(proof.Z),
	}
}

// newResultsElection encrypts nVoters ballots with nf active fields under a
// key derived from seed, sums them, builds the 64-level arbo state tree with
// the genesis config leaves, the accumulator and a few ballot leaves sharing
// low path bits with 0x03 and 0x04, and assembles a valid results request.
func newResultsElection(t *testing.T, seed string, nVoters, nf int) *resultsElection {
	t.Helper()
	pub, priv := elgamalKeyFromSeed(seed)
	e := &resultsElection{pub: pub, priv: priv}
	for i := range e.acc {
		for j := 0; j < 2; j++ {
			e.acc[i][j] = pub.New()
			e.acc[i][j].SetZero()
		}
	}
	for v := 0; v < nVoters; v++ {
		for i := 0; i < nf; i++ {
			m := uint64((i*3 + v) % 5)
			if i == 2 && v == 0 {
				m += 1 << 32 // exercise the hi register of a tally
			}
			c1, c2, _, err := elgamal.Encrypt(pub, new(big.Int).SetUint64(m))
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			e.acc[i][0].Add(e.acc[i][0], c1)
			e.acc[i][1].Add(e.acc[i][1], c2)
			e.tally[i] += m
		}
	}

	coords := make([]*big.Int, 0, davinci.BallotFields)
	for i := range e.acc {
		c1x, c1y := teCoords(e.acc[i][0])
		c2x, c2y := teCoords(e.acc[i][1])
		coords = append(coords, c1x, c1y, c2x, c2y)
	}
	root, siblings := buildResultsTree(t, nf,
		encKeyLeafValue(pub.(*bjjgnark.BJJ)), accLeafValue(coords))
	e.root = root

	pkx, pky := teCoords(pub)
	e.req = resultsRequest{
		StateRoot:   hex.EncodeToString(e.root),
		EncKeyX:     le32Hex(pkx),
		EncKeyY:     le32Hex(pky),
		KeySiblings: siblings(0x03),
		AccSiblings: siblings(keyResults),
		Results:     e.tally[:],
	}
	for _, c := range coords {
		e.req.Accumulator = append(e.req.Accumulator, le32Hex(c))
	}
	for i := range e.acc {
		e.req.CpProofs = append(e.req.CpProofs,
			cpProofJSON(t, priv, pub, e.acc[i][0], e.acc[i][1], e.tally[i]))
	}
	return e
}

// accLeafValue is the 0x04 leaf value: sha256 over the 64 coordinates, BE32.
func accLeafValue(coords []*big.Int) *big.Int {
	h := sha256.New()
	buf := make([]byte, 32)
	for _, c := range coords {
		c.FillBytes(buf)
		h.Write(buf)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// buildResultsTree builds the 64-level arbo state tree with the genesis config
// leaves, the given 0x03 and 0x04 values and a few ballot leaves sharing low
// path bits with 0x03 and 0x04. It returns the root and a sibling getter.
func buildResultsTree(t *testing.T, nf int, keyLeaf, accLeaf *big.Int) ([]byte, func(uint64) []string) {
	t.Helper()
	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		t.Fatalf("arbo.NewTree: %v", err)
	}
	filler := func(k uint64) *big.Int {
		d := sha256.Sum256([]byte{byte(k), 0xAA})
		return new(big.Int).SetBytes(d[:])
	}
	leaves := []struct {
		key uint64
		val *big.Int
	}{
		{0x00, big.NewInt(0xDA71C1)},
		{0x02, big.NewInt(int64(nf))},
		{0x03, keyLeaf},
		{keyResults, accLeaf},
		{0x06, big.NewInt(1)},
		{0x07, filler(0x07)},
		{0x13, filler(0x13)}, // shares 4 low bits with 0x03
		{0x14, filler(0x14)}, // shares 4 low bits with 0x04
		{0x44, filler(0x44)}, // shares 6 low bits with 0x04
		{0x23, filler(0x23)},
	}
	for _, l := range leaves {
		if err := tree.Add(arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(l.key)),
			arbo.BigIntToBytes(32, l.val)); err != nil {
			t.Fatalf("tree.Add(0x%02x): %v", l.key, err)
		}
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatalf("root: %v", err)
	}

	siblings := func(key uint64) []string {
		_, _, packed, exists, err := tree.GenProof(arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(key)))
		if err != nil || !exists {
			t.Fatalf("GenProof(0x%02x): exists=%v err=%v", key, exists, err)
		}
		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packed)
		if err != nil {
			t.Fatalf("UnpackSiblings: %v", err)
		}
		out := make([]string, 0, procLevels)
		for _, s := range sibs {
			out = append(out, hex.EncodeToString(pad32(s)))
		}
		for len(out) < procLevels {
			out = append(out, hex.EncodeToString(make([]byte, 32)))
		}
		return out
	}
	return pad32(root), siblings
}

// clone deep-copies the request so subtests can tamper independently.
func (r resultsRequest) clone() resultsRequest {
	c := r
	c.KeySiblings = append([]string(nil), r.KeySiblings...)
	c.Accumulator = append([]string(nil), r.Accumulator...)
	c.AccSiblings = append([]string(nil), r.AccSiblings...)
	c.Results = append([]uint64(nil), r.Results...)
	c.CpProofs = append([]davinci.CpProof(nil), r.CpProofs...)
	return c
}

func findGenResultsInputBin(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GEN_RESULTS_INPUT_BIN"); p != "" {
		return p
	}
	// Prefer the workspace build over a possibly stale copy on PATH.
	if _, err := os.Stat("../../../target/release/gen-results-input"); err == nil {
		return "../../../target/release/gen-results-input"
	}
	if p, err := exec.LookPath("gen-results-input"); err == nil {
		return p
	}
	t.Skip("gen-results-input not found — build with 'cargo build --release -p davinci-zkvm-input-gen'")
	return ""
}

func resultsELF() string {
	if p := os.Getenv("RESULTS_ELF_PATH"); p != "" {
		return p
	}
	return "../../../circuit-results/elf/results.elf"
}

// encodeResults runs gen-results-input on req and returns the guest frame.
func encodeResults(t *testing.T, req resultsRequest) []byte {
	t.Helper()
	bin := findGenResultsInputBin(t)
	dir := t.TempDir()
	reqPath := filepath.Join(dir, "request.json")
	outPath := filepath.Join(dir, "input.bin")
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := os.WriteFile(reqPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "--request", reqPath, "--output", outPath).CombinedOutput(); err != nil {
		t.Fatalf("gen-results-input: %v\n%s", err, out)
	}
	frame, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func runResults(t *testing.T, frame []byte) []uint32 {
	t.Helper()
	out, err := runZiskEmuELF(resultsELF(), frame)
	if err != nil {
		t.Fatalf("ziskemu: %v", err)
	}
	if len(out) < rNumRegs {
		t.Fatalf("expected %d registers, got %d", rNumRegs, len(out))
	}
	return out
}

// expectReject asserts ok=0 and exactly the fail_mask want.
func expectReject(t *testing.T, out []uint32, want uint32) {
	t.Helper()
	if out[rRegOk] != 0 {
		t.Fatalf("ok=%d, want 0 (fail_mask=0x%02x)", out[rRegOk], out[rRegMask])
	}
	if out[rRegMask] != want {
		t.Fatalf("fail_mask=0x%02x, want 0x%02x", out[rRegMask], want)
	}
	for i := rRegRoot; i < rRegCPIndex; i++ {
		if out[i] != 0 {
			t.Fatalf("register %d = %#x on a rejected input, want 0", i, out[i])
		}
	}
	t.Logf("rejected: fail_mask=0x%02x cp_index=%#x", out[rRegMask], out[rRegCPIndex])
}

func expectCPIndex(t *testing.T, out []uint32, want uint32) {
	t.Helper()
	if out[rRegCPIndex] != want {
		t.Fatalf("cp_fail_index=%#x, want %#x", out[rRegCPIndex], want)
	}
}

// expectAccept asserts ok=1 and the published root and tallies.
func expectAccept(t *testing.T, out []uint32, e *resultsElection) {
	t.Helper()
	if out[rRegOk] != 1 || out[rRegMask] != 0 {
		t.Fatalf("ok=%d fail_mask=0x%02x cp_index=%#x, want ok=1", out[rRegOk], out[rRegMask], out[rRegCPIndex])
	}
	for j := 0; j < 8; j++ {
		if w := binary.LittleEndian.Uint32(e.root[j*4:]); out[rRegRoot+j] != w {
			t.Fatalf("state_root reg %d = %#x, want %#x", j, out[rRegRoot+j], w)
		}
	}
	for i, m := range e.tally {
		lo, hi := out[rRegResults+2*i], out[rRegResults+2*i+1]
		if got := uint64(lo) | uint64(hi)<<32; got != m {
			t.Fatalf("results[%d] = %d, want %d", i, got, m)
		}
	}
	expectCPIndex(t, out, 0xFFFFFFFF)
}

func addHex(t *testing.T, s string, d *big.Int) string {
	t.Helper()
	return le32Hex(new(big.Int).Add(leHexInt(t, s), d))
}

func TestResultsCheat(t *testing.T) {
	const nf = 6
	e := newResultsElection(t, "results-cheat-a", 5, nf)
	p := bn254ScalarField
	valid := encodeResults(t, e.req)

	t.Run("Valid", func(t *testing.T) {
		out := runResults(t, valid)
		expectAccept(t, out, e)
		if e.tally[2] < 1<<32 {
			t.Fatalf("test election should carry a tally above 2^32")
		}
		// RESULTS_CHEAT_DUMP=<dir>: keep the request and its emulator publics
		// for a GPU /results run to compare against.
		if dir := os.Getenv("RESULTS_CHEAT_DUMP"); dir != "" {
			raw, _ := json.MarshalIndent(e.req, "", " ")
			pubs := make([]byte, 4*rNumRegs)
			for i := 0; i < rNumRegs; i++ {
				binary.LittleEndian.PutUint32(pubs[i*4:], out[i])
			}
			if err := os.WriteFile(filepath.Join(dir, "results_request.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "results_publics_emu.bin"), pubs, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	})

	t.Run("WrongStateRoot", func(t *testing.T) {
		r := e.req.clone()
		root := append([]byte(nil), e.root...)
		root[0] ^= 1
		r.StateRoot = hex.EncodeToString(root)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclKey|rFailInclResults)
	})

	// Empty election: the identity accumulator decrypts to zero under any key,
	// so another key's proofs verify and only the 0x03 inclusion stops it.
	t.Run("OtherKeyValidCP", func(t *testing.T) {
		empty := newResultsElection(t, "results-cheat-empty", 0, nf)
		expectAccept(t, runResults(t, encodeResults(t, empty.req)), empty)
		other := newResultsElection(t, "results-cheat-other", 0, nf)
		r := empty.req.clone()
		r.EncKeyX, r.EncKeyY = other.req.EncKeyX, other.req.EncKeyY
		r.CpProofs = append([]davinci.CpProof(nil), other.req.CpProofs...)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclKey)
	})

	// Another election's key, accumulator and valid proofs under the honest root.
	t.Run("SwappedElection", func(t *testing.T) {
		other := newResultsElection(t, "results-cheat-b", 5, nf)
		r := e.req.clone()
		r.EncKeyX, r.EncKeyY = other.req.EncKeyX, other.req.EncKeyY
		r.Accumulator = append([]string(nil), other.req.Accumulator...)
		r.Results = append([]uint64(nil), other.req.Results...)
		r.CpProofs = append([]davinci.CpProof(nil), other.req.CpProofs...)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclKey|rFailInclResults)
	})

	// c1y of field 1 + 1: off the curve and a different leaf hash.
	t.Run("AccumulatorCoordChanged", func(t *testing.T) {
		r := e.req.clone()
		r.Accumulator[5] = le32Hex(new(big.Int).Mod(new(big.Int).Add(leHexInt(t, r.Accumulator[5]), big.NewInt(1)), p))
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailInclResults|rFailCP)
		expectCPIndex(t, out, 1)
	})

	t.Run("WrongPlaintextField3", func(t *testing.T) {
		r := e.req.clone()
		r.Results[3]++
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailCP)
		expectCPIndex(t, out, 3)
	})

	// A consistent proof for a wrong plaintext cannot exist either.
	t.Run("WrongPlaintextWithProof", func(t *testing.T) {
		r := e.req.clone()
		r.Results[3]++
		r.CpProofs[3] = cpProofJSON(t, e.priv, e.pub, e.acc[3][0], e.acc[3][1], r.Results[3])
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailCP)
		expectCPIndex(t, out, 3)
	})

	t.Run("ForgedZ", func(t *testing.T) {
		r := e.req.clone()
		z := new(big.Int).Add(leHexInt(t, r.CpProofs[1].Z), big.NewInt(1))
		r.CpProofs[1].Z = le32Hex(z.Mod(z, bjjSubOrder))
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailCP)
		expectCPIndex(t, out, 1)
	})

	// Padded identity field: only m = 0 is provable.
	t.Run("PaddedFieldNonZero", func(t *testing.T) {
		r := e.req.clone()
		r.Results[15] = 1
		r.CpProofs[15] = cpProofJSON(t, e.priv, e.pub, e.acc[15][0], e.acc[15][1], 1)
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailCP)
		expectCPIndex(t, out, 15)
	})

	// pk + (0, -1): on the curve, outside the prime subgroup.
	t.Run("KeyNotInSubgroup", func(t *testing.T) {
		r := e.req.clone()
		x, y := leHexInt(t, r.EncKeyX), leHexInt(t, r.EncKeyY)
		r.EncKeyX = le32Hex(new(big.Int).Sub(p, x))
		r.EncKeyY = le32Hex(new(big.Int).Sub(p, y))
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailKey|rFailInclKey|rFailCP)
		expectCPIndex(t, out, 0)
	})

	t.Run("KeyIdentity", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyX, r.EncKeyY = le32Hex(big.NewInt(0)), le32Hex(big.NewInt(1))
		expectReject(t, runResults(t, encodeResults(t, r)), rFailKey|rFailInclKey|rFailCP)
	})

	t.Run("KeyOffCurve", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyY = addHex(t, r.EncKeyY, big.NewInt(1))
		expectReject(t, runResults(t, encodeResults(t, r)), rFailKey|rFailInclKey|rFailCP)
	})

	t.Run("NonCanonicalKeyX", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyX = addHex(t, r.EncKeyX, p)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange|rFailInclKey)
	})

	t.Run("NonCanonicalAccumulatorX", func(t *testing.T) {
		r := e.req.clone()
		r.Accumulator[0] = addHex(t, r.Accumulator[0], p)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange|rFailInclResults)
	})

	// Same point, second encoding: only the range check notices.
	t.Run("NonCanonicalCPA1X", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].A1X = addHex(t, r.CpProofs[0].A1X, p)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange)
	})

	// z + l is the same scalar on the subgroup: only the range check notices.
	t.Run("NonCanonicalZ", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].Z = addHex(t, r.CpProofs[0].Z, bjjSubOrder)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange)
	})

	t.Run("TruncatedFrame", func(t *testing.T) {
		expectReject(t, runResults(t, valid[:len(valid)-1]), rFailParse)
		expectCPIndex(t, runResults(t, valid[:len(valid)-1]), 0xFFFFFFFF)
	})

	t.Run("TrailingByte", func(t *testing.T) {
		expectReject(t, runResults(t, append(append([]byte(nil), valid...), 0)), rFailParse)
	})

	t.Run("EmptyFrame", func(t *testing.T) {
		expectReject(t, runResults(t, []byte{}), rFailParse)
	})

	t.Run("BadMagic", func(t *testing.T) {
		f := append([]byte(nil), valid...)
		f[0] ^= 1
		expectReject(t, runResults(t, f), rFailParse)
	})

	t.Run("BadSiblingCount", func(t *testing.T) {
		f := append([]byte(nil), valid...)
		binary.LittleEndian.PutUint64(f[rOffNKey:], procLevels-1)
		expectReject(t, runResults(t, f), rFailParse)
	})

	// Adversarial pass: one case per attack tried against the guest.
	resultsAttackParse(t, valid)
	resultsAttackRange(t, e, nf)
	resultsAttackKey(t, e, nf)
	resultsAttackInclusion(t, e, nf)
	resultsAttackCP(t, e, nf)
}

// resultsAttackParse: counts and frame shapes the parser must refuse, and
// hostile bodies that must end in a fail_mask, not a guest panic.
func resultsAttackParse(t *testing.T, valid []byte) {
	for _, c := range []struct {
		name string
		off  int
		n    uint64
	}{
		{"AccSiblingCount63", rOffNAcc, procLevels - 1},
		{"KeySiblingCount0", rOffNKey, 0},
		{"AccSiblingCount0", rOffNAcc, 0},
		{"KeySiblingCountMax", rOffNKey, ^uint64(0)},
		{"KeySiblingCount65", rOffNKey, procLevels + 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint64(f[c.off:], c.n)
			expectReject(t, runResults(t, f), rFailParse)
		})
	}

	// 65 declared and 65 present: the frame is one sibling too long.
	t.Run("KeySiblings65Consistent", func(t *testing.T) {
		f := append([]byte(nil), valid[:rOffNAcc]...)
		binary.LittleEndian.PutUint64(f[rOffNKey:], procLevels+1)
		f = append(f, make([]byte, 32)...)
		f = append(f, valid[rOffNAcc:]...)
		expectReject(t, runResults(t, f), rFailParse)
	})

	// 8 extra bytes, 8-aligned, so the emulator pad cannot hide them.
	t.Run("TrailingWord", func(t *testing.T) {
		expectReject(t, runResults(t, append(append([]byte(nil), valid...), make([]byte, 8)...)), rFailParse)
	})

	body := func(fill byte) []byte {
		f := make([]byte, len(valid))
		copy(f, valid[:8])
		for i := 8; i < len(f); i++ {
			f[i] = fill
		}
		binary.LittleEndian.PutUint64(f[rOffNKey:], procLevels)
		binary.LittleEndian.PutUint64(f[rOffNAcc:], procLevels)
		return f
	}
	// pk = (0, 0) is off the curve, zero siblings put each leaf at the root.
	t.Run("ZeroBody", func(t *testing.T) {
		out := runResults(t, body(0))
		expectReject(t, out, rFailKey|rFailInclKey|rFailInclResults|rFailCP)
		expectCPIndex(t, out, 0)
	})
	// Every word 2^256-1: every check fails, none panics.
	t.Run("AllOnesBody", func(t *testing.T) {
		out := runResults(t, body(0xFF))
		expectReject(t, out, rFailRange|rFailKey|rFailInclKey|rFailInclResults|rFailCP)
		expectCPIndex(t, out, 0)
	})
}

// resultsAttackRange: second encodings (x + p, y + p, z + l) and out-of-range
// words at every coordinate class. The CP challenge reduces its inputs, so a
// second encoding of a proof point verifies and only RANGE stops it.
func resultsAttackRange(t *testing.T, e *resultsElection, nf int) {
	p := bn254ScalarField
	max256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	maxHex := le32Hex(max256)

	t.Run("NonCanonicalKeyY", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyY = addHex(t, r.EncKeyY, p)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange|rFailInclKey)
	})
	for _, idx := range []int{1, 2, 3} { // C1y, C2x, C2y of field 0
		t.Run(fmt.Sprintf("NonCanonicalAccumulator%d", idx), func(t *testing.T) {
			r := e.req.clone()
			r.Accumulator[idx] = addHex(t, r.Accumulator[idx], p)
			expectReject(t, runResults(t, encodeResults(t, r)), rFailRange|rFailInclResults)
		})
	}
	// Padded field 15: C1x = 0 written as p. Same identity point, new leaf.
	t.Run("PaddedCoordEqualsP", func(t *testing.T) {
		r := e.req.clone()
		r.Accumulator[60] = le32Hex(p)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange|rFailInclResults)
	})
	for _, f := range []string{"A1Y", "A2X", "A2Y"} {
		t.Run("NonCanonicalCP"+f, func(t *testing.T) {
			r := e.req.clone()
			cp := &r.CpProofs[4]
			switch f {
			case "A1Y":
				cp.A1Y = addHex(t, cp.A1Y, p)
			case "A2X":
				cp.A2X = addHex(t, cp.A2X, p)
			case "A2Y":
				cp.A2Y = addHex(t, cp.A2Y, p)
			}
			expectReject(t, runResults(t, encodeResults(t, r)), rFailRange)
		})
	}
	t.Run("ZEqualsL", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].Z = le32Hex(bjjSubOrder)
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailRange|rFailCP)
		expectCPIndex(t, out, 0)
	})
	t.Run("ZAllOnes", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[2].Z = maxHex
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailRange|rFailCP)
		expectCPIndex(t, out, 2)
	})
	// (p, 1) reduces to the identity key.
	t.Run("KeyPOne", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyX, r.EncKeyY = le32Hex(p), le32Hex(big.NewInt(1))
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailRange|rFailKey|rFailInclKey|rFailCP)
		expectCPIndex(t, out, 0)
	})
	// The key really committed as (x + p, y), with honest proofs: the leaf and
	// the curve work both pass, RANGE alone refuses it (fail closed).
	t.Run("NonCanonicalKeyCommitted", func(t *testing.T) {
		pk := tePtFromHex(t, e.req.EncKeyX, e.req.EncKeyY)
		pk.x = new(big.Int).Add(pk.x, p)
		coords := make([]*big.Int, len(e.req.Accumulator))
		for i, c := range e.req.Accumulator {
			coords[i] = leHexInt(t, c)
		}
		r, _ := rawResultsRequest(t, nf, pk, coords, e.req.Results, e.req.CpProofs)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailRange)
	})
	t.Run("KeyAllOnes", func(t *testing.T) {
		r := e.req.clone()
		r.EncKeyX, r.EncKeyY = maxHex, maxHex
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailRange|rFailKey|rFailInclKey|rFailCP)
		expectCPIndex(t, out, 0)
	})
}

// resultsAttackKey: bad keys given in the frame, then bad keys that are
// really committed at 0x03 with proofs ground to verify under them, so only
// FAIL_KEY stands between them and ok=1.
func resultsAttackKey(t *testing.T, e *resultsElection, nf int) {
	pk := tePtFromHex(t, e.req.EncKeyX, e.req.EncKeyY)
	t2, t4, t8 := teOrder2(), teOrder4(t), teOrder8(t)

	for _, c := range []struct {
		name string
		key  tePt
		want uint32
	}{
		{"KeyOrder2", t2, rFailKey | rFailInclKey | rFailCP},
		{"KeyOrder4", t4, rFailKey | rFailInclKey | rFailCP},
		{"KeyOrder8", t8, rFailKey | rFailInclKey | rFailCP},
		{"KeyPlusOrder8", ptAdd(pk, t8), rFailKey | rFailInclKey | rFailCP},
		// In the subgroup and on the curve: only the leaf and the proofs differ.
		{"KeyNegated", teNeg(pk), rFailInclKey | rFailCP},
		{"KeySwappedXY", tePt{pk.y, pk.x}, rFailKey | rFailInclKey | rFailCP},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.req.clone()
			r.EncKeyX, r.EncKeyY = c.key.hex()
			out := runResults(t, encodeResults(t, r))
			expectReject(t, out, c.want)
			expectCPIndex(t, out, 0)
		})
	}
	// The gnark in-memory (RTE) coordinates of the right key.
	t.Run("KeyRTEForm", func(t *testing.T) {
		r := e.req.clone()
		x, y := e.pub.Point()
		r.EncKeyX, r.EncKeyY = le32Hex(x), le32Hex(y)
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailKey|rFailInclKey|rFailCP)
		expectCPIndex(t, out, 0)
	})

	zeros := make([]uint64, davinci.NumFields)
	committed := func(t *testing.T, key tePt, proof davinci.CpProof) {
		t.Helper()
		if !teOnCurve(key) {
			t.Fatal("committed key off the curve")
		}
		proofs := make([]davinci.CpProof, davinci.NumFields)
		for i := range proofs {
			proofs[i] = proof
		}
		r, _ := rawResultsRequest(t, nf, key, identityAccumulator(), zeros, proofs)
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailKey)
		expectCPIndex(t, out, 0xFFFFFFFF)
	}
	t.Run("KeyIdentityCommitted", func(t *testing.T) {
		committed(t, teIdentity(), cpTorsionKey(t, big.NewInt(0), teIdentity(), teIdentity(), 1))
	})
	t.Run("KeyOrder2Committed", func(t *testing.T) {
		committed(t, t2, cpTorsionKey(t, big.NewInt(0), t2, t2, 2))
	})
	t.Run("KeyOrder8Committed", func(t *testing.T) {
		committed(t, t8, cpTorsionKey(t, big.NewInt(0), t8, t8, 8))
	})
	t.Run("KeyPlusOrder2Committed", func(t *testing.T) {
		key := ptAdd(pk, t2)
		committed(t, key, cpTorsionKey(t, e.priv, key, t2, 2))
	})
	// Control: the same construction under the honest key is accepted, so the
	// cases above fail on the key check alone.
	t.Run("KeyHonestCommittedControl", func(t *testing.T) {
		proof := cpTorsionKey(t, e.priv, pk, teIdentity(), 1)
		proofs := make([]davinci.CpProof, davinci.NumFields)
		for i := range proofs {
			proofs[i] = proof
		}
		r, root := rawResultsRequest(t, nf, pk, identityAccumulator(), zeros, proofs)
		out := runResults(t, encodeResults(t, r))
		expectAccept(t, out, &resultsElection{root: root})
	})
}

// resultsAttackInclusion: sibling lists moved between keys, cut, extended or
// zeroed, and roots that are a single leaf of one of the two keys.
func resultsAttackInclusion(t *testing.T, e *resultsElection, nf int) {
	nz := hex.EncodeToString(bytes.Repeat([]byte{0x5A}, 32))
	zero := hex.EncodeToString(make([]byte, 32))
	kd, ad := sibDepth(t, e.req.KeySiblings), sibDepth(t, e.req.AccSiblings)
	if kd < 2 || ad < 2 {
		t.Fatalf("test tree too shallow: key depth %d, acc depth %d", kd, ad)
	}

	for _, c := range []struct {
		name string
		mod  func(r *resultsRequest)
		want uint32
	}{
		{"KeySiblingsOf0x04", func(r *resultsRequest) { r.KeySiblings = append([]string(nil), e.req.AccSiblings...) }, rFailInclKey},
		{"AccSiblingsOf0x03", func(r *resultsRequest) { r.AccSiblings = append([]string(nil), e.req.KeySiblings...) }, rFailInclResults},
		{"SwappedSiblingLists", func(r *resultsRequest) { r.KeySiblings, r.AccSiblings = r.AccSiblings, r.KeySiblings }, rFailInclKey | rFailInclResults},
		{"KeySiblingsAllZero", func(r *resultsRequest) {
			for i := range r.KeySiblings {
				r.KeySiblings[i] = zero
			}
		}, rFailInclKey},
		// Claim the leaf one level deeper than it is.
		{"KeyExtraTrailingSibling", func(r *resultsRequest) { r.KeySiblings[kd] = nz }, rFailInclKey},
		{"AccExtraTrailingSibling", func(r *resultsRequest) { r.AccSiblings[ad] = nz }, rFailInclResults},
		// A non-zero sibling at the last level makes the leaf level undefined.
		{"KeyLeafLevelSiblingSet", func(r *resultsRequest) { r.KeySiblings[procLevels-1] = nz }, rFailInclKey},
		{"AccLeafLevelSiblingSet", func(r *resultsRequest) { r.AccSiblings[procLevels-1] = nz }, rFailInclResults},
		// Claim the leaf one level higher than it is.
		{"KeyDeepestSiblingDropped", func(r *resultsRequest) { r.KeySiblings[kd-1] = zero }, rFailInclKey},
		{"AccDeepestSiblingDropped", func(r *resultsRequest) { r.AccSiblings[ad-1] = zero }, rFailInclResults},
		{"KeyRootSiblingFlipped", func(r *resultsRequest) {
			r.KeySiblings[0] = flipHex(t, r.KeySiblings[0])
		}, rFailInclKey},
		{"AccSiblingsShifted", func(r *resultsRequest) {
			r.AccSiblings = append([]string{zero}, r.AccSiblings[:procLevels-1]...)
		}, rFailInclResults},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.req.clone()
			c.mod(&r)
			expectReject(t, runResults(t, encodeResults(t, r)), c.want)
		})
	}

	// A root that is just the 0x03 leaf proves the key and nothing else.
	allZero := make([]string, procLevels)
	for i := range allZero {
		allZero[i] = zero
	}
	pk := tePtFromHex(t, e.req.EncKeyX, e.req.EncKeyY)
	coords := make([]*big.Int, len(e.req.Accumulator))
	for i, c := range e.req.Accumulator {
		coords[i] = leHexInt(t, c)
	}
	t.Run("RootIsKeyLeaf", func(t *testing.T) {
		r := e.req.clone()
		r.StateRoot = hex.EncodeToString(arboLeafHash(0x03, teKeyLeaf(pk)))
		r.KeySiblings = append([]string(nil), allZero...)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclResults)
	})
	t.Run("RootIsAccLeaf", func(t *testing.T) {
		r := e.req.clone()
		r.StateRoot = hex.EncodeToString(arboLeafHash(keyResults, accLeafValue(coords)))
		r.AccSiblings = append([]string(nil), allZero...)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclKey)
	})

	// Same key, another tree: its accumulator, tallies and valid proofs under
	// this root.
	t.Run("SameKeyOtherAccumulator", func(t *testing.T) {
		other := newResultsElection(t, "results-cheat-a", 3, nf)
		if other.req.EncKeyX != e.req.EncKeyX {
			t.Fatal("expected the same key")
		}
		r := e.req.clone()
		r.Accumulator = append([]string(nil), other.req.Accumulator...)
		r.Results = append([]uint64(nil), other.req.Results...)
		r.CpProofs = append([]davinci.CpProof(nil), other.req.CpProofs...)
		expectReject(t, runResults(t, encodeResults(t, r)), rFailInclResults)
	})

	// Boundary, accepted by design: a tree the host made up, with the real key
	// and an accumulator encrypting a chosen tally, proves that tally under its
	// own root. Only the contract's root check rejects it; the guest must
	// publish exactly that root.
	t.Run("ForgedTreePublishesItsRoot", func(t *testing.T) {
		forged := [davinci.NumFields]uint64{1000, 0, 7}
		coords := identityAccumulator()
		proofs := make([]davinci.CpProof, davinci.NumFields)
		for i := range proofs {
			c1, c2 := e.pub.New(), e.pub.New()
			c1.SetZero()
			c2.SetZero()
			if forged[i] != 0 {
				var err error
				c1, c2, _, err = elgamal.Encrypt(e.pub, new(big.Int).SetUint64(forged[i]))
				if err != nil {
					t.Fatal(err)
				}
				coords[4*i], coords[4*i+1] = teCoords(c1)
				coords[4*i+2], coords[4*i+3] = teCoords(c2)
			}
			proofs[i] = cpProofJSON(t, e.priv, e.pub, c1, c2, forged[i])
		}
		r, root := rawResultsRequest(t, nf, pk, coords, forged[:], proofs)
		if hex.EncodeToString(root) == e.req.StateRoot {
			t.Fatal("forged root equals the honest root")
		}
		expectAccept(t, runResults(t, encodeResults(t, r)), &resultsElection{root: root, tally: forged})
	})
}

// resultsAttackCP: proofs moved between fields, built for another key or
// ciphertext, with torsion or negated commitments, with the challenge hashed
// the wrong way, and plaintexts that wrap.
func resultsAttackCP(t *testing.T, e *resultsElection, nf int) {
	pk := tePtFromHex(t, e.req.EncKeyX, e.req.EncKeyY)
	c1 := func(i int) tePt { return tePtFromHex(t, e.req.Accumulator[4*i], e.req.Accumulator[4*i+1]) }
	c2 := func(i int) tePt { return tePtFromHex(t, e.req.Accumulator[4*i+2], e.req.Accumulator[4*i+3]) }
	spec := func(i int) cpSpec {
		return cpSpec{s: e.priv, w: big.NewInt(int64(1000 + i)), pk: pk, c1: c1(i), c2: c2(i), m: e.tally[i]}
	}
	rejectAt := func(t *testing.T, r resultsRequest, idx uint32) {
		t.Helper()
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailCP)
		expectCPIndex(t, out, idx)
	}

	// Control: hand-built proofs verify, so the variants below fail on their
	// one change.
	t.Run("HandmadeProofsControl", func(t *testing.T) {
		r := e.req.clone()
		for i := range r.CpProofs {
			r.CpProofs[i] = cpHandmade(t, spec(i))
		}
		expectAccept(t, runResults(t, encodeResults(t, r)), e)
	})

	t.Run("ProofsUnderOtherKey", func(t *testing.T) {
		opub, opriv := elgamalKeyFromSeed("results-cheat-other")
		r := e.req.clone()
		for i := range r.CpProofs {
			r.CpProofs[i] = cpProofJSON(t, opriv, opub, e.acc[i][0], e.acc[i][1], e.tally[i])
		}
		rejectAt(t, r, 0)
	})
	t.Run("ProofForOtherC1", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0] = cpProofJSON(t, e.priv, e.pub, e.acc[1][0], e.acc[0][1], e.tally[0])
		rejectAt(t, r, 0)
	})
	t.Run("SwappedProofs", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0], r.CpProofs[1] = r.CpProofs[1], r.CpProofs[0]
		rejectAt(t, r, 0)
	})
	t.Run("SwappedTalliesWithProofs", func(t *testing.T) {
		r := e.req.clone()
		r.Results[0], r.Results[1] = r.Results[1], r.Results[0]
		r.CpProofs[0], r.CpProofs[1] = r.CpProofs[1], r.CpProofs[0]
		rejectAt(t, r, 0)
	})
	t.Run("AllProofsOfField0", func(t *testing.T) {
		r := e.req.clone()
		for i := range r.CpProofs {
			r.CpProofs[i] = r.CpProofs[0]
		}
		rejectAt(t, r, 1)
	})
	t.Run("SwappedA1A2", func(t *testing.T) {
		r := e.req.clone()
		cp := &r.CpProofs[0]
		cp.A1X, cp.A1Y, cp.A2X, cp.A2Y = cp.A2X, cp.A2Y, cp.A1X, cp.A1Y
		rejectAt(t, r, 0)
	})
	t.Run("A1Negated", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].A1X = le32Hex(new(big.Int).Sub(bn254ScalarField, leHexInt(t, r.CpProofs[0].A1X)))
		rejectAt(t, r, 0)
	})
	// (0, 0): the all-zero word pair, off the curve.
	t.Run("A1AllZero", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].A1X, r.CpProofs[0].A1Y = le32Hex(big.NewInt(0)), le32Hex(big.NewInt(0))
		rejectAt(t, r, 0)
	})
	t.Run("A1OffCurve", func(t *testing.T) {
		r := e.req.clone()
		r.CpProofs[0].A1Y = le32Hex(fmod(new(big.Int).Add(leHexInt(t, r.CpProofs[0].A1Y), big.NewInt(1))))
		rejectAt(t, r, 0)
	})
	t.Run("ProofPointsRTE", func(t *testing.T) {
		r := e.req.clone()
		cp := &r.CpProofs[0]
		ax, _ := format.FromTEtoRTE(leHexInt(t, cp.A1X), leHexInt(t, cp.A1Y))
		bx, _ := format.FromTEtoRTE(leHexInt(t, cp.A2X), leHexInt(t, cp.A2Y))
		cp.A1X, cp.A2X = le32Hex(ax), le32Hex(bx)
		rejectAt(t, r, 0)
	})

	// Torsion in a commitment, with z consistent with the resulting challenge.
	t2, t8 := teOrder2(), teOrder8(t)
	for _, c := range []struct {
		name   string
		a1, a2 *tePt
	}{
		{"A1PlusOrder2", &t2, nil},
		{"A1PlusOrder8", &t8, nil},
		{"A2PlusOrder2", nil, &t2},
		{"A2PlusOrder8", nil, &t8},
	} {
		t.Run(c.name, func(t *testing.T) {
			sp := spec(0)
			sp.a1Extra, sp.a2Extra = c.a1, c.a2
			r := e.req.clone()
			r.CpProofs[0] = cpHandmade(t, sp)
			rejectAt(t, r, 0)
		})
	}

	// Fiat-Shamir variants: a consistent proof whose challenge is not the guest's.
	for _, c := range []struct {
		name string
		chal func(t *testing.T, pk, c1, d, a1, a2 tePt) *big.Int
	}{
		{"ChallengeOverTE", func(_ *testing.T, pk, c1, d, a1, a2 tePt) *big.Int {
			in := []*big.Int{}
			for _, p := range []tePt{pk, pk, c1, d, a1, a2} {
				in = append(in, p.x, p.y)
			}
			v, _ := poseidon.MultiPoseidon(in...)
			return v
		}},
		// C2 instead of D: the plaintext drops out of the transcript.
		{"ChallengeOmitsPlaintext", func(t *testing.T, pk, c1, _, a1, a2 tePt) *big.Int {
			return cpChallenge(t, pk, c1, c2(0), a1, a2)
		}},
		{"ChallengeOverB8", func(_ *testing.T, pk, c1, d, a1, a2 tePt) *big.Int {
			in := []*big.Int{}
			for _, p := range []tePt{teB8, pk, c1, d, a1, a2} {
				rx, ry := format.FromTEtoRTE(p.x, p.y)
				in = append(in, rx, ry)
			}
			v, _ := poseidon.MultiPoseidon(in...)
			return v
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if e.tally[0] == 0 {
				t.Fatal("field 0 needs a non-zero tally")
			}
			sp := spec(0)
			sp.chal = c.chal
			r := e.req.clone()
			r.CpProofs[0] = cpHandmade(t, sp)
			rejectAt(t, r, 0)
		})
	}

	// Zero nonce (A1 = A2 = O) is a valid proof shape; it still binds m.
	t.Run("ZeroNonceWrongPlaintext", func(t *testing.T) {
		sp := spec(1)
		sp.w = big.NewInt(0)
		sp.m++
		r := e.req.clone()
		r.Results[1] = sp.m
		r.CpProofs[1] = cpHandmade(t, sp)
		rejectAt(t, r, 1)
	})

	// Plaintexts near 2^64: a u64 is below l, so none aliases the tally.
	for _, c := range []struct {
		name string
		idx  int
		m    func(uint64) uint64
	}{
		{"PlaintextWrapsBelowZero", 0, func(v uint64) uint64 { return v - (v + 1) }},
		{"PlaintextHighBit", 2, func(v uint64) uint64 { return v ^ 1<<63 }},
		{"PaddedPlaintextMax", 15, func(uint64) uint64 { return ^uint64(0) }},
		{"PlaintextPlus2To32", 2, func(v uint64) uint64 { return v + 1<<32 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.req.clone()
			r.Results[c.idx] = c.m(r.Results[c.idx])
			r.CpProofs[c.idx] = cpProofJSON(t, e.priv, e.pub, e.acc[c.idx][0], e.acc[c.idx][1], r.Results[c.idx])
			rejectAt(t, r, uint32(c.idx))
		})
	}

	// Accumulator shape changes: both inclusion and proofs break.
	t.Run("SwappedCiphertextHalves", func(t *testing.T) {
		r := e.req.clone()
		a := r.Accumulator
		a[0], a[1], a[2], a[3] = a[2], a[3], a[0], a[1]
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailInclResults|rFailCP)
		expectCPIndex(t, out, 0)
	})
	t.Run("AccumulatorRTE", func(t *testing.T) {
		r := e.req.clone()
		for i := 0; i < nf; i++ {
			c1x, _ := e.acc[i][0].Point()
			c2x, _ := e.acc[i][1].Point()
			r.Accumulator[4*i], r.Accumulator[4*i+2] = le32Hex(c1x), le32Hex(c2x)
		}
		out := runResults(t, encodeResults(t, r))
		expectReject(t, out, rFailInclResults|rFailCP)
		expectCPIndex(t, out, 0)
	})
}

// flipHex flips the low bit of the first byte of a 32-byte hex string.
func flipHex(t *testing.T, s string) string {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[0] ^= 1
	return hex.EncodeToString(b)
}
