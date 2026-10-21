// census_corpus_test.go runs an external corpus of census cases through the
// vote-batch guest on ziskemu and checks each verdict against the guest
// rules (CIRCUIT.md 3A, 3B.2c). It is a tool for differential runs, gated by
// CENSUS_CORPUS (a JSON file) and never run by default:
//
//	{"proofCases": [{"id", "root", "leaf", "pathBits" (decimal), "siblings": [..]}],
//	 "leaves":     [{"id", "address" (40 hex digits), "weight" (decimal)}]}
//
// Census values are "0x" + 64 hex digits. Each proof case replaces the census
// block of an honest one-voter batch; each leaf case is signed by the CSP of
// an honest one-voter CSP batch as (address, weight, index 0). The guest's
// verdict is read from the fail mask: a census case is refused when
// FAIL_CENSUS, FAIL_PARSE or FAIL_MISSING_BLOCK is set, a CSP case when
// FAIL_CENSUS or FAIL_CSP is. Proof A is zeroed so the pairing is skipped
// (FAIL_CURVE); the other bits the swapped data trips are ignored.
// CENSUS_CORPUS_OUT writes {"proofCases": {id: verdict}, "leaves": {id: verdict}},
// CENSUS_CORPUS_JOBS (default 4) sets the parallel emulator runs and
// CENSUS_CORPUS_SAMPLE keeps every n-th case.
package integration

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

type corpusProof struct {
	ID       string   `json:"id"`
	Root     string   `json:"root"`
	Leaf     string   `json:"leaf"`
	PathBits string   `json:"pathBits"`
	Siblings []string `json:"siblings"`
}

type corpusLeaf struct {
	ID      int    `json:"id"`
	Address string `json:"address"`
	Weight  string `json:"weight"`
}

// censusNode parses "0x" + 64 hex digits.
func censusNode(t *testing.T, s string) *big.Int {
	t.Helper()
	h, ok := strings.CutPrefix(s, "0x")
	if !ok || len(h) != 64 {
		t.Fatalf("corpus value %q is not 0x + 64 hex digits", s)
	}
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		t.Fatalf("corpus value %q is not hex", s)
	}
	return v
}

// rawCensusBlock encodes one proof as the guest reads it, with no SDK checks.
func rawCensusBlock(root, leaf *big.Int, index uint64, sibs []*big.Int) []byte {
	b := binary.LittleEndian.AppendUint64([]byte("CENSUS!!"), 1)
	put := func(v *big.Int) {
		var le [32]byte
		lePut(le[:], v)
		b = append(b, le[:]...)
	}
	put(root)
	put(leaf)
	b = binary.LittleEndian.AppendUint64(b, index)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(sibs)))
	for _, s := range sibs {
		put(s)
	}
	return b
}

// censusRuleVerdict is the guest's Merkle rule set: at most 64 siblings on
// the wire, at most 61 in the walk, no path bit above the count, leaf below
// 2^248, and the Keccak walk reaching the root.
func censusRuleVerdict(root, leaf *big.Int, index uint64, sibs []*big.Int) bool {
	n := len(sibs)
	if n > 61 || index>>uint(n) != 0 || leaf.BitLen() > 248 {
		return false
	}
	node := leaf
	for i, s := range sibs {
		if index>>uint(i)&1 == 1 {
			node = davinci.KeccakHasher(s, node)
		} else {
			node = davinci.KeccakHasher(node, s)
		}
	}
	return node.Cmp(root) == 0
}

// zeroProofA zeroes proof 0's A so the guest skips the pairing.
func zeroProofA(t *testing.T, base *cheatElectionInput) {
	t.Helper()
	off := proofOff(t, base, 0)
	base.baseBin = append([]byte(nil), base.baseBin...)
	for i := off; i < off+64; i++ {
		base.baseBin[i] = 0
	}
}

func TestCensusCorpusOnGuest(t *testing.T) {
	path := os.Getenv("CENSUS_CORPUS")
	if path == "" {
		t.Skip("set CENSUS_CORPUS to a census corpus JSON file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		ProofCases []corpusProof `json:"proofCases"`
		Leaves     []corpusLeaf  `json:"leaves"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("corpus: %v", err)
	}
	jobs, sample := 4, 1
	if v, err := strconv.Atoi(os.Getenv("CENSUS_CORPUS_JOBS")); err == nil && v > 0 {
		jobs = v
	}
	if v, err := strconv.Atoi(os.Getenv("CENSUS_CORPUS_SAMPLE")); err == nil && v > 0 {
		sample = v
	}

	merkle, _, _ := buildCheatInputN(t, 1)
	zeroProofA(t, merkle)
	cspElection, err := NewCSPElection(1)
	if err != nil {
		t.Fatalf("NewCSPElection: %v", err)
	}
	csp := buildCSPBatch(t, cspElection, cspElection.Voters)
	zeroProofA(t, csp)

	type job struct {
		kind, id string
		input    []byte
		want     bool
		refuse   uint32
	}
	var work []job
	out := map[string]map[string]string{"proofCases": {}, "leaves": {}}
	var mu sync.Mutex
	unencodable := 0
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	for i, p := range corpus.ProofCases {
		if i%sample != 0 {
			continue
		}
		bits, ok := new(big.Int).SetString(p.PathBits, 10)
		if !ok || bits.Sign() < 0 {
			t.Fatalf("%s: bad pathBits %q", p.ID, p.PathBits)
		}
		if bits.Cmp(two64) >= 0 {
			// The wire field is a u64: the service cannot even encode it.
			out["proofCases"][p.ID] = "unencodable"
			unencodable++
			continue
		}
		root, leaf := censusNode(t, p.Root), censusNode(t, p.Leaf)
		sibs := make([]*big.Int, len(p.Siblings))
		for j, s := range p.Siblings {
			sibs[j] = censusNode(t, s)
		}
		idx := bits.Uint64()
		work = append(work, job{
			kind: "proofCases", id: p.ID,
			input:  merkle.assembleWith(rawCensusBlock(root, leaf, idx, sibs)),
			want:   censusRuleVerdict(root, leaf, idx, sibs),
			refuse: failCensus | failParse | failMissing,
		})
	}
	pidBE := pad32(new(big.Int).SetBytes(cspElection.ProcessID[:]).Bytes())
	for i, l := range corpus.Leaves {
		if i%sample != 0 {
			continue
		}
		addr, err := hex.DecodeString(l.Address)
		if err != nil || len(addr) != 20 {
			t.Fatalf("leaf %d: bad address %q", l.ID, l.Address)
		}
		w, ok := new(big.Int).SetString(l.Weight, 10)
		if !ok || w.Sign() < 0 || w.BitLen() > 256 {
			t.Fatalf("leaf %d: bad weight %q", l.ID, l.Weight)
		}
		var payload [92]byte
		copy(payload[:32], pidBE)
		copy(payload[32:52], addr)
		w.FillBytes(payload[52:84])
		digest := crypto.Keccak256(append([]byte("\x19Ethereum Signed Message:\n92"), payload[:]...))
		sig, err := crypto.Sign(digest, cspElection.CspKey)
		if err != nil {
			t.Fatal(err)
		}
		block, err := davinci.EncodeCspBlock(&davinci.CspData{Proofs: []davinci.CspProof{{
			R: "0x" + hex.EncodeToString(sig[:32]), S: "0x" + hex.EncodeToString(sig[32:64]), Recid: sig[64],
			VoterAddress: "0x" + l.Address, Weight: fmt.Sprintf("0x%064x", w), Index: 0,
		}}})
		if err != nil {
			t.Fatalf("leaf %d: EncodeCspBlock: %v", l.ID, err)
		}
		work = append(work, job{
			kind: "leaves", id: strconv.Itoa(l.ID),
			input:  csp.assembleWith(block),
			want:   w.BitLen() <= 88,
			refuse: failCensus | failCSP,
		})
	}

	ch := make(chan job)
	var wg sync.WaitGroup
	mismatches := 0
	for range jobs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				regs, err := runZiskEmu(j.input)
				verdict := "abort"
				if err == nil {
					verdict = strconv.FormatBool(regs[davinci.OutputFailMask]&j.refuse == 0)
				}
				mu.Lock()
				out[j.kind][j.id] = verdict
				if verdict != strconv.FormatBool(j.want) {
					mismatches++
					t.Errorf("%s %s: guest %s, guest rules %v", j.kind, j.id, verdict, j.want)
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range work {
		ch <- j
	}
	close(ch)
	wg.Wait()
	t.Logf("%d census and CSP cases on the guest (sample 1/%d), %d unencodable path-bit values, %d verdicts differ from the guest rules",
		len(work), sample, unencodable, mismatches)
	if o := os.Getenv("CENSUS_CORPUS_OUT"); o != "" {
		b, _ := json.MarshalIndent(out, "", " ")
		if err := os.WriteFile(o, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
