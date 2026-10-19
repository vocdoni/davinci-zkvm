package davinci

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
)

func TestBigIntToHex32BEPanics(t *testing.T) {
	for _, v := range []*big.Int{big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("bigIntToHex32BE(%v): want panic", v)
				}
			}()
			bigIntToHex32BE(v)
		}()
	}
}

func TestABIValuesNil(t *testing.T) {
	vals := (&PublicOutputs{}).ABIValues()
	for i, v := range vals {
		if v == nil || v.Sign() != 0 {
			t.Errorf("vals[%d] = %v, want 0", i, v)
		}
	}
}

func TestJobPath(t *testing.T) {
	if got := jobPath("abc", "/snark"); got != "/jobs/abc/snark" {
		t.Errorf("jobPath = %q", got)
	}
	if got := jobPath("../evil", ""); got != "/jobs/..%2Fevil" {
		t.Errorf("jobPath does not escape: %q", got)
	}
}

func TestErrBodyTruncate(t *testing.T) {
	if got := errBody([]byte("short")); got != "short" {
		t.Errorf("errBody = %q", got)
	}
	got := errBody(make([]byte, maxErrBody+100))
	if len(got) != maxErrBody+len("...(truncated)") {
		t.Errorf("errBody length = %d", len(got))
	}
}

func vkJSON(alpha, delta string, nIC int) []byte {
	ic := strings.TrimSuffix(strings.Repeat(`["1","2","1"],`, nIC), ",")
	return []byte(`{"vk_alpha_1":["` + alpha + `","2","1"],` +
		`"vk_beta_2":[["1","2"],["3","4"],["1","0"]],` +
		`"vk_gamma_2":[["1","2"],["3","4"],["1","0"]],` +
		`"vk_delta_2":[["` + delta + `","2"],["3","4"],["1","0"]],` +
		`"IC":[` + ic + `]}`)
}

func vkJSONWithAlpha(x string) []byte { return vkJSON(x, "5", BallotPublicInputs+1) }

func TestBallotVKLeafRefusesBadShape(t *testing.T) {
	if _, err := BallotVKLeaf(vkJSON("1", "1", BallotPublicInputs+1)); err == nil {
		t.Error("delta == gamma: want error")
	}
	if _, err := BallotVKLeaf(vkJSON("1", "01", BallotPublicInputs+1)); err == nil {
		t.Error("delta == gamma written differently: want error")
	}
	for _, n := range []int{4, BallotPublicInputs, BallotPublicInputs + 2} {
		if _, err := BallotVKLeaf(vkJSON("1", "5", n)); err == nil {
			t.Errorf("%d IC points: want error", n)
		}
	}
}

func TestBallotVKLeaf(t *testing.T) {
	h1, err := BallotVKLeaf(vkJSONWithAlpha("1"))
	if err != nil {
		t.Fatalf("BallotVKLeaf: %v", err)
	}
	h2, err := BallotVKLeaf(vkJSONWithAlpha("1"))
	if err != nil {
		t.Fatalf("BallotVKLeaf: %v", err)
	}
	if h1.Sign() == 0 || h1.Cmp(h2) != 0 {
		t.Errorf("leaf not deterministic or zero: %v vs %v", h1, h2)
	}
	if h3, _ := BallotVKLeaf(vkJSONWithAlpha("5")); h3.Cmp(h1) == 0 {
		t.Error("different VK must produce a different leaf")
	}
}

func TestBallotVKLeafBadCoordinate(t *testing.T) {
	over := new(big.Int).Lsh(big.NewInt(1), 256).String()
	for _, bad := range []string{over, "-5", "xyz"} {
		if _, err := BallotVKLeaf(vkJSONWithAlpha(bad)); err == nil {
			t.Errorf("coordinate %q: want error, got nil", bad)
		}
	}
}

func TestProveRequestBuilderMaxBatchSize(t *testing.T) {
	b := NewProveRequestBuilder().SetVerificationKeyJSON([]byte(`{}`))
	for i := 0; i <= MaxBatchSize; i++ {
		b.AddProofJSON([]byte(`{}`)).
			AddEcdsaSignature(&EcdsaSignature{})
	}
	if _, err := b.Build(); err == nil || !strings.Contains(err.Error(), "MaxBatchSize") {
		t.Errorf("want MaxBatchSize error, got %v", err)
	}
}

// An identity VK point hashes as zeros, like rust-sdk put_g1, input-gen
// g1_to_raw and the TS SDK write it.
func TestBallotVKLeafIdentityPointIsZeros(t *testing.T) {
	n := BallotPublicInputs + 1
	raw := vkJSON("1", "5", n)
	i := strings.LastIndex(string(raw), `["1","2","1"]`)
	raw = []byte(string(raw)[:i] + `["1","2","0"]` + string(raw)[i+len(`["1","2","1"]`):])

	le := func(v uint64) []byte { b := make([]byte, 32); binary.LittleEndian.PutUint64(b, v); return b }
	var w []byte
	for _, v := range []uint64{1, 2} { // alpha
		w = append(w, le(v)...)
	}
	for _, g2 := range [][]uint64{{1, 2, 3, 4}, {1, 2, 3, 4}, {5, 2, 3, 4}} { // beta, gamma, delta
		for _, v := range g2 {
			w = append(w, le(v)...)
		}
	}
	w = binary.LittleEndian.AppendUint64(w, uint64(n))
	for range n - 1 {
		w = append(w, le(1)...)
		w = append(w, le(2)...)
	}
	w = append(w, make([]byte, 64)...)
	sum := sha256.Sum256(w)

	got, err := BallotVKLeaf(raw)
	if err != nil {
		t.Fatalf("BallotVKLeaf: %v", err)
	}
	if want := new(big.Int).SetBytes(sum[:]); got.Cmp(want) != 0 {
		t.Errorf("leaf = %x, want %x (identity point as 64 zero bytes)", got, want)
	}
}
