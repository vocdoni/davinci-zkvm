package davinci

import (
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

func vkJSONWithAlpha(x string) []byte {
	return []byte(`{"vk_alpha_1":["` + x + `","2","1"],` +
		`"vk_beta_2":[["1","2"],["3","4"],["1","0"]],` +
		`"vk_gamma_2":[["1","2"],["3","4"],["1","0"]],` +
		`"vk_delta_2":[["1","2"],["3","4"],["1","0"]],` +
		`"IC":[["1","2","1"],["3","4","1"]]}`)
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
		b.AddProofJSON([]byte(`{}`), NewPublicInput(big.NewInt(1))).
			AddEcdsaSignature(&EcdsaSignature{})
	}
	if _, err := b.Build(); err == nil || !strings.Contains(err.Error(), "MaxBatchSize") {
		t.Errorf("want MaxBatchSize error, got %v", err)
	}
}
