package elgamal

import (
	"fmt"
	"math/big"
	"testing"

	bjj_gnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/curves"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec/params"
)

// Frozen vector shared with the guest (circuit-primitives babyjubjub tests):
// seed = 1, oldRoot = 2.
func TestReencChainVector(t *testing.T) {
	want := []string{
		"0a63922a58b3fe4dbec15e6db1be5438713862d2fa6fa543af70812000d38d7d",
		"1d7152578cfe912cf8cc3185201ade4d7d81f22d91173f16fb8e88da028240ed",
		"2848f34e5de5c01ed168f2be00d066ba64d30e1229318b7ed98ab934f78a2137",
	}
	c := NewReencChain(big.NewInt(1), big.NewInt(2))
	for i, w := range want {
		if got := fmt.Sprintf("%064x", c.Next()); got != w {
			t.Fatalf("r%d = %s, want %s", i, got, w)
		}
	}
}

// Two ballots share one chain: active fields get original + EncryptedZero(pk,
// r_t) in ballot order, padded fields are copied untouched, and the chain the
// caller holds has advanced by exactly numFields per ballot.
func TestReencryptChained(t *testing.T) {
	c := curves.New(bjj_gnark.CurveType)
	pk := c.New()
	pk.ScalarBaseMult(big.NewInt(123456789))
	const nf = 3
	ballots := make([]*Ballot, 2)
	for b := range ballots {
		var msgs [params.FieldsPerBallot]*big.Int
		for i := range msgs {
			msgs[i] = big.NewInt(int64(10*b + i))
		}
		var err error
		ballots[b], err = NewBallot(c).Encrypt(msgs, pk, big.NewInt(int64(77+b)))
		if err != nil {
			t.Fatal(err)
		}
	}

	chain := NewReencChain(big.NewInt(7), big.NewInt(9))
	ref := NewReencChain(big.NewInt(7), big.NewInt(9))
	for b, orig := range ballots {
		got, err := orig.ReencryptChained(pk, chain, nf)
		if err != nil {
			t.Fatal(err)
		}
		for i := range got.Ciphertexts {
			if i < nf {
				c1, c2 := EncryptedZero(pk, ref.Next())
				want := NewCiphertext(c).Add(orig.Ciphertexts[i], &Ciphertext{C1: c1, C2: c2})
				if !got.Ciphertexts[i].C1.Equal(want.C1) || !got.Ciphertexts[i].C2.Equal(want.C2) {
					t.Fatalf("ballot %d field %d: chained re-encryption mismatch", b, i)
				}
				continue
			}
			if !got.Ciphertexts[i].C1.Equal(orig.Ciphertexts[i].C1) || !got.Ciphertexts[i].C2.Equal(orig.Ciphertexts[i].C2) {
				t.Fatalf("ballot %d padded field %d changed", b, i)
			}
		}
		if chain.next.Cmp(ref.next) != 0 {
			t.Fatalf("ballot %d: caller chain out of step with %d scalars per ballot", b, nf)
		}
	}
}
