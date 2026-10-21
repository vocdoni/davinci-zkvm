package davinci

import (
	"math/big"
	"testing"
)

// BUG: toRequest silently drops the census proofs of voters without a CSP attestation, and voters without re-encryption data, when the batch mixes them; the guest then refuses the whole batch.
func TestProveBatchRefusesMixedVoters(t *testing.T) {
	voter := func(csp, reenc bool) VoterBallot {
		v := VoterBallot{
			Proof:     &Groth16Proof{A: [3]string{"1", "2", "1"}, B: [3][2]string{{"1", "2"}, {"3", "4"}, {"1", "0"}}, C: [3]string{"5", "6", "1"}},
			Signature: &EcdsaSignature{R: big.NewInt(1), S: big.NewInt(2), PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4), Address: big.NewInt(5)},
			Census:    CensusProofFromBigInts(big.NewInt(100), big.NewInt(200), 0, []*big.Int{big.NewInt(300)}),
		}
		if csp {
			v.Csp = &CspProof{R: "0x01", S: "0x02", VoterAddress: "0x" + "00", Weight: "0x01"}
		}
		if reenc {
			v.Reencryption = &VoterReencryption{}
		}
		return v
	}
	batch := func(voters ...VoterBallot) *ProveBatch {
		return &ProveBatch{
			VerificationKeyJSON: []byte(`{}`),
			Voters:              voters,
			EncryptionKey:       &BjjPoint{X: "0x01", Y: "0x02"},
			ReencryptionSeed:    big.NewInt(7),
		}
	}
	for name, b := range map[string]*ProveBatch{
		"csp then merkle":    batch(voter(true, true), voter(false, true)),
		"merkle then csp":    batch(voter(false, true), voter(true, true)),
		"reenc then none":    batch(voter(false, true), voter(false, false)),
		"none then reenc":    batch(voter(false, false), voter(false, true)),
		"csp, partial reenc": batch(voter(true, false), voter(true, true)),
	} {
		if _, err := b.toRequest(); err == nil {
			t.Errorf("%s: want error, got a request the guest refuses", name)
		}
	}
	// Uniform batches still build.
	for name, b := range map[string]*ProveBatch{
		"merkle": batch(voter(false, true), voter(false, true)),
		"csp":    batch(voter(true, true), voter(true, true)),
	} {
		if _, err := b.toRequest(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
