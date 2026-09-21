package elgamal

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/curves"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec/params"
)

// reencDomainTag is the 16-byte domain separator for the batch
// re-encryption scalar chain: r_0 = H(tag || be32(seed) || be32(oldRoot)).
var reencDomainTag = []byte("davinci-reenc-v1")

// ReencChain is the per-batch offset-scalar chain: one secret seed per
// transition drives every re-encryption, and binding r_0 to the state
// root before the batch keeps the chain distinct across transitions —
// so no scalar can repeat within or across batches. The seed carries
// all the secrecy; the root is a domain separator, not a secret.
type ReencChain struct {
	next *big.Int
}

// NewReencChain seeds the chain from the sequencer-private seed and the
// state root BEFORE the batch (as a big.Int; see the SDK helper for the
// arbo-LE hex conversion). r_0 = H(tag || be32(seed) || be32(oldRoot))
// reduced mod BN254 Fr.
func NewReencChain(seed, oldRoot *big.Int) *ReencChain {
	if seed == nil || oldRoot == nil {
		panic("elgamal: NewReencChain needs a seed and the previous root")
	}
	var buf [16 + 32 + 32]byte
	copy(buf[:16], reencDomainTag)
	seed.FillBytes(buf[16:48])
	oldRoot.FillBytes(buf[48:80])
	d := sha256.Sum256(buf[:])
	r0 := new(big.Int).Mod(new(big.Int).SetBytes(d[:]), fr.Modulus())
	return &ReencChain{next: r0}
}

// Next returns the current chain scalar and advances the chain
// (r_{t+1} = H(be32(r_t)) mod Fr, same reencryptScalar as the guest).
func (c *ReencChain) Next() *big.Int {
	r := new(big.Int).Set(c.next)
	c.next = reencryptScalar(c.next)
	return r
}

// ReencryptChained re-encrypts the ballot's active fields with the
// batch's shared scalar chain. Fields [0, numFields) each consume one
// chain scalar and become ct + EncryptedZero(pk, r_i); padded fields
// [numFields, params.FieldsPerBallot) are copied unchanged so they
// stay at whatever the caller stored (the guest asserts identity).
func (z *Ballot) ReencryptChained(publicKey ecc.Point, chain *ReencChain, numFields int) (*Ballot, error) {
	if !z.Valid() {
		return nil, fmt.Errorf("invalid ballot")
	}
	if chain == nil {
		return nil, fmt.Errorf("nil reenc chain")
	}
	if numFields < 1 || numFields > params.FieldsPerBallot {
		return nil, fmt.Errorf("numFields %d out of range [1, %d]", numFields, params.FieldsPerBallot)
	}
	// Match Reencrypt's curve-type conversion: build the encrypted zero
	// on the ballot's own curve so SafeAdd doesn't hit a type mismatch
	// between bjj_gnark and bjj_iden3 implementations.
	ballotCurve := curves.New(z.CurveType)
	convertedPubKey := ballotCurve.SetPoint(publicKey.Point())
	out := NewBallot(ballotCurve)
	for i := 0; i < params.FieldsPerBallot; i++ {
		if i < numFields {
			r := chain.Next()
			c1zero, c2zero := EncryptedZero(convertedPubKey, r)
			out.Ciphertexts[i].Add(z.Ciphertexts[i], &Ciphertext{C1: c1zero, C2: c2zero})
			continue
		}
		// Padded slot: copy the input coordinates verbatim.
		px, py := z.Ciphertexts[i].C1.Point()
		out.Ciphertexts[i].C1 = ballotCurve.New().SetPoint(px, py)
		px, py = z.Ciphertexts[i].C2.Point()
		out.Ciphertexts[i].C2 = ballotCurve.New().SetPoint(px, py)
	}
	return out, nil
}
