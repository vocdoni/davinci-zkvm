package davinci

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// VoteTag domain-separates the vote envelope a voter signs.
const VoteTag = "davinci-vote-v1"

// VoteEnvelopeDigest is the 32-byte message a voter signs:
// keccak256(VoteTag ‖ processID_BE32 ‖ voteID_BE8 ‖ sha256(ballot)), 87 bytes.
// ballot is the original ballot the proof commits to, as its BallotFields
// twisted-Edwards coordinates in circuit order (c1.x, c1.y, c2.x, c2.y per
// field, the identity (0, 1), (0, 1) at or above the election's numFields);
// sha256 runs over the coordinates as 32-byte big-endian words and is never
// reduced. Mirrors rust-sdk census::vote_envelope_digest and the batch guest
// (circuit/src/ecdsa.rs).
func VoteEnvelopeDigest(processID *big.Int, voteID uint64, ballot []*big.Int) ([32]byte, error) {
	var out [32]byte
	if processID == nil || processID.Sign() < 0 || processID.Cmp(bn254FrModulus) >= 0 {
		return out, fmt.Errorf("vote envelope: process id is not a field element")
	}
	if len(ballot) != BallotFields {
		return out, fmt.Errorf("vote envelope: %d ballot coordinates, want %d", len(ballot), BallotFields)
	}
	h := sha256.New()
	var word [32]byte
	for i, c := range ballot {
		if c == nil || c.Sign() < 0 || c.Cmp(bn254FrModulus) >= 0 {
			return out, fmt.Errorf("vote envelope: ballot coordinate %d is not a field element", i)
		}
		c.FillBytes(word[:])
		h.Write(word[:])
	}
	pre := make([]byte, 0, 87)
	pre = append(pre, VoteTag...)
	processID.FillBytes(word[:])
	pre = append(pre, word[:]...)
	pre = binary.BigEndian.AppendUint64(pre, voteID)
	pre = h.Sum(pre)
	copy(out[:], ethcrypto.Keccak256(pre))
	return out, nil
}

// VoteMessageHash is the personal-sign hash of VoteEnvelopeDigest,
// keccak256("\x19Ethereum Signed Message:\n32" ‖ digest): the value the guest
// recovers the voter's key from.
func VoteMessageHash(processID *big.Int, voteID uint64, ballot []*big.Int) ([32]byte, error) {
	var out [32]byte
	d, err := VoteEnvelopeDigest(processID, voteID, ballot)
	if err != nil {
		return out, err
	}
	copy(out[:], ethcrypto.Keccak256([]byte("\x19Ethereum Signed Message:\n32"), d[:]))
	return out, nil
}

// SignVote signs the vote envelope with the voter's key: r ‖ s ‖ v, 65 bytes,
// low-S, v the recovery id 0 or 1 (deterministic, RFC 6979).
func SignVote(key *ecdsa.PrivateKey, processID *big.Int, voteID uint64, ballot []*big.Int) ([]byte, error) {
	z, err := VoteMessageHash(processID, voteID, ballot)
	if err != nil {
		return nil, err
	}
	return ethcrypto.Sign(z[:], key)
}

// RecoverVoteSigner returns the address that signed the vote envelope. sig is
// r ‖ s ‖ v with v in {0, 1, 27, 28}; a high-S signature is refused.
func RecoverVoteSigner(processID *big.Int, voteID uint64, ballot []*big.Int, sig []byte) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("vote signature: %d bytes, want 65", len(sig))
	}
	norm := append([]byte(nil), sig...)
	switch norm[64] {
	case 0, 1:
	case 27, 28:
		norm[64] -= 27
	default:
		return common.Address{}, fmt.Errorf("vote signature: recovery id %d not in {0, 1, 27, 28}", sig[64])
	}
	r, s := new(big.Int).SetBytes(norm[:32]), new(big.Int).SetBytes(norm[32:64])
	if !ethcrypto.ValidateSignatureValues(norm[64], r, s, true) {
		return common.Address{}, fmt.Errorf("vote signature: r or s out of range, or high S")
	}
	z, err := VoteMessageHash(processID, voteID, ballot)
	if err != nil {
		return common.Address{}, err
	}
	pub, err := ethcrypto.SigToPub(z[:], norm)
	if err != nil {
		return common.Address{}, fmt.Errorf("vote signature: %w", err)
	}
	return ethcrypto.PubkeyToAddress(*pub), nil
}
