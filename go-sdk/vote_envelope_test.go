package davinci

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	qt "github.com/frankban/quicktest"
)

type voteEnvelopeFixture struct {
	ProcessID string   `json:"pid"`
	VoteID    string   `json:"vote_id"`
	Ballot    []string `json:"ballot"`
	SignerKey string   `json:"signer_key"`
	Digest    string   `json:"digest"`
	Signature string   `json:"signature"`
	Address   string   `json:"address"`
}

func unhex(c *qt.C, s string) []byte {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	c.Assert(err, qt.IsNil)
	return b
}

// TestVoteEnvelopeVectors replays rust-sdk/testdata/hashes.json
// vote_envelope (written by cmd/sdk-vectors) and rebuilds each digest from
// the byte layout by hand: tag (15) ‖ pid BE32 ‖ vote id BE8 ‖ sha256 of the
// 64 BE32 coordinates, keccak256 over the 87 bytes.
func TestVoteEnvelopeVectors(t *testing.T) {
	c := qt.New(t)
	raw, err := os.ReadFile("../rust-sdk/testdata/hashes.json")
	c.Assert(err, qt.IsNil)
	var file struct {
		VoteEnvelope []voteEnvelopeFixture `json:"vote_envelope"`
	}
	c.Assert(json.Unmarshal(raw, &file), qt.IsNil)
	c.Assert(file.VoteEnvelope, qt.HasLen, 5)
	for i, v := range file.VoteEnvelope {
		pid := new(big.Int).SetBytes(unhex(c, v.ProcessID))
		vid := new(big.Int).SetBytes(unhex(c, v.VoteID)).Uint64()
		ballot := make([]*big.Int, len(v.Ballot))
		h := sha256.New()
		for j, s := range v.Ballot {
			ballot[j], _ = new(big.Int).SetString(s, 10)
			h.Write(ballot[j].FillBytes(make([]byte, 32)))
		}
		pre := append([]byte("davinci-vote-v1"), unhex(c, v.ProcessID)...)
		pre = append(pre, unhex(c, v.VoteID)...)
		pre = h.Sum(pre)
		c.Assert(pre, qt.HasLen, 87)
		c.Assert(hex.EncodeToString(ethcrypto.Keccak256(pre)), qt.Equals, strings.TrimPrefix(v.Digest, "0x"))

		d, err := VoteEnvelopeDigest(pid, vid, ballot)
		c.Assert(err, qt.IsNil)
		c.Assert("0x"+hex.EncodeToString(d[:]), qt.Equals, v.Digest, qt.Commentf("vector %d", i))
		key, err := ethcrypto.ToECDSA(unhex(c, v.SignerKey))
		c.Assert(err, qt.IsNil)
		sig, err := SignVote(key, pid, vid, ballot)
		c.Assert(err, qt.IsNil)
		c.Assert("0x"+hex.EncodeToString(sig), qt.Equals, v.Signature)
		addr := common.HexToAddress(v.Address)
		got, err := RecoverVoteSigner(pid, vid, ballot, sig)
		c.Assert(err, qt.IsNil)
		c.Assert(got, qt.Equals, addr)
		sig27 := append([]byte(nil), sig...)
		sig27[64] += 27
		got, err = RecoverVoteSigner(pid, vid, ballot, sig27)
		c.Assert(err, qt.IsNil)
		c.Assert(got, qt.Equals, addr)

		// Another vote id, process id or ciphertext recovers someone else.
		other, err := RecoverVoteSigner(pid, vid^1, ballot, sig)
		c.Assert(err == nil && other == addr, qt.IsFalse)
		other, err = RecoverVoteSigner(new(big.Int).Add(pid, big.NewInt(1)), vid, ballot, sig)
		c.Assert(err == nil && other == addr, qt.IsFalse)
		changed := append([]*big.Int(nil), ballot...)
		changed[3] = new(big.Int).Add(changed[3], big.NewInt(1))
		other, err = RecoverVoteSigner(pid, vid, changed, sig)
		c.Assert(err == nil && other == addr, qt.IsFalse)

		// Malformed: recovery id 2, the high-S twin, a short signature.
		bad := append([]byte(nil), sig...)
		bad[64] = 2
		_, err = RecoverVoteSigner(pid, vid, ballot, bad)
		c.Assert(err, qt.IsNotNil)
		twin := append([]byte(nil), sig...)
		new(big.Int).Sub(ethcrypto.S256().Params().N, new(big.Int).SetBytes(sig[32:64])).FillBytes(twin[32:64])
		twin[64] ^= 1
		_, err = RecoverVoteSigner(pid, vid, ballot, twin)
		c.Assert(err, qt.IsNotNil)
		_, err = RecoverVoteSigner(pid, vid, ballot, sig[:64])
		c.Assert(err, qt.IsNotNil)
	}
	// Inputs that are not field elements, or not 64 coordinates.
	c.Assert(func() error {
		_, err := VoteEnvelopeDigest(bn254FrModulus, 1<<63, make([]*big.Int, BallotFields))
		return err
	}(), qt.IsNotNil)
	_, err = VoteEnvelopeDigest(big.NewInt(1), 1<<63, make([]*big.Int, BallotFields-1))
	c.Assert(err, qt.IsNotNil)
}
