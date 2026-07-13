package davinci

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// BallotVKLeaf computes the state tree's BallotVKHash config leaf (key 0x07)
// from a snarkjs verification_key.json: sha256 over the batch guest's VK wire
// bytes (alpha_g1 ‖ beta_g2 ‖ gamma_g2 ‖ delta_g2 ‖ gamma_abc_len ‖ gamma_abc,
// canonical coordinates as 32-byte little-endian integers — input-gen's
// g1_to_raw / g2_to_raw layout). The digest is read big-endian, matching the
// guest's hash_vk_bytes.
//
// ponytail: assumes snarkjs G2 ordering [[x_c0,x_c1],[y_c0,y_c1],[1,0]] (the
// ballot VK is a genuine circom/snarkjs artifact). A VK in another ordering
// would hash differently and fail the guest's binding check immediately.
func BallotVKLeaf(vkJSON []byte) (*big.Int, error) {
	var vk struct {
		Alpha [3]string    `json:"vk_alpha_1"`
		Beta  [3][2]string `json:"vk_beta_2"`
		Gamma [3][2]string `json:"vk_gamma_2"`
		Delta [3][2]string `json:"vk_delta_2"`
		IC    [][3]string  `json:"IC"`
	}
	if err := json.Unmarshal(vkJSON, &vk); err != nil {
		return nil, fmt.Errorf("vk json: %w", err)
	}

	var buf []byte
	var badCoord string
	le32 := func(dec string) {
		v, ok := new(big.Int).SetString(dec, 10)
		if !ok {
			if badCoord == "" {
				badCoord = dec
			}
			v = new(big.Int)
		}
		var b [32]byte
		v.FillBytes(b[:])
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		buf = append(buf, b[:]...)
	}
	g1 := func(p [3]string) {
		if p[2] == "0" {
			// arkworks identity encoding: x=0, y=1
			le32("0")
			le32("1")
			return
		}
		le32(p[0])
		le32(p[1])
	}
	g2 := func(p [3][2]string) {
		if p[2][0] == "0" && p[2][1] == "0" {
			le32("0")
			le32("0")
			le32("1")
			le32("0")
			return
		}
		le32(p[0][0])
		le32(p[0][1])
		le32(p[1][0])
		le32(p[1][1])
	}

	g1(vk.Alpha)
	g2(vk.Beta)
	g2(vk.Gamma)
	g2(vk.Delta)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(vk.IC)))
	for _, ic := range vk.IC {
		g1(ic)
	}
	if badCoord != "" {
		return nil, fmt.Errorf("vk: bad coordinate %q", badCoord)
	}
	digest := sha256.Sum256(buf)
	return new(big.Int).SetBytes(digest[:]), nil
}
