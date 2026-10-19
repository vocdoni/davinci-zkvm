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
// Assumes snarkjs G2 ordering [[x_c0,x_c1],[y_c0,y_c1],[1,0]] (the
// ballot VK is a genuine circom/snarkjs artifact). A VK in another ordering
// would hash differently and fail the guest's binding check immediately.
//
// It refuses a VK the batch guest rejects: one without BallotPublicInputs+1
// IC points, or with vk_delta_2 == vk_gamma_2 (no phase-2 contribution, so
// anyone can forge proofs).
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
	if len(vk.IC) != BallotPublicInputs+1 {
		return nil, fmt.Errorf("vk has %d IC points, want %d", len(vk.IC), BallotPublicInputs+1)
	}
	if g2Equal(vk.Delta, vk.Gamma) {
		return nil, fmt.Errorf("vk has delta == gamma (no phase-2 contribution)")
	}

	var buf []byte
	var badCoord string
	le32 := func(dec string) {
		v, ok := new(big.Int).SetString(dec, 10)
		if !ok || v.Sign() < 0 || v.BitLen() > 256 {
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
			// Identity: all zeros, as input-gen's g1_to_raw and the guest write it.
			buf = append(buf, make([]byte, 64)...)
			return
		}
		le32(p[0])
		le32(p[1])
	}
	g2 := func(p [3][2]string) {
		if p[2][0] == "0" && p[2][1] == "0" {
			buf = append(buf, make([]byte, 128)...)
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

// g2Equal compares two snarkjs G2 points numerically, so a padded or
// re-encoded copy of gamma is still caught.
func g2Equal(a, b [3][2]string) bool {
	for i := range a {
		for j := range a[i] {
			x, okx := new(big.Int).SetString(a[i][j], 10)
			y, oky := new(big.Int).SetString(b[i][j], 10)
			if !okx || !oky || x.Cmp(y) != 0 {
				return false
			}
		}
	}
	return true
}
