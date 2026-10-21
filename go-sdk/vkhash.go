package davinci

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
)

// bn254Q is the BN254 base field modulus. VK coordinates must be below it,
// as input-gen and rust-sdk require (Fq::from_bigint).
var bn254Q, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)

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
// It refuses a VK the batch guest or input-gen rejects: one without
// BallotPublicInputs+1 IC points, a point that is not exactly [x, y, z] (G1)
// or three pairs (G2), a coordinate that is not a decimal below q, a marker
// other than 1 / [1, 0] (affine) or 0 / [0, 0] (identity), or delta equal
// to gamma on the wire (no phase-2 contribution, so anyone can forge proofs).
func BallotVKLeaf(vkJSON []byte) (*big.Int, error) {
	var vk struct {
		Alpha []string   `json:"vk_alpha_1"`
		Beta  [][]string `json:"vk_beta_2"`
		Gamma [][]string `json:"vk_gamma_2"`
		Delta [][]string `json:"vk_delta_2"`
		IC    [][]string `json:"IC"`
	}
	if err := json.Unmarshal(vkJSON, &vk); err != nil {
		return nil, fmt.Errorf("vk json: %w", err)
	}
	if len(vk.IC) != BallotPublicInputs+1 {
		return nil, fmt.Errorf("vk has %d IC points, want %d", len(vk.IC), BallotPublicInputs+1)
	}
	alpha, err := vkG1Wire(vk.Alpha)
	if err != nil {
		return nil, fmt.Errorf("vk_alpha_1: %w", err)
	}
	g2s := make([][]byte, 3)
	for i, p := range [][][]string{vk.Beta, vk.Gamma, vk.Delta} {
		if g2s[i], err = vkG2Wire(p); err != nil {
			return nil, fmt.Errorf("vk %s: %w", []string{"vk_beta_2", "vk_gamma_2", "vk_delta_2"}[i], err)
		}
	}
	// Compare what the guest sees: the markers are not on the wire.
	if bytes.Equal(g2s[1], g2s[2]) {
		return nil, fmt.Errorf("vk has delta == gamma (no phase-2 contribution)")
	}

	buf := append([]byte(nil), alpha...)
	for _, w := range g2s {
		buf = append(buf, w...)
	}
	buf = binary.LittleEndian.AppendUint64(buf, uint64(len(vk.IC)))
	for i, ic := range vk.IC {
		w, err := vkG1Wire(ic)
		if err != nil {
			return nil, fmt.Errorf("vk IC[%d]: %w", i, err)
		}
		buf = append(buf, w...)
	}
	digest := sha256.Sum256(buf)
	return new(big.Int).SetBytes(digest[:]), nil
}

// vkCoord is a decimal coordinate below q as 32 little-endian bytes.
func vkCoord(dec string) ([]byte, error) {
	v, ok := new(big.Int).SetString(dec, 10)
	if !ok || v.Sign() < 0 || v.Cmp(bn254Q) >= 0 {
		return nil, fmt.Errorf("bad coordinate %q", dec)
	}
	var b [32]byte
	v.FillBytes(b[:])
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b[:], nil
}

// vkG1Wire is a snarkjs G1 point [x, y, z] as the guest's 64 wire bytes;
// the identity (z = "0") is all zeros, as input-gen's g1_to_raw writes it.
func vkG1Wire(p []string) ([]byte, error) {
	if len(p) != 3 {
		return nil, fmt.Errorf("G1 point has %d entries, want 3", len(p))
	}
	switch p[2] {
	case "0":
		return make([]byte, 64), nil
	case "1":
	default:
		return nil, fmt.Errorf("G1 marker %q, want 1 or 0", p[2])
	}
	x, err := vkCoord(p[0])
	if err != nil {
		return nil, err
	}
	y, err := vkCoord(p[1])
	if err != nil {
		return nil, err
	}
	return append(x, y...), nil
}

// vkG2Wire is a snarkjs G2 point [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]]
// as the guest's 128 wire bytes; the identity (z = [0, 0]) is all zeros.
func vkG2Wire(p [][]string) ([]byte, error) {
	if len(p) != 3 {
		return nil, fmt.Errorf("G2 point has %d rows, want 3", len(p))
	}
	for i, row := range p {
		if len(row) != 2 {
			return nil, fmt.Errorf("G2 row %d has %d entries, want 2", i, len(row))
		}
	}
	switch {
	case p[2][0] == "0" && p[2][1] == "0":
		return make([]byte, 128), nil
	case p[2][0] == "1" && p[2][1] == "0":
	default:
		return nil, fmt.Errorf("G2 marker %q, want [1, 0] or [0, 0]", p[2])
	}
	var out []byte
	for _, dec := range []string{p[0][0], p[0][1], p[1][0], p[1][1]} {
		c, err := vkCoord(dec)
		if err != nil {
			return nil, err
		}
		out = append(out, c...)
	}
	return out, nil
}
