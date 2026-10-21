package davinci

import (
	"strings"
	"testing"
)

// vkVariant is vkJSON with one top-level field replaced by raw JSON.
func vkVariant(field, raw string) []byte {
	ic := strings.TrimSuffix(strings.Repeat(`["1","2","1"],`, BallotPublicInputs+1), ",")
	fields := map[string]string{
		"vk_alpha_1": `["1","2","1"]`,
		"vk_beta_2":  `[["1","2"],["3","4"],["1","0"]]`,
		"vk_gamma_2": `[["1","2"],["3","4"],["1","0"]]`,
		"vk_delta_2": `[["5","2"],["3","4"],["1","0"]]`,
		"IC":         `[` + ic + `]`,
	}
	var parts []string
	for _, k := range []string{"vk_alpha_1", "vk_beta_2", "vk_gamma_2", "vk_delta_2", "IC"} {
		v := fields[k]
		if k == field {
			if raw == "" {
				continue // drop the field
			}
			v = raw
		}
		parts = append(parts, `"`+k+`":`+v)
	}
	return []byte("{" + strings.Join(parts, ",") + "}")
}

// vkWithLastIC is the base VK with its last IC point replaced.
func vkWithLastIC(raw string) []byte {
	ic := strings.Repeat(`["1","2","1"],`, BallotPublicInputs) + raw
	return vkVariant("IC", "["+ic+"]")
}

// The base variant must hash, or the negative cases below prove nothing.
func TestBallotVKLeafVariantBaseAccepted(t *testing.T) {
	if _, err := BallotVKLeaf(vkVariant("", "")); err != nil {
		t.Fatalf("base VK: %v", err)
	}
}

// BUG: an empty or missing coordinate is hashed as zero and BallotVKLeaf succeeds, where Rust refuses the VK.
func TestBallotVKLeafRefusesEmptyAndMissingCoordinates(t *testing.T) {
	cases := map[string][]byte{
		"empty alpha x":        vkVariant("vk_alpha_1", `["","2","1"]`),
		"empty beta y.c1":      vkVariant("vk_beta_2", `[["1","2"],["3",""],["1","0"]]`),
		"empty delta x.c0":     vkVariant("vk_delta_2", `[["","2"],["3","4"],["1","0"]]`),
		"empty IC y":           vkWithLastIC(`["1","","1"]`),
		"alpha short array":    vkVariant("vk_alpha_1", `["1","2"]`),
		"alpha long array":     vkVariant("vk_alpha_1", `["1","2","1","7"]`),
		"beta short array":     vkVariant("vk_beta_2", `[["1","2"],["3","4"]]`),
		"beta short row":       vkVariant("vk_beta_2", `[["1"],["3","4"],["1","0"]]`),
		"beta long row":        vkVariant("vk_beta_2", `[["1","2","9"],["3","4"],["1","0"]]`),
		"IC short entry":       vkWithLastIC(`["1","2"]`),
		"IC empty entry":       vkWithLastIC(`[]`),
		"missing vk_beta_2":    vkVariant("vk_beta_2", ""),
		"missing vk_alpha_1":   vkVariant("vk_alpha_1", ""),
		"null vk_gamma_2":      vkVariant("vk_gamma_2", `null`),
		"empty marker alpha":   vkVariant("vk_alpha_1", `["1","2",""]`),
		"empty marker delta":   vkVariant("vk_delta_2", `[["5","2"],["3","4"],["",""]]`),
		"coordinate >= q":      vkVariant("vk_alpha_1", `["21888242871839275222246405745257275088696311157297823662689037894645226208583","2","1"]`),
		"coordinate 2^256-1":   vkVariant("vk_alpha_1", `["115792089237316195423570985008687907853269984665640564039457584007913129639935","2","1"]`),
		"G1 marker not 0 or 1": vkVariant("vk_alpha_1", `["1","2","2"]`),
		"G2 marker not 1,0":    vkVariant("vk_beta_2", `[["1","2"],["3","4"],["1","1"]]`),
	}
	for name, raw := range cases {
		if _, err := BallotVKLeaf(raw); err == nil {
			t.Errorf("%s: want error, got a leaf", name)
		}
	}
}

// BUG: delta == gamma is missed when only the projective markers differ, though the wire (and Rust, TS, the guest) see the same point.
func TestBallotVKLeafRefusesDeltaEqualGammaOtherMarker(t *testing.T) {
	gamma := `[["1","2"],["3","4"],["1","0"]]`
	for name, delta := range map[string]string{
		"marker 5,0": `[["1","2"],["3","4"],["5","0"]]`,
		"marker 1,7": `[["1","2"],["3","4"],["1","7"]]`,
		"marker 0,1": `[["1","2"],["3","4"],["0","1"]]`,
	} {
		raw := vkVariant("vk_gamma_2", gamma)
		raw = []byte(strings.Replace(string(raw), `"vk_delta_2":[["5","2"],["3","4"],["1","0"]]`, `"vk_delta_2":`+delta, 1))
		if _, err := BallotVKLeaf(raw); err == nil {
			t.Errorf("%s: delta equals gamma on the wire, want error", name)
		}
	}
}
