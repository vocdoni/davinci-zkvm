package davinci

import (
	"encoding/json"
	"testing"
)

// BUG: a typed Groth16Proof marshals without "curve", a field input-gen's SnarkJsProof requires, so the service refuses every request built from typed proofs.
func TestGroth16ProofMarshalHasServiceFields(t *testing.T) {
	data, err := json.Marshal(&Groth16Proof{
		A: [3]string{"1", "2", "1"}, B: [3][2]string{{"3", "4"}, {"5", "6"}, {"1", "0"}}, C: [3]string{"7", "8", "1"},
		Protocol: "groth16",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// input-gen SnarkJsProof: curve, protocol, pi_a, pi_b, pi_c, none defaulted.
	for _, k := range []string{"curve", "protocol", "pi_a", "pi_b", "pi_c"} {
		if _, ok := m[k]; !ok {
			t.Errorf("proof JSON lacks %q: %s", k, data)
		}
	}
}
