package davinci

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestBigIntToHex32BE(t *testing.T) {
	tests := []struct {
		name string
		in   *big.Int
		want string
	}{
		{"zero", big.NewInt(0), "0x" + zeroHex64},
		{"nil", nil, "0x" + zeroHex64},
		{"one", big.NewInt(1), "0x0000000000000000000000000000000000000000000000000000000000000001"},
		{"0xff", big.NewInt(0xff), "0x00000000000000000000000000000000000000000000000000000000000000ff"},
		{"large", new(big.Int).SetBytes([]byte{0xab, 0xcd, 0xef}), "0x0000000000000000000000000000000000000000000000000000000000abcdef"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bigIntToHex32BE(tt.in)
			if got != tt.want {
				t.Errorf("bigIntToHex32BE(%v) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseOutputs(t *testing.T) {
	// Construct a synthetic output register array from known values.
	outputs := make([]uint32, 46)

	// overall_ok = 1, fail_mask = 0
	outputs[OutputOverallOk] = 1
	outputs[OutputFailMask] = 0

	// OldRoot = 0x0000...0001 (in 8 × u32 LE: word 0 of pair 0 = 1, rest zero)
	outputs[OutputOldRoot] = 1

	// NewRoot = 0x0000...0002
	outputs[OutputNewRoot] = 2

	// VotersCount = 5, OverwrittenCount = 1
	outputs[OutputVotersCount] = 5
	outputs[OutputOverwrittenCount] = 1

	// CensusRoot = 0xABCD at lowest 32 bits
	outputs[OutputCensusRoot] = 0xABCD

	// BlobCommitment limb[0] = 42
	outputs[OutputBlobCommitment] = 42

	// Diagnostics
	outputs[OutputBatchOk] = 1
	outputs[OutputECDSAOk] = 1
	outputs[OutputNProofs] = 128
	outputs[OutputNPublic] = 3
	outputs[OutputLogN] = 7

	po, err := ParseOutputs(outputs)
	if err != nil {
		t.Fatalf("ParseOutputs: %v", err)
	}

	if !po.OK {
		t.Error("expected OK=true")
	}
	if po.FailMask != 0 {
		t.Errorf("expected FailMask=0, got 0x%x", po.FailMask)
	}
	if po.VotersCount != 5 {
		t.Errorf("VotersCount = %d, want 5", po.VotersCount)
	}
	if po.OverwrittenVotesCount != 1 {
		t.Errorf("OverwrittenVotesCount = %d, want 1", po.OverwrittenVotesCount)
	}
	if po.RootHashBefore.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("RootHashBefore = %s, want 1", po.RootHashBefore)
	}
	if po.RootHashAfter.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("RootHashAfter = %s, want 2", po.RootHashAfter)
	}
	if po.CensusRoot.Cmp(big.NewInt(0xABCD)) != 0 {
		t.Errorf("CensusRoot = %s, want 0xABCD", po.CensusRoot)
	}
	if po.BlobCommitmentLimbs[0].Cmp(big.NewInt(42)) != 0 {
		t.Errorf("BlobCommitmentLimbs[0] = %s, want 42", po.BlobCommitmentLimbs[0])
	}
	if po.NProofs != 128 {
		t.Errorf("NProofs = %d, want 128", po.NProofs)
	}
}

func TestParseOutputsFailure(t *testing.T) {
	outputs := make([]uint32, 46)
	outputs[OutputOverallOk] = 0
	outputs[OutputFailMask] = FailSMTVoteID | FailSMTBallot

	po, err := ParseOutputs(outputs)
	if err != nil {
		t.Fatalf("ParseOutputs: %v", err)
	}
	if po.OK {
		t.Error("expected OK=false")
	}
	if po.FailMask&FailSMTVoteID == 0 {
		t.Error("expected FailSMTVoteID set")
	}
	if po.FailMask&FailSMTBallot == 0 {
		t.Error("expected FailSMTBallot set")
	}
}

func TestParseOutputsTooShort(t *testing.T) {
	_, err := ParseOutputs(make([]uint32, 10))
	if err == nil {
		t.Error("expected error for short output slice")
	}
}

func TestSmtEntryFromArboTransition(t *testing.T) {
	tr := &ArboTransition{
		OldRoot:  big.NewInt(100),
		NewRoot:  big.NewInt(200),
		OldKey:   big.NewInt(0),
		OldValue: big.NewInt(0),
		NewKey:   big.NewInt(42),
		NewValue: big.NewInt(99),
		IsOld0:   1,
		Fnc0:     1,
		Fnc1:     0,
		Siblings: []*big.Int{big.NewInt(11), big.NewInt(22)},
	}

	entry := SmtEntryFromArboTransition(tr, 4)

	if entry.Fnc0 != 1 || entry.Fnc1 != 0 {
		t.Errorf("Fnc0=%d Fnc1=%d, want 1 0", entry.Fnc0, entry.Fnc1)
	}
	if entry.IsOld0 != 1 {
		t.Errorf("IsOld0=%d, want 1", entry.IsOld0)
	}
	if len(entry.Siblings) != 4 {
		t.Errorf("len(siblings)=%d, want 4", len(entry.Siblings))
	}
	// Last two siblings should be zero-padded
	if entry.Siblings[2] != "0x"+zeroHex64 || entry.Siblings[3] != "0x"+zeroHex64 {
		t.Error("siblings[2..3] should be zero-padded")
	}
}

func TestEcdsaSignatureMarshalJSON(t *testing.T) {
	sig := &EcdsaSignature{
		R:       big.NewInt(1),
		S:       big.NewInt(2),
		PubKeyX: big.NewInt(3),
		PubKeyY: big.NewInt(4),
		VoteID:  12345,
		Address: big.NewInt(99999),
	}

	data, err := json.Marshal(sig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify it's valid JSON with expected fields
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["vote_id"].(float64) != 12345 {
		t.Errorf("vote_id = %v, want 12345", m["vote_id"])
	}
	if m["address"].(string) != "99999" {
		t.Errorf("address = %v, want '99999'", m["address"])
	}
}

func TestGroth16ProofMarshalJSON(t *testing.T) {
	proof := &Groth16Proof{
		A:        [3]string{"1", "2", "1"},
		B:        [3][2]string{{"3", "4"}, {"5", "6"}, {"1", "0"}},
		C:        [3]string{"7", "8", "1"},
		Protocol: "groth16",
	}

	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["protocol"].(string) != "groth16" {
		t.Errorf("protocol = %v, want groth16", m["protocol"])
	}
	piA := m["pi_a"].([]interface{})
	if len(piA) != 3 {
		t.Errorf("pi_a length = %d, want 3", len(piA))
	}
}

func TestVerificationKeyMarshalJSON(t *testing.T) {
	vk := &VerificationKey{
		Protocol: "groth16",
		Curve:    "bn128",
		NPublic:  2,
		Alpha1:   [3]string{"1", "2", "1"},
		Beta2:    [3][2]string{{"3", "4"}, {"5", "6"}, {"1", "0"}},
		Gamma2:   [3][2]string{{"7", "8"}, {"9", "10"}, {"1", "0"}},
		Delta2:   [3][2]string{{"11", "12"}, {"13", "14"}, {"1", "0"}},
		IC:       [][3]string{{"15", "16", "1"}, {"17", "18", "1"}, {"19", "20", "1"}},
	}

	data, err := json.Marshal(vk)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["protocol"].(string) != "groth16" {
		t.Errorf("protocol = %v, want groth16", m["protocol"])
	}
	if m["curve"].(string) != "bn128" {
		t.Errorf("curve = %v, want bn128", m["curve"])
	}
	if m["nPublic"].(float64) != 2 {
		t.Errorf("nPublic = %v, want 2", m["nPublic"])
	}
	ic := m["IC"].([]interface{})
	if len(ic) != 3 {
		t.Errorf("IC length = %d, want 3", len(ic))
	}
}

func TestCensusProofFromBigInts(t *testing.T) {
	root := big.NewInt(100)
	leaf := big.NewInt(200)
	sibs := []*big.Int{big.NewInt(1), big.NewInt(2)}

	cp := CensusProofFromBigInts(root, leaf, 42, sibs)
	if cp.Index != 42 {
		t.Errorf("Index = %d, want 42", cp.Index)
	}
	if len(cp.Siblings) != 2 {
		t.Errorf("len(Siblings) = %d, want 2", len(cp.Siblings))
	}
}

func TestReencryptionEntryFromBigInts(t *testing.T) {
	k := big.NewInt(999)
	orig := make([]*big.Int, 32)
	reenc := make([]*big.Int, 32)
	for i := 0; i < 32; i++ {
		orig[i] = big.NewInt(int64(i))
		reenc[i] = big.NewInt(int64(100 + i))
	}

	entry, err := ReencryptionEntryFromBigInts(k, orig, reenc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if entry.K != bigIntToHex32BE(k) {
		t.Errorf("K mismatch")
	}
	// Verify first ciphertext
	if entry.Original[0].C1.X != bigIntToHex32BE(big.NewInt(0)) {
		t.Errorf("Original[0].C1.X mismatch")
	}

	// Wrong length
	_, err = ReencryptionEntryFromBigInts(k, make([]*big.Int, 31), reenc)
	if err == nil {
		t.Error("expected error for wrong original length")
	}
}

func TestProveRequestBuilder(t *testing.T) {
	vk := &VerificationKey{
		Protocol: "groth16",
		Curve:    "bn128",
		NPublic:  2,
		Alpha1:   [3]string{"1", "2", "1"},
		Beta2:    [3][2]string{{"3", "4"}, {"5", "6"}, {"1", "0"}},
		Gamma2:   [3][2]string{{"7", "8"}, {"9", "10"}, {"1", "0"}},
		Delta2:   [3][2]string{{"11", "12"}, {"13", "14"}, {"1", "0"}},
		IC:       [][3]string{{"15", "16", "1"}, {"17", "18", "1"}, {"19", "20", "1"}},
	}

	proof := &Groth16Proof{
		A:        [3]string{"1", "2", "1"},
		B:        [3][2]string{{"3", "4"}, {"5", "6"}, {"1", "0"}},
		C:        [3]string{"7", "8", "1"},
		Protocol: "groth16",
	}

	pubInputs := &PublicInput{Values: []*big.Int{big.NewInt(0xDEAD), big.NewInt(0xBEEF)}}

	sig := &EcdsaSignature{
		R:       big.NewInt(1),
		S:       big.NewInt(2),
		PubKeyX: big.NewInt(3),
		PubKeyY: big.NewInt(4),
		VoteID:  12345,
		Address: big.NewInt(99),
	}

	req, err := NewProveRequestBuilder().
		SetVerificationKey(vk).
		AddProof(proof, pubInputs).
		AddEcdsaSignature(sig).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if len(req.Proofs) != 1 {
		t.Errorf("len(Proofs) = %d, want 1", len(req.Proofs))
	}
	if len(req.PublicInputs) != 1 {
		t.Errorf("len(PublicInputs) = %d, want 1", len(req.PublicInputs))
	}
	if req.PublicInputs[0][0] != "57005" { // 0xDEAD = 57005
		t.Errorf("PublicInputs[0][0] = %s, want '57005'", req.PublicInputs[0][0])
	}
	if len(req.Sigs) != 1 {
		t.Errorf("len(Sigs) = %d, want 1", len(req.Sigs))
	}

	// Full JSON round-trip
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty marshaled request")
	}
}

func TestProveRequestBuilderValidation(t *testing.T) {
	vk := &VerificationKey{Protocol: "groth16", Curve: "bn128"}
	proof := &Groth16Proof{Protocol: "groth16"}
	pubIn := &PublicInput{Values: []*big.Int{big.NewInt(1)}}
	sig := &EcdsaSignature{R: big.NewInt(1), S: big.NewInt(2), PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4)}

	// Missing VK
	_, err := NewProveRequestBuilder().AddProof(proof, pubIn).AddEcdsaSignature(sig).Build()
	if err == nil {
		t.Error("expected error for missing VK")
	}

	// Missing proofs
	_, err = NewProveRequestBuilder().SetVerificationKey(vk).Build()
	if err == nil {
		t.Error("expected error for missing proofs")
	}

	// Mismatched sig count
	_, err = NewProveRequestBuilder().SetVerificationKey(vk).AddProof(proof, pubIn).Build()
	if err == nil {
		t.Error("expected error for missing signature")
	}
}

func TestProveRequestBuilderJSON(t *testing.T) {
	// Test that SetVerificationKeyJSON and AddProofJSON work end-to-end
	vkJSON := []byte(`{"protocol":"groth16","curve":"bn128","nPublic":1,"vk_alpha_1":["1","2","1"],"vk_beta_2":[["3","4"],["5","6"],["1","0"]],"vk_gamma_2":[["7","8"],["9","10"],["1","0"]],"vk_delta_2":[["11","12"],["13","14"],["1","0"]],"IC":[["15","16","1"],["17","18","1"]]}`)
	proofJSON := []byte(`{"pi_a":["1","2","1"],"pi_b":[["3","4"],["5","6"],["1","0"]],"pi_c":["7","8","1"],"protocol":"groth16"}`)

	pubIn := &PublicInput{Values: []*big.Int{big.NewInt(42)}}
	sig := &EcdsaSignature{R: big.NewInt(1), S: big.NewInt(2), PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4)}

	req, err := NewProveRequestBuilder().
		SetVerificationKeyJSON(vkJSON).
		AddProofJSON(proofJSON, pubIn).
		AddEcdsaSignature(sig).
		Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// The raw JSON should be embedded directly
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty marshaled request")
	}
}

func TestABIEncode(t *testing.T) {
	o := &PublicOutputs{
		OK:                    true,
		RootHashBefore:        big.NewInt(1),
		RootHashAfter:         big.NewInt(2),
		VotersCount:           3,
		OverwrittenVotesCount: 1,
		CensusRoot:            big.NewInt(100),
		BlobCommitmentLimbs:   [3]*big.Int{big.NewInt(10), big.NewInt(20), big.NewInt(30)},
	}

	buf := o.ABIEncode()
	if len(buf) != 256 {
		t.Fatalf("ABIEncode length = %d, want 256", len(buf))
	}

	// Check that RootHashBefore is at offset 0..31 (left-padded big-endian)
	if buf[31] != 1 {
		t.Errorf("ABIEncode[31] = %d, want 1 (RootHashBefore)", buf[31])
	}
	// RootHashAfter at offset 32..63
	if buf[63] != 2 {
		t.Errorf("ABIEncode[63] = %d, want 2 (RootHashAfter)", buf[63])
	}
	// VotersCount at offset 64..95
	if buf[95] != 3 {
		t.Errorf("ABIEncode[95] = %d, want 3 (VotersCount)", buf[95])
	}

	// Also test ABIValues
	vals := o.ABIValues()
	if vals[2].Int64() != 3 {
		t.Errorf("ABIValues[2] = %s, want 3", vals[2])
	}
}

func TestFailString(t *testing.T) {
	o := &PublicOutputs{FailMask: 0}
	if o.FailString() != "ok" {
		t.Errorf("FailString() = %q, want 'ok'", o.FailString())
	}

	o.FailMask = FailECDSA | FailKZG
	s := o.FailString()
	if s != "ecdsa|kzg" {
		t.Errorf("FailString() = %q, want 'ecdsa|kzg'", s)
	}
}

func TestPublicOutputsString(t *testing.T) {
	o := &PublicOutputs{
		OK:                    true,
		FailMask:              0,
		RootHashBefore:        big.NewInt(0xabc),
		RootHashAfter:         big.NewInt(0xdef),
		VotersCount:           5,
		OverwrittenVotesCount: 1,
		CensusRoot:            big.NewInt(0),
		BlobCommitmentLimbs:   [3]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)},
	}
	s := o.String()
	if s == "" {
		t.Error("String() returned empty")
	}
	if !contains(s, "PASS") {
		t.Errorf("expected PASS in %q", s)
	}
}

func TestNewReencryptionData(t *testing.T) {
	entries := []ReencryptionEntry{{K: "0x01"}}
	rd := NewReencryptionData(big.NewInt(10), big.NewInt(20), entries)
	if rd.EncryptionKeyX != bigIntToHex32BE(big.NewInt(10)) {
		t.Errorf("EncryptionKeyX = %s", rd.EncryptionKeyX)
	}
	if rd.EncryptionKeyY != bigIntToHex32BE(big.NewInt(20)) {
		t.Errorf("EncryptionKeyY = %s", rd.EncryptionKeyY)
	}
	if len(rd.Entries) != 1 {
		t.Errorf("len(Entries) = %d, want 1", len(rd.Entries))
	}
}

func TestNewStateTransitionData(t *testing.T) {
	voteIDSmt := []SmtEntry{{NewKey: "0x01"}}
	ballotSmt := []SmtEntry{{NewKey: "0x02"}}
	processSmt := []SmtEntry{{NewKey: "0x03"}}
	resultsAdd := &SmtEntry{NewKey: "0x04"}

	st := NewStateTransitionData(
		5, 1,
		big.NewInt(42), big.NewInt(100), big.NewInt(200),
		voteIDSmt, ballotSmt, processSmt, resultsAdd, nil,
	)

	if st.VotersCount != 5 {
		t.Errorf("VotersCount = %d, want 5", st.VotersCount)
	}
	if st.OverwrittenCount != 1 {
		t.Errorf("OverwrittenCount = %d, want 1", st.OverwrittenCount)
	}
	if st.ProcessID != bigIntToHex32BE(big.NewInt(42)) {
		t.Errorf("ProcessID = %s", st.ProcessID)
	}
	if st.ResultsAddSmt == nil {
		t.Error("ResultsAddSmt should not be nil")
	}
	if st.ResultsSubSmt != nil {
		t.Error("ResultsSubSmt should be nil")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsHelper(s, sub))
}

func containsHelper(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
