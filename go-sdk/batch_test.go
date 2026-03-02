package davinci

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

func TestProveBatchToRequest(t *testing.T) {
	vk := &VerificationKey{
		Protocol: "groth16",
		Curve:    "bn128",
		NPublic:  3,
		Alpha1:   [3]string{"1", "2", "1"},
		Beta2:    [3][2]string{{"1", "0"}, {"0", "1"}, {"1", "0"}},
		Gamma2:   [3][2]string{{"1", "0"}, {"0", "1"}, {"1", "0"}},
		Delta2:   [3][2]string{{"1", "0"}, {"0", "1"}, {"1", "0"}},
		IC:       [][3]string{{"1", "2", "1"}, {"3", "4", "1"}, {"5", "6", "1"}, {"7", "8", "1"}},
	}

	proof := &Groth16Proof{
		A:        [3]string{"10", "20", "1"},
		B:        [3][2]string{{"11", "12"}, {"13", "14"}, {"1", "0"}},
		C:        [3]string{"30", "40", "1"},
		Protocol: "groth16",
	}

	sig := &EcdsaSignature{
		R:       big.NewInt(111),
		S:       big.NewInt(222),
		PubKeyX: big.NewInt(333),
		PubKeyY: big.NewInt(444),
		VoteID:  42,
		Address: big.NewInt(0xDEAD),
	}

	pubInputs := NewPublicInput(big.NewInt(0xDEAD), big.NewInt(42), big.NewInt(999))

	census := CensusProofFromBigInts(big.NewInt(100), big.NewInt(200), 0, []*big.Int{big.NewInt(300)})

	batch := &ProveBatch{
		VerificationKey: vk,
		Voters: []VoterBallot{
			{
				Proof:        proof,
				PublicInputs: pubInputs,
				Signature:    sig,
				Census:       census,
			},
		},
	}

	req, err := batch.toRequest()
	if err != nil {
		t.Fatalf("toRequest: %v", err)
	}

	// Verify VK is present
	if len(req.VK) == 0 {
		t.Fatal("VK should not be empty")
	}

	// Verify parallel arrays have correct length
	if len(req.Proofs) != 1 {
		t.Fatalf("expected 1 proof, got %d", len(req.Proofs))
	}
	if len(req.PublicInputs) != 1 {
		t.Fatalf("expected 1 public input set, got %d", len(req.PublicInputs))
	}
	if len(req.Sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(req.Sigs))
	}
	if len(req.CensusProofs) != 1 {
		t.Fatalf("expected 1 census proof, got %d", len(req.CensusProofs))
	}

	// Verify public inputs are decimal strings
	if req.PublicInputs[0][0] != "57005" { // 0xDEAD
		t.Errorf("expected public input 0 = '57005', got %q", req.PublicInputs[0][0])
	}
	if req.PublicInputs[0][1] != "42" {
		t.Errorf("expected public input 1 = '42', got %q", req.PublicInputs[0][1])
	}

	// No re-encryption → field should be nil
	if req.Reencryption != nil {
		t.Error("expected nil reencryption when no voter has reenc data")
	}
}

func TestProveBatchWithReencryption(t *testing.T) {
	batch := &ProveBatch{
		VerificationKeyJSON: json.RawMessage(`{"protocol":"groth16"}`),
		Voters: []VoterBallot{
			{
				ProofJSON:    json.RawMessage(`{"pi_a":["1","2","1"]}`),
				PublicInputs: NewPublicInput(big.NewInt(1)),
				Signature: &EcdsaSignature{
					R: big.NewInt(1), S: big.NewInt(2),
					PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4),
					VoteID: 1, Address: big.NewInt(5),
				},
				Census: CensusProof{Root: "0x" + zeroHex64, Leaf: "0x" + zeroHex64},
				Reencryption: &VoterReencryption{
					K: big.NewInt(42),
				},
			},
		},
		EncryptionKey: &BjjPoint{X: bigIntToHex32BE(big.NewInt(10)), Y: bigIntToHex32BE(big.NewInt(20))},
	}

	req, err := batch.toRequest()
	if err != nil {
		t.Fatalf("toRequest: %v", err)
	}

	if req.Reencryption == nil {
		t.Fatal("expected reencryption data")
	}
	if len(req.Reencryption.Entries) != 1 {
		t.Fatalf("expected 1 reenc entry, got %d", len(req.Reencryption.Entries))
	}
	if req.Reencryption.EncryptionKeyX != bigIntToHex32BE(big.NewInt(10)) {
		t.Errorf("wrong encryption key X: %s", req.Reencryption.EncryptionKeyX)
	}
}

func TestProveBatchValidation(t *testing.T) {
	tests := []struct {
		name  string
		batch ProveBatch
		want  string
	}{
		{
			name:  "no VK",
			batch: ProveBatch{Voters: []VoterBallot{{}}},
			want:  "verification key is required",
		},
		{
			name:  "no voters",
			batch: ProveBatch{VerificationKeyJSON: json.RawMessage(`{}`)},
			want:  "at least one voter ballot is required",
		},
		{
			name: "reenc without encryption key",
			batch: ProveBatch{
				VerificationKeyJSON: json.RawMessage(`{}`),
				Voters: []VoterBallot{{
					ProofJSON:    json.RawMessage(`{}`),
					PublicInputs: NewPublicInput(big.NewInt(1)),
					Signature: &EcdsaSignature{
						R: big.NewInt(1), S: big.NewInt(2),
						PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4),
						Address: big.NewInt(5),
					},
					Reencryption: &VoterReencryption{K: big.NewInt(1)},
				}},
			},
			want: "encryption key is required",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.batch.toRequest()
			if err == nil {
				t.Fatal("expected error")
			}
			if !strContains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.want)
			}
		})
	}
}

func strContains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstr(s, substr)
}

func searchSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestPackAddressWeight(t *testing.T) {
	addr := new(big.Int).SetUint64(0xDEADBEEF)
	weight := big.NewInt(1)

	leaf := PackAddressWeight(addr, weight)

	// leaf = (addr << 88) | weight
	expected := new(big.Int).Lsh(addr, 88)
	expected.Or(expected, weight)

	if leaf.Cmp(expected) != 0 {
		t.Errorf("PackAddressWeight mismatch: got %s, want %s", leaf.Text(16), expected.Text(16))
	}

	// Verify we can extract the address back: addr = leaf >> 88
	recovered := new(big.Int).Rsh(leaf, 88)
	if recovered.Cmp(addr) != 0 {
		t.Errorf("address recovery failed: got %s, want %s", recovered.Text(16), addr.Text(16))
	}
}

func TestNewBallotProofData(t *testing.T) {
	make32 := func(start int64) []*big.Int {
		vals := make([]*big.Int, 32)
		for i := range vals {
			vals[i] = big.NewInt(start + int64(i))
		}
		return vals
	}

	bp := NewBallotProofData(make32(0), make32(100), [][]*big.Int{make32(200)}, nil)

	if len(bp.OldResultsAdd) != 32 {
		t.Fatalf("OldResultsAdd: expected 32, got %d", len(bp.OldResultsAdd))
	}
	if len(bp.OldResultsSub) != 32 {
		t.Fatalf("OldResultsSub: expected 32, got %d", len(bp.OldResultsSub))
	}
	if len(bp.VoterBallots) != 1 {
		t.Fatalf("VoterBallots: expected 1, got %d", len(bp.VoterBallots))
	}
	if len(bp.OverwrittenBallots) != 0 {
		t.Fatalf("OverwrittenBallots: expected 0, got %d", len(bp.OverwrittenBallots))
	}

	// Verify hex encoding: first element should be bigIntToHex32BE(big.NewInt(0))
	if bp.OldResultsAdd[0] != bigIntToHex32BE(big.NewInt(0)) {
		t.Errorf("OldResultsAdd[0] = %s, want %s", bp.OldResultsAdd[0], bigIntToHex32BE(big.NewInt(0)))
	}
}

func TestNewPublicInput(t *testing.T) {
	pi := NewPublicInput(big.NewInt(0xDEAD), big.NewInt(42), big.NewInt(999))
	strs := pi.toStrings()
	if len(strs) != 3 {
		t.Fatalf("expected 3 values, got %d", len(strs))
	}
	if strs[0] != "57005" {
		t.Errorf("expected 57005, got %s", strs[0])
	}
	if strs[1] != "42" {
		t.Errorf("expected 42, got %s", strs[1])
	}
}

func TestProveContextCancellation(t *testing.T) {
	// Verify that Prove respects context cancellation immediately on build error
	c := NewClient("http://localhost:0")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := c.Prove(ctx, &ProveBatch{
		VerificationKeyJSON: json.RawMessage(`{}`),
		Voters: []VoterBallot{{
			ProofJSON:    json.RawMessage(`{}`),
			PublicInputs: NewPublicInput(big.NewInt(1)),
			Signature: &EcdsaSignature{
				R: big.NewInt(1), S: big.NewInt(2),
				PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4),
				Address: big.NewInt(5),
			},
		}},
	})
	if err == nil {
		t.Fatal("expected error from cancelled context or connection refused")
	}
	// Either "context canceled" or "connection refused" — both are acceptable
	t.Logf("Prove error (expected): %v", err)
}

func TestProveBatchRoundTrip(t *testing.T) {
	// Verify that ProveBatch → ProveRequest → JSON is valid
	batch := &ProveBatch{
		VerificationKeyJSON: json.RawMessage(`{"protocol":"groth16","curve":"bn128","nPublic":3}`),
		Voters: []VoterBallot{
			{
				ProofJSON:    json.RawMessage(`{"pi_a":["1","2","1"],"pi_b":[["3","4"],["5","6"],["1","0"]],"pi_c":["7","8","1"],"protocol":"groth16"}`),
				PublicInputs: NewPublicInput(big.NewInt(100), big.NewInt(200)),
				Signature: &EcdsaSignature{
					R: big.NewInt(1), S: big.NewInt(2),
					PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4),
					VoteID: 10, Address: big.NewInt(0xFF),
				},
				Census: CensusProofFromBigInts(big.NewInt(1), big.NewInt(2), 0, nil),
			},
		},
		State: NewStateTransitionData(1, 0, big.NewInt(1), big.NewInt(2), big.NewInt(3), nil, nil, nil, nil, nil),
	}

	req, err := batch.toRequest()
	if err != nil {
		t.Fatalf("toRequest: %v", err)
	}

	// Verify it serializes to valid JSON
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("empty JSON output")
	}

	// Verify we can unmarshal it back
	var req2 ProveRequest
	if err := json.Unmarshal(data, &req2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req2.Proofs) != 1 {
		t.Errorf("roundtrip: expected 1 proof, got %d", len(req2.Proofs))
	}

	// Verify state data survived
	if req2.State == nil {
		t.Fatal("state should not be nil after roundtrip")
	}
	if req2.State.VotersCount != 1 {
		t.Errorf("voters count: got %d, want 1", req2.State.VotersCount)
	}
}

func TestProveTimeout(t *testing.T) {
	// Verify that Prove respects context deadlines
	c := NewClient("http://localhost:0")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Sleep briefly so the deadline expires
	time.Sleep(5 * time.Millisecond)

	_, err := c.Prove(ctx, &ProveBatch{
		VerificationKeyJSON: json.RawMessage(`{}`),
		Voters: []VoterBallot{{
			ProofJSON:    json.RawMessage(`{}`),
			PublicInputs: NewPublicInput(big.NewInt(1)),
			Signature: &EcdsaSignature{
				R: big.NewInt(1), S: big.NewInt(2),
				PubKeyX: big.NewInt(3), PubKeyY: big.NewInt(4),
				Address: big.NewInt(5),
			},
		}},
	})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	t.Logf("Timeout error (expected): %v", err)
}
