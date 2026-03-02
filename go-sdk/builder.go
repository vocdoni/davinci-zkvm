package davinci

import (
	"encoding/json"
	"fmt"
)

// ProveRequestBuilder provides a fluent interface for constructing ProveRequest
// using strongly-typed inputs. It handles all serialization to the JSON format
// expected by the Rust service.
//
// Usage:
//
//	req, err := davinci.NewProveRequestBuilder().
//	    SetVerificationKey(vk).
//	    AddProof(proof, pubInputs).
//	    AddEcdsaSignature(sig).
//	    SetStateTransition(stateData).
//	    Build()
type ProveRequestBuilder struct {
	vk           *VerificationKey
	vkRaw        json.RawMessage // alternative: raw JSON from circom/snarkjs
	proofs       []*Groth16Proof
	proofsRaw    []json.RawMessage // alternative: raw JSON proofs
	publicInputs []*PublicInput
	sigs         []*EcdsaSignature
	state        *StateTransitionData
	census       []CensusProof
	reenc        *ReencryptionData
	kzg          *KZGRequest
	legacySmt    []SmtEntry
}

// NewProveRequestBuilder creates a new empty builder.
func NewProveRequestBuilder() *ProveRequestBuilder {
	return &ProveRequestBuilder{}
}

// SetVerificationKey sets the Groth16 BN254 verification key (shared across all proofs).
func (b *ProveRequestBuilder) SetVerificationKey(vk *VerificationKey) *ProveRequestBuilder {
	b.vk = vk
	b.vkRaw = nil
	return b
}

// SetVerificationKeyJSON sets the verification key from raw snarkjs JSON bytes.
// Use this when you already have the VK in JSON format from circom/snarkjs.
func (b *ProveRequestBuilder) SetVerificationKeyJSON(vkJSON []byte) *ProveRequestBuilder {
	b.vk = nil
	b.vkRaw = json.RawMessage(vkJSON)
	return b
}

// AddProof adds a ballot proof with its public inputs to the batch.
// Proofs must be added in the same order as their ECDSA signatures.
func (b *ProveRequestBuilder) AddProof(proof *Groth16Proof, pubInputs *PublicInput) *ProveRequestBuilder {
	b.proofs = append(b.proofs, proof)
	b.proofsRaw = append(b.proofsRaw, nil)
	b.publicInputs = append(b.publicInputs, pubInputs)
	return b
}

// AddProofJSON adds a ballot proof from raw snarkjs JSON bytes with its public inputs.
// Use this when you already have the proof in JSON format from circom/snarkjs.
func (b *ProveRequestBuilder) AddProofJSON(proofJSON []byte, pubInputs *PublicInput) *ProveRequestBuilder {
	b.proofs = append(b.proofs, nil)
	b.proofsRaw = append(b.proofsRaw, json.RawMessage(proofJSON))
	b.publicInputs = append(b.publicInputs, pubInputs)
	return b
}

// AddEcdsaSignature adds an ECDSA signature for the corresponding proof.
// Signatures must be added in the same order as proofs.
func (b *ProveRequestBuilder) AddEcdsaSignature(sig *EcdsaSignature) *ProveRequestBuilder {
	b.sigs = append(b.sigs, sig)
	return b
}

// SetStateTransition sets the full DAVINCI state-transition data.
// Mutually exclusive with SetLegacySmt.
func (b *ProveRequestBuilder) SetStateTransition(state *StateTransitionData) *ProveRequestBuilder {
	b.state = state
	return b
}

// SetLegacySmt sets legacy SMT entries (for testing or simple use cases).
// Mutually exclusive with SetStateTransition.
func (b *ProveRequestBuilder) SetLegacySmt(entries []SmtEntry) *ProveRequestBuilder {
	b.legacySmt = entries
	return b
}

// SetCensusProofs sets the lean-IMT Poseidon census membership proofs.
func (b *ProveRequestBuilder) SetCensusProofs(proofs []CensusProof) *ProveRequestBuilder {
	b.census = proofs
	return b
}

// SetReencryption sets the ElGamal re-encryption verification data.
func (b *ProveRequestBuilder) SetReencryption(reenc *ReencryptionData) *ProveRequestBuilder {
	b.reenc = reenc
	return b
}

// SetKZG sets the KZG blob barycentric evaluation data.
func (b *ProveRequestBuilder) SetKZG(kzg *KZGRequest) *ProveRequestBuilder {
	b.kzg = kzg
	return b
}

// Build validates the builder state and produces a ProveRequest ready for
// submission via Client.SubmitProve.
func (b *ProveRequestBuilder) Build() (*ProveRequest, error) {
	if b.vk == nil && b.vkRaw == nil {
		return nil, fmt.Errorf("verification key is required")
	}
	if len(b.proofs) == 0 {
		return nil, fmt.Errorf("at least one proof is required")
	}
	if len(b.proofs) != len(b.publicInputs) {
		return nil, fmt.Errorf("proofs count (%d) must match public inputs count (%d)",
			len(b.proofs), len(b.publicInputs))
	}
	if len(b.sigs) != len(b.proofs) {
		return nil, fmt.Errorf("signatures count (%d) must match proofs count (%d)",
			len(b.sigs), len(b.proofs))
	}
	if b.state != nil && len(b.legacySmt) > 0 {
		return nil, fmt.Errorf("state and legacy smt are mutually exclusive")
	}

	// Serialize VK (use raw if provided, otherwise marshal typed)
	var vkJSON json.RawMessage
	if b.vkRaw != nil {
		vkJSON = b.vkRaw
	} else {
		raw, err := json.Marshal(b.vk)
		if err != nil {
			return nil, fmt.Errorf("marshal verification key: %w", err)
		}
		vkJSON = raw
	}

	// Serialize proofs (use raw if provided, otherwise marshal typed)
	proofsJSON := make([]json.RawMessage, len(b.proofs))
	for i := range b.proofs {
		if b.proofsRaw[i] != nil {
			proofsJSON[i] = b.proofsRaw[i]
		} else {
			raw, err := json.Marshal(b.proofs[i])
			if err != nil {
				return nil, fmt.Errorf("marshal proof[%d]: %w", i, err)
			}
			proofsJSON[i] = raw
		}
	}

	// Convert public inputs to [][]string
	pubInputs := make([][]string, len(b.publicInputs))
	for i, pi := range b.publicInputs {
		pubInputs[i] = pi.toStrings()
	}

	// Serialize signatures
	sigsJSON := make([]json.RawMessage, len(b.sigs))
	for i, s := range b.sigs {
		raw, err := json.Marshal(s)
		if err != nil {
			return nil, fmt.Errorf("marshal sig[%d]: %w", i, err)
		}
		sigsJSON[i] = raw
	}

	return &ProveRequest{
		VK:           vkJSON,
		Proofs:       proofsJSON,
		PublicInputs: pubInputs,
		Sigs:         sigsJSON,
		Smt:          b.legacySmt,
		State:        b.state,
		CensusProofs: b.census,
		Reencryption: b.reenc,
		KZG:          b.kzg,
	}, nil
}
