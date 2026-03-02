package davinci

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// VoterBallot groups all proving data for a single voter in a batch.
// This is the natural unit of data that the davinci-node sequencer holds
// per ballot — it ties together the Circom proof, ECDSA signature, census
// membership proof, and re-encryption data that belong to the same vote.
//
// Voters must be added to the ProveBatch in the same order as their
// corresponding VoteID/Ballot SMT chain entries.
type VoterBallot struct {
	// Proof is the Circom BN254 Groth16 ballot proof (typed).
	// Mutually exclusive with ProofJSON.
	Proof *Groth16Proof

	// ProofJSON is a raw snarkjs proof JSON blob. Use this when the proof
	// is already serialized (e.g. from an HTTP API). Mutually exclusive
	// with Proof.
	ProofJSON json.RawMessage

	// PublicInputs are the ballot proof's public signals.
	// For the standard Circom BallotCircuit: [address, voteID, inputsHash].
	PublicInputs *PublicInput

	// Signature is the voter's ECDSA secp256k1 signature.
	Signature *EcdsaSignature

	// Census is the lean-IMT Poseidon membership proof for this voter.
	Census CensusProof

	// Reencryption holds the per-voter re-encryption data.
	// When nil, no re-encryption entry is submitted for this voter.
	Reencryption *VoterReencryption
}

// VoterReencryption holds the re-encryption data for one voter.
// This is a convenience wrapper around ReencryptionEntry that accepts
// structured BjjCiphertext values rather than flat hex strings.
type VoterReencryption struct {
	// K is the re-encryption random seed (before Poseidon hash).
	K *big.Int
	// Original contains the 8 original ElGamal ciphertexts from the ballot proof.
	Original [8]BjjCiphertext
	// Reencrypted contains the 8 re-encrypted ciphertexts stored in the state tree.
	Reencrypted [8]BjjCiphertext
}

// ProveBatch is a complete batch of voter ballots with all auxiliary data
// needed to produce a single DAVINCI ZisK proof. It is the primary
// integration type for callers replacing the Gnark proving pipeline.
//
// Usage from davinci-node's sequencer:
//
//	batch := &davinci.ProveBatch{
//	    VerificationKey: vk,
//	    Voters:          voters,
//	    State:           stateData,
//	    EncryptionKey:   &davinci.BjjPoint{X: encKeyXHex, Y: encKeyYHex},
//	    KZG:             kzgReq,
//	}
//	result, err := client.Prove(ctx, batch)
//	if err != nil { ... }
//	// result.Proof  — raw ZisK proof bytes
//	// result.Outputs — parsed PublicOutputs (roots, counts, etc.)
type ProveBatch struct {
	// VerificationKey is the Groth16 BN254 verification key shared by all
	// ballot proofs. Mutually exclusive with VerificationKeyJSON.
	VerificationKey *VerificationKey

	// VerificationKeyJSON is a raw snarkjs VK JSON blob. Use when the key
	// is already serialized. Mutually exclusive with VerificationKey.
	VerificationKeyJSON json.RawMessage

	// Voters contains one entry per non-dummy vote in the batch.
	// The order must match the VoteID and Ballot SMT chains in State.
	Voters []VoterBallot

	// State holds all state-transition SMT data (chains, results, process proofs).
	// Required for full protocol verification.
	State *StateTransitionData

	// EncryptionKey is the ElGamal public key used for re-encryption verification.
	// Required when any voter has re-encryption data. Coordinates are 32-byte
	// big-endian hex strings.
	EncryptionKey *BjjPoint

	// KZG is the data-availability blob proof. Nil when blobs are not used.
	KZG *KZGRequest
}

// ProveResult is the result of a successful DAVINCI proof generation.
type ProveResult struct {
	// JobID is the service-assigned job identifier.
	JobID string
	// Proof contains the raw ZisK STARK proof bytes.
	Proof []byte
	// Elapsed is the wall-clock time reported by the service.
	Elapsed time.Duration
}

// toRequest converts a ProveBatch into the wire-format ProveRequest
// expected by the service HTTP API.
func (b *ProveBatch) toRequest() (*ProveRequest, error) {
	if b.VerificationKey == nil && len(b.VerificationKeyJSON) == 0 {
		return nil, fmt.Errorf("verification key is required")
	}
	if len(b.Voters) == 0 {
		return nil, fmt.Errorf("at least one voter ballot is required")
	}

	// Serialize VK
	var vkJSON json.RawMessage
	if len(b.VerificationKeyJSON) > 0 {
		vkJSON = b.VerificationKeyJSON
	} else {
		raw, err := json.Marshal(b.VerificationKey)
		if err != nil {
			return nil, fmt.Errorf("marshal verification key: %w", err)
		}
		vkJSON = raw
	}

	// Flatten per-voter data into parallel arrays
	proofs := make([]json.RawMessage, len(b.Voters))
	pubInputs := make([][]string, len(b.Voters))
	sigs := make([]json.RawMessage, len(b.Voters))
	var censusProofs []CensusProof
	var reencEntries []ReencryptionEntry
	hasReenc := false

	for i, v := range b.Voters {
		// Proof
		if v.Proof == nil && len(v.ProofJSON) == 0 {
			return nil, fmt.Errorf("voter[%d]: proof or ProofJSON is required", i)
		}
		if len(v.ProofJSON) > 0 {
			proofs[i] = v.ProofJSON
		} else {
			raw, err := json.Marshal(v.Proof)
			if err != nil {
				return nil, fmt.Errorf("voter[%d]: marshal proof: %w", i, err)
			}
			proofs[i] = raw
		}

		// Public inputs
		if v.PublicInputs == nil {
			return nil, fmt.Errorf("voter[%d]: public inputs are required", i)
		}
		pubInputs[i] = v.PublicInputs.toStrings()

		// Signature
		if v.Signature == nil {
			return nil, fmt.Errorf("voter[%d]: signature is required", i)
		}
		raw, err := json.Marshal(v.Signature)
		if err != nil {
			return nil, fmt.Errorf("voter[%d]: marshal signature: %w", i, err)
		}
		sigs[i] = raw

		// Census
		censusProofs = append(censusProofs, v.Census)

		// Re-encryption
		if v.Reencryption != nil {
			hasReenc = true
			entry := ReencryptionEntry{
				K:           bigIntToHex32BE(v.Reencryption.K),
				Original:    v.Reencryption.Original,
				Reencrypted: v.Reencryption.Reencrypted,
			}
			reencEntries = append(reencEntries, entry)
		}
	}

	req := &ProveRequest{
		VK:           vkJSON,
		Proofs:       proofs,
		PublicInputs: pubInputs,
		Sigs:         sigs,
		State:        b.State,
		CensusProofs: censusProofs,
		KZG:          b.KZG,
	}

	if hasReenc {
		if b.EncryptionKey == nil {
			return nil, fmt.Errorf("encryption key is required when voters have re-encryption data")
		}
		req.Reencryption = &ReencryptionData{
			EncryptionKeyX: b.EncryptionKey.X,
			EncryptionKeyY: b.EncryptionKey.Y,
			Entries:        reencEntries,
		}
	}

	return req, nil
}

// Prove submits a ProveBatch for proving and blocks until the proof is ready
// or the context is cancelled.
//
// This is the high-level entry point that replaces the 3-stage Gnark pipeline
// (VoteVerifier → Aggregator → StateTransition) with a single ZisK proof.
//
// The returned ProveResult contains the raw proof bytes and service metadata.
// Use PublicOutputs for on-chain public inputs once the service supports
// returning circuit outputs alongside the proof.
func (c *Client) Prove(ctx context.Context, batch *ProveBatch) (*ProveResult, error) {
	req, err := batch.toRequest()
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	jobID, err := c.SubmitProve(req)
	if err != nil {
		return nil, fmt.Errorf("submit: %w", err)
	}

	// Poll until done or context cancelled
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("prove cancelled: %w", ctx.Err())
		default:
		}

		job, err := c.GetJob(jobID)
		if err != nil {
			return nil, fmt.Errorf("poll job %s: %w", jobID, err)
		}

		switch job.Status {
		case "done":
			proof, err := c.GetProof(jobID)
			if err != nil {
				return nil, fmt.Errorf("download proof %s: %w", jobID, err)
			}
			var elapsed time.Duration
			if job.ElapsedMs != nil {
				elapsed = time.Duration(*job.ElapsedMs) * time.Millisecond
			}
			return &ProveResult{
				JobID:   jobID,
				Proof:   proof,
				Elapsed: elapsed,
			}, nil

		case "failed":
			errMsg := "unknown error"
			if job.Error != nil {
				errMsg = *job.Error
			}
			return nil, fmt.Errorf("job %s failed: %s", jobID, errMsg)
		}

		// Backoff before next poll
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("prove cancelled: %w", ctx.Err())
		case <-time.After(3 * time.Second):
		}
	}
}

// NewPublicInput creates a PublicInput from variadic big.Int values.
// For the standard Circom BallotCircuit the order is:
// [address, voteID, ballotInputsHash].
func NewPublicInput(values ...*big.Int) *PublicInput {
	return &PublicInput{Values: values}
}

// PackAddressWeight packs an Ethereum address and voter weight into the
// census leaf value used by the lean-IMT: leaf = (address << 88) | weight.
//
// This matches the packing used by davinci-node's census tree and the
// circuit's extract_address_from_census_leaf function.
func PackAddressWeight(address, weight *big.Int) *big.Int {
	leaf := new(big.Int).Lsh(address, 88)
	leaf.Or(leaf, weight)
	return leaf
}
