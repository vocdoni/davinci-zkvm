// Package davinci provides a Go client SDK for the davinci-zkvm service.
//
// It allows callers to submit batches of Groth16 BN254 ballot proofs
// alongside Ethereum ECDSA signatures for ZisK STARK proving.
package davinci

import "encoding/json"

// Output register layout for the ZisK circuit.
// These constants identify the index of each u32 output register returned
// by the ZisK emulator / prover and mirror the public inputs of the
// davinci-node StateTransitionCircuit.
//
// To reconstruct a 256-bit root from its 8 u32 output slots (LE):
//
//	var root [4]uint64
//	for i := 0; i < 4; i++ {
//	    root[i] = uint64(outputs[base+i*2]) | (uint64(outputs[base+i*2+1]) << 32)
//	}
const (
	OutputOverallOk  = 0  // 1 = all checks passed, 0 = failure
	OutputFailMask   = 1  // bit-flag mask (see FAIL_* in types.rs)

	// RootHashBefore: 256-bit Arbo SHA-256 state root before the batch (8 × u32, LE)
	OutputOldRoot    = 2  // base index; occupies slots [2..9]

	// RootHashAfter: 256-bit Arbo SHA-256 state root after the batch (8 × u32, LE)
	OutputNewRoot    = 10 // base index; occupies slots [10..17]

	OutputVotersCount     = 18 // number of non-dummy votes in this batch
	OutputOverwrittenCount = 19 // number of votes that overwrote an earlier ballot

	// CensusRoot: 256-bit lean-IMT Poseidon BN254 census root (8 × u32, LE)
	OutputCensusRoot = 20 // base index; occupies slots [20..27]

	// BlobCommitmentLimbs: 3 × 128-bit KZG blob commitment limbs (12 × u32)
	// Populated from the KZG commitment when a KZGBLK block is present, zero otherwise.
	OutputBlobCommitment = 28 // base index; occupies slots [28..39]

	// Diagnostic outputs (not used as public inputs)
	OutputBatchOk    = 40 // Groth16 batch verification result (1=ok)
	OutputECDSAOk    = 41 // ECDSA signature batch result (1=ok)
	OutputSMTOk      = 42 // legacy SMTBLK batch (1=ok, 2=absent, 0=fail)
	OutputNProofs    = 43 // number of Groth16 proofs verified
	OutputNPublic    = 44 // number of public inputs per Groth16 proof
	OutputLogN       = 45 // log₂ of the aggregation tree depth
)

// SmtEntry represents one Arbo-compatible SMT state-transition proof.
// All 32-byte field values are hex-encoded strings (with "0x" prefix).
// Siblings must be padded with "0x00..00" entries to n_levels length.
type SmtEntry struct {
	// OldRoot is the 32-byte big-endian hex-encoded tree root before the transition.
	OldRoot string `json:"old_root"`
	// NewRoot is the 32-byte big-endian hex-encoded tree root after the transition.
	NewRoot string `json:"new_root"`
	// OldKey is the key of the existing leaf being replaced (zero if IsOld0=1).
	OldKey string `json:"old_key"`
	// OldValue is the value of the existing leaf (zero if IsOld0=1).
	OldValue string `json:"old_value"`
	// IsOld0 is 1 when the old leaf slot was empty (pure insert), 0 otherwise.
	IsOld0 uint8 `json:"is_old0"`
	// NewKey is the key being inserted or updated.
	NewKey string `json:"new_key"`
	// NewValue is the value being inserted or updated.
	NewValue string `json:"new_value"`
	// Fnc0 is 1 for insert (fnc0=1, fnc1=0) or delete (fnc0=1, fnc1=1).
	Fnc0 uint8 `json:"fnc0"`
	// Fnc1 is 1 for update (fnc0=0, fnc1=1) or delete (fnc0=1, fnc1=1).
	Fnc1 uint8 `json:"fnc1"`
	// Siblings are the Merkle sibling hashes root→leaf, padded to n_levels with zeros.
	Siblings []string `json:"siblings"`
}

// StateTransitionData holds all state-transition fields for the full DAVINCI protocol.
// When non-nil, the ZisK circuit will verify the full state-transition in addition
// to Groth16 proofs and ECDSA signatures.
//
// All 32-byte field values are 64-character hex strings (with "0x" prefix).
// All SMT sibling slices must be padded to the same n_levels with zero entries.
type StateTransitionData struct {
	// VotersCount is the number of real (non-dummy) votes in this batch.
	VotersCount uint64 `json:"voters_count"`
	// OverwrittenCount is the number of votes that replaced an existing ballot.
	OverwrittenCount uint64 `json:"overwritten_count"`

	// ProcessID is the 32-byte process identifier (arbo SHA-256 state tree key 0x0).
	ProcessID string `json:"process_id"`
	// OldStateRoot is the arbo SHA-256 state root before all transitions.
	OldStateRoot string `json:"old_state_root"`
	// NewStateRoot is the arbo SHA-256 state root after all transitions.
	NewStateRoot string `json:"new_state_root"`

	// VoteIDSmt is the chain of VoteID insertion proofs (one per real vote).
	// Keys are in [VoteIDMin, VoteIDMax] = [0x8000000000000000, 0xFFFFFFFFFFFFFFFF].
	VoteIDSmt []SmtEntry `json:"vote_id_smt"`

	// BallotSmt is the chain of ballot insertion/update proofs (one per real vote).
	// Keys are in [BallotMin, BallotMax] = [0x10, 0x7FFFFFFFFFFFFFFF].
	BallotSmt []SmtEntry `json:"ballot_smt"`

	// ResultsAddSmt is the transition that accumulates the homomorphic sum of ballots.
	// Nil if no accumulator update (e.g. all dummy votes).
	ResultsAddSmt *SmtEntry `json:"results_add_smt,omitempty"`

	// ResultsSubSmt is the transition that records re-encrypted ballots to subtract.
	// Nil when there are no overwritten votes.
	ResultsSubSmt *SmtEntry `json:"results_sub_smt,omitempty"`

	// ProcessSmt holds exactly 4 read-proofs for config entries in OldStateRoot.
	// Order: processID (0x0), ballotMode (0x2), encryptionKey (0x3), censusOrigin (0x6).
	ProcessSmt []SmtEntry `json:"process_smt"`

	// BallotProofs holds the result accumulator and leaf hash verification data.
	// When non-nil, the circuit verifies:
	//   - Each ballot SMT leaf = SHA-256(serialized_ballot)
	//   - NewResultsAdd = OldResultsAdd + Σ(VoterBallots)
	//   - NewResultsSub = OldResultsSub + Σ(OverwrittenBallots)
	BallotProofs *BallotProofData `json:"ballot_proofs,omitempty"`
}

// BallotProofData holds the ballot data needed for result accumulator verification.
// Each BallotData is 32 hex strings representing 32 BN254 Fr field elements
// (8 ElGamal ciphertexts × 4 coordinates: C1.X, C1.Y, C2.X, C2.Y).
type BallotProofData struct {
	// OldResultsAdd is the previous ResultsAdd leaf value (32 Fr elements, big-endian hex).
	OldResultsAdd []string `json:"old_results_add"`
	// OldResultsSub is the previous ResultsSub leaf value (32 Fr elements, big-endian hex).
	OldResultsSub []string `json:"old_results_sub"`
	// VoterBallots contains the re-encrypted ballot for each voter (same order as BallotSmt).
	// Each inner slice has exactly 32 big-endian hex strings.
	VoterBallots [][]string `json:"voter_ballots"`
	// OverwrittenBallots contains the old ballot data for each UPDATE entry.
	// Each inner slice has exactly 32 big-endian hex strings.
	OverwrittenBallots [][]string `json:"overwritten_ballots"`
}

// CensusProof is a lean-IMT Poseidon membership proof for a census voter.
// The leaf value is PackAddressWeight(address, weight) = (address << 88) | weight.
// Siblings are the actual non-empty siblings in the Merkle path (lean-IMT omits empty levels).
type CensusProof struct {
	// Root is the 32-byte big-endian hex-encoded census tree root.
	Root string `json:"root"`
	// Leaf is the 32-byte big-endian hex-encoded leaf: PackAddressWeight(address, weight).
	Leaf string `json:"leaf"`
	// Index contains the packed path bits (bit i = (index >> i) & 1; 1 = right child).
	Index uint64 `json:"index"`
	// Siblings are the non-empty Merkle siblings in the path (variable length).
	Siblings []string `json:"siblings"`
}

// BjjPoint is an ElGamal ciphertext point (x, y) on BabyJubJub in BN254 Fr.
// Coordinates are 32-byte big-endian hex strings.
type BjjPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

// BjjCiphertext is one ElGamal ciphertext (C1, C2) on BabyJubJub.
type BjjCiphertext struct {
	C1 BjjPoint `json:"c1"`
	C2 BjjPoint `json:"c2"`
}

// ReencryptionEntry holds the re-encryption data for one voter.
type ReencryptionEntry struct {
	// K is the re-encryption seed (before Poseidon hash), 32-byte BE hex.
	K string `json:"k"`
	// Original contains the 8 original ciphertexts from the ballot proof.
	Original [8]BjjCiphertext `json:"original"`
	// Reencrypted contains the 8 re-encrypted ciphertexts stored in the state tree.
	Reencrypted [8]BjjCiphertext `json:"reencrypted"`
}

// ReencryptionData holds the re-encryption verification data for the full batch.
type ReencryptionData struct {
	// EncryptionKeyX is the x-coordinate of the ElGamal encryption public key.
	EncryptionKeyX string `json:"encryption_key_x"`
	// EncryptionKeyY is the y-coordinate of the ElGamal encryption public key.
	EncryptionKeyY string `json:"encryption_key_y"`
	// Entries holds one entry per real voter.
	Entries []ReencryptionEntry `json:"entries"`
}

// ProveRequest is the HTTP request body for POST /prove.
type ProveRequest struct {
	// VK is the snarkjs verification key (JSON object).
	VK json.RawMessage `json:"vk"`
	// Proofs is the array of snarkjs Groth16 proof objects.
	Proofs []json.RawMessage `json:"proofs"`
	// PublicInputs contains the public signals for each proof (same order as Proofs).
	PublicInputs [][]string `json:"public_inputs"`
	// Sigs contains one ECDSA signature per proof (same order as Proofs). Mandatory.
	Sigs []json.RawMessage `json:"sigs"`
	// Smt contains optional simple SMT state-transition proofs (legacy / testing).
	// For the full DAVINCI protocol, use State instead.
	Smt []SmtEntry `json:"smt,omitempty"`
	// State contains the full state-transition data for the DAVINCI protocol.
	// When non-nil, the circuit verifies chained SMT transitions and outputs
	// the old/new state roots and vote counts (outputs 10-15).
	State *StateTransitionData `json:"state,omitempty"`
	// CensusProofs contains one lean-IMT Poseidon membership proof per voter.
	// When non-empty, the circuit verifies each proof against the census root.
	CensusProofs []CensusProof `json:"census_proofs,omitempty"`
	// Reencryption contains the re-encryption verification data.
	// When non-nil, the circuit verifies ElGamal re-encryption for each voter.
	Reencryption *ReencryptionData `json:"reencryption,omitempty"`
	// KZG contains the EIP-4844 blob barycentric evaluation data.
	// When non-nil, the circuit verifies the KZG commitment and evaluation.
	KZG *KZGRequest `json:"kzg,omitempty"`
}

// KZGRequest holds the KZG blob barycentric evaluation inputs for the API.
// All byte fields are hex-encoded with optional "0x" prefix.
type KZGRequest struct {
	// ProcessID is the 32-byte big-endian hex BN254 Fr process identifier.
	ProcessID string `json:"process_id"`
	// RootHashBefore is the 32-byte big-endian hex Arbo state root before the batch.
	RootHashBefore string `json:"root_hash_before"`
	// Commitment is the 48-byte big-endian hex compressed BLS12-381 G1 KZG commitment.
	Commitment string `json:"commitment"`
	// YClaimed is the 32-byte big-endian hex BLS12-381 Fr claimed evaluation Y = P(Z).
	YClaimed string `json:"y_claimed"`
	// Blob is the 131072-byte big-endian hex full EIP-4844 blob (4096 × 32-byte cells).
	Blob string `json:"blob"`
}

// JobResponse is the response body for GET /jobs/{id}.
type JobResponse struct {
	JobID     string  `json:"job_id"`
	Status    string  `json:"status"`
	ElapsedMs *int64  `json:"elapsed_ms,omitempty"`
	Error     *string `json:"error,omitempty"`
}

// ProveResponse is the response body for POST /prove.
type ProveResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

// HealthResponse is the response body for GET /health.
type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	QueueLen int    `json:"queue_len"`
}
