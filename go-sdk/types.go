// Package davinci provides a Go client SDK for the davinci-zkvm service.
//
// It allows callers to submit batches of Groth16 BN254 ballot proofs
// alongside Ethereum ECDSA signatures for ZisK STARK proving.
package davinci

import "encoding/json"

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
	// Smt contains optional SMT state-transition proofs. When present, the circuit
	// verifies each transition and sets output[9]=1 on success.
	Smt []SmtEntry `json:"smt,omitempty"`
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
