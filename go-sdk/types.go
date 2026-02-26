// Package davinci provides a Go client SDK for the davinci-zkvm service.
//
// It allows callers to submit batches of Groth16 BN254 ballot proofs
// alongside Ethereum ECDSA signatures for ZisK STARK proving.
package davinci

import "encoding/json"

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
