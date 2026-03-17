// Package davinci provides a Go client SDK for the davinci-zkvm service.
//
// The active ballot path uses davinci-stark proofs plus ecgfp5-native
// re-encryption and result-accumulator data.
package davinci

import (
	"encoding/json"
	"os"
	"strconv"
)

const DefaultMaxBatchSize = 128

// ConfiguredMaxBatchSize returns the Go-side batch cap used by the integration
// helpers. It must match the build-time DAVINCI_MAX_BATCH_SIZE used for the
// Rust input generator and zkVM circuit.
func ConfiguredMaxBatchSize() int {
	if s := os.Getenv("DAVINCI_MAX_BATCH_SIZE"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 2 && n&(n-1) == 0 {
			return n
		}
	}
	return DefaultMaxBatchSize
}

const (
	OutputOverallOk        = 0
	OutputFailMask         = 1
	OutputOldRoot          = 2
	OutputNewRoot          = 10
	OutputVotersCount      = 18
	OutputOverwrittenCount = 19
	OutputCensusRoot       = 20
	OutputBlobCommitment   = 28
	OutputBatchOk          = 40
	OutputECDSAOk          = 41
	OutputNProofs          = 43
	OutputNPublic          = 44
	OutputLogN             = 45
)

type SmtEntry struct {
	OldRoot  string   `json:"old_root"`
	NewRoot  string   `json:"new_root"`
	OldKey   string   `json:"old_key"`
	OldValue string   `json:"old_value"`
	IsOld0   uint8    `json:"is_old0"`
	NewKey   string   `json:"new_key"`
	NewValue string   `json:"new_value"`
	Fnc0     uint8    `json:"fnc0"`
	Fnc1     uint8    `json:"fnc1"`
	Siblings []string `json:"siblings"`
}

type StateTransitionData struct {
	VotersCount        uint64                 `json:"voters_count"`
	OverwrittenCount   uint64                 `json:"overwritten_count"`
	ProcessID          string                 `json:"process_id"`
	OldStateRoot       string                 `json:"old_state_root"`
	NewStateRoot       string                 `json:"new_state_root"`
	VoteIDSmt          []SmtEntry             `json:"vote_id_smt"`
	BallotSmt          []SmtEntry             `json:"ballot_smt"`
	ResultsAddSmt      *SmtEntry              `json:"results_add_smt,omitempty"`
	ResultsSubSmt      *SmtEntry              `json:"results_sub_smt,omitempty"`
	ProcessSmt         []SmtEntry             `json:"process_smt"`
	Ecgfp5BallotProofs *Ecgfp5BallotProofData `json:"ecgfp5_ballot_proofs,omitempty"`
}

type Ecgfp5Ciphertext struct {
	C1 string `json:"c1"`
	C2 string `json:"c2"`
}

type Ecgfp5BallotProofData struct {
	OldResultsAdd      [8]Ecgfp5Ciphertext   `json:"old_results_add"`
	OldResultsSub      [8]Ecgfp5Ciphertext   `json:"old_results_sub"`
	VoterBallots       [][8]Ecgfp5Ciphertext `json:"voter_ballots"`
	OverwrittenBallots [][8]Ecgfp5Ciphertext `json:"overwritten_ballots"`
}

type StarkProofBundleJson struct {
	Proof        string `json:"proof"`
	PublicValues string `json:"public_values"`
}

type CensusProof struct {
	Root     string   `json:"root"`
	Leaf     string   `json:"leaf"`
	Index    uint64   `json:"index"`
	Siblings []string `json:"siblings"`
}

type CensusOrigin uint64

const (
	CensusOriginMerkle CensusOrigin = 1
	CensusOriginCSP    CensusOrigin = 4
)

func (co CensusOrigin) IsCSP() bool    { return co == CensusOriginCSP }
func (co CensusOrigin) IsMerkle() bool { return co >= 1 && co <= 3 }

type CspProof struct {
	R            string `json:"r"`
	S            string `json:"s"`
	VoterAddress string `json:"voter_address"`
	Weight       string `json:"weight"`
	Index        uint64 `json:"index"`
}

type CspData struct {
	CspPubKeyX string     `json:"csp_pub_key_x"`
	CspPubKeyY string     `json:"csp_pub_key_y"`
	Proofs     []CspProof `json:"proofs"`
}

type Ecgfp5ReencryptionEntry struct {
	K           string              `json:"k"`
	Original    [8]Ecgfp5Ciphertext `json:"original"`
	Reencrypted [8]Ecgfp5Ciphertext `json:"reencrypted"`
}

type Ecgfp5ReencryptionData struct {
	EncryptionKey string                    `json:"encryption_key"`
	Entries       []Ecgfp5ReencryptionEntry `json:"entries"`
}

type ProveRequest struct {
	StarkProofs        []StarkProofBundleJson  `json:"stark_proofs,omitempty"`
	Sigs               []json.RawMessage       `json:"sigs,omitempty"`
	State              *StateTransitionData    `json:"state,omitempty"`
	CensusProofs       []CensusProof           `json:"census_proofs,omitempty"`
	CspData            *CspData                `json:"csp_data,omitempty"`
	Ecgfp5Reencryption *Ecgfp5ReencryptionData `json:"ecgfp5_reencryption,omitempty"`
	KZG                *KZGRequest             `json:"kzg,omitempty"`
}

type KZGRequest struct {
	ProcessID      string `json:"process_id"`
	RootHashBefore string `json:"root_hash_before"`
	Commitment     string `json:"commitment"`
	YClaimed       string `json:"y_claimed"`
	Blob           string `json:"blob"`
}

type JobResponse struct {
	JobID     string  `json:"job_id"`
	Status    string  `json:"status"`
	ElapsedMs *int64  `json:"elapsed_ms,omitempty"`
	Error     *string `json:"error,omitempty"`
}

type ProveResponse struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

type HealthResponse struct {
	Status      string `json:"status"`
	Version     string `json:"version"`
	ZiskVersion string `json:"zisk_version"`
	QueueLen    int    `json:"queue_len"`
}
