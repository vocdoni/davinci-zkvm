package integration

// ballot_worker.go implements subprocess-based ballot proof generation.
//
// generateBallotBatchViaSubprocess spawns a fresh copy of the test binary in
// BALLOT_WORKER_MODE so that the OS reclaims all wasmer/rapidsnark CGO memory
// (~128 MB WASM linear memory per proof) when the subprocess exits.

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"

	"github.com/vocdoni/davinci-node/circuits/ballotproof"
	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/types"
)

// ---- wire types ----

type ballotWorkerInput struct {
	ProcessID []byte        `json:"process_id"`
	EncKeyX   string        `json:"enc_key_x"` // decimal big.Int
	EncKeyY   string        `json:"enc_key_y"` // decimal big.Int
	Voters    []workerVoter `json:"voters"`
	SeedBase  int64         `json:"seed_base"`
}

type workerVoter struct {
	CensusIdx int    `json:"census_idx"`
	WeightStr string `json:"weight"` // decimal big.Int
}

type ballotWorkerOutput struct {
	Results []workerBallotResult `json:"results"`
}

type workerBallotResult struct {
	VoteID       uint64    `json:"vote_id"`
	AddressLo16  uint64    `json:"address_lo16"`
	ProofJSON    string    `json:"proof_json"`
	PublicInputs []string  `json:"public_inputs"`
	SigJSON      string    `json:"sig_json"`
	C1X          [NumFields]string `json:"c1x"`
	C1Y          [NumFields]string `json:"c1y"`
	C2X          [NumFields]string `json:"c2x"`
	C2Y          [NumFields]string `json:"c2y"`
}

// ---- parent side ----

// ballotWorkerChunkSize bounds how many ballot proofs a single subprocess
// generates. Wasmer/rapidsnark accumulate native memory across iterations even
// without an OS-level OOM, and the CGO runtime SIGABRTs above ~300–400 proofs.
// Chunking forces a fresh subprocess (and thus fresh CGO heap) per chunk.
const ballotWorkerChunkSize = 128

// generateBallotBatchViaSubprocess generates ballot proofs in fresh subprocess(es)
// so that all WASM/JIT native memory is freed when each subprocess exits.
// For batches larger than ballotWorkerChunkSize it spawns multiple subprocesses
// and concatenates the results.
func generateBallotBatchViaSubprocess(
	processID types.ProcessID,
	encKey *bjjgnark.BJJ,
	voters []*Voter,
	seedBase int64,
) (*BatchProveComponents, error) {
	if len(voters) <= ballotWorkerChunkSize {
		return generateBallotBatchSubprocessOne(processID, encKey, voters, seedBase)
	}
	// Chunk: each chunk's subprocess receives seedBase+offset so the per-voter
	// seeds (seedBase+i in GenerateBallotBatch) line up with the original batch.
	var combined *BatchProveComponents
	for off := 0; off < len(voters); off += ballotWorkerChunkSize {
		end := off + ballotWorkerChunkSize
		if end > len(voters) {
			end = len(voters)
		}
		part, err := generateBallotBatchSubprocessOne(
			processID, encKey, voters[off:end], seedBase+int64(off),
		)
		if err != nil {
			return nil, fmt.Errorf("ballot chunk [%d,%d): %w", off, end, err)
		}
		if combined == nil {
			combined = part
		} else {
			combined.Proofs = append(combined.Proofs, part.Proofs...)
			combined.PublicInputs = append(combined.PublicInputs, part.PublicInputs...)
			combined.Sigs = append(combined.Sigs, part.Sigs...)
			combined.Results = append(combined.Results, part.Results...)
		}
	}
	return combined, nil
}

func generateBallotBatchSubprocessOne(
	processID types.ProcessID,
	encKey *bjjgnark.BJJ,
	voters []*Voter,
	seedBase int64,
) (*BatchProveComponents, error) {
	// Build the input payload
	coords := encKey.BigInts()
	inp := ballotWorkerInput{
		ProcessID: processID[:],
		EncKeyX:   coords[0].String(),
		EncKeyY:   coords[1].String(),
		SeedBase:  seedBase,
		Voters:    make([]workerVoter, len(voters)),
	}
	for i, v := range voters {
		inp.Voters[i] = workerVoter{
			CensusIdx: v.CensusIdx,
			WeightStr: v.Weight.String(),
		}
	}

	inputData, err := json.Marshal(inp)
	if err != nil {
		return nil, fmt.Errorf("marshal worker input: %w", err)
	}

	// Temp files for IPC
	inF, err := os.CreateTemp("", "bw-in-*.json")
	if err != nil {
		return nil, fmt.Errorf("create input temp: %w", err)
	}
	defer os.Remove(inF.Name())
	if _, err := inF.Write(inputData); err != nil {
		return nil, err
	}
	inF.Close()

	outF, err := os.CreateTemp("", "bw-out-*.json")
	if err != nil {
		return nil, fmt.Errorf("create output temp: %w", err)
	}
	outPath := outF.Name()
	outF.Close()
	defer os.Remove(outPath)

	// Run subprocess
	selfExe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable: %w", err)
	}
	cmd := exec.Command(selfExe, "-test.run=^$", "-test.v=false")
	cmd.Env = append(os.Environ(),
		"BALLOT_WORKER_MODE=1",
		"BALLOT_WORKER_INPUT="+inF.Name(),
		"BALLOT_WORKER_OUTPUT="+outPath,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ballot worker subprocess failed: %w\n%s", err, out)
	}

	// Parse output
	outData, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("read worker output: %w", err)
	}
	var wo ballotWorkerOutput
	if err := json.Unmarshal(outData, &wo); err != nil {
		return nil, fmt.Errorf("parse worker output: %w", err)
	}

	// Reconstruct BatchProveComponents
	n := len(wo.Results)
	proofs := make([]json.RawMessage, n)
	pubInputs := make([][]string, n)
	sigs := make([]json.RawMessage, n)
	results := make([]*BallotResult, n)

	for i, wr := range wo.Results {
		proofs[i] = json.RawMessage(wr.ProofJSON)
		pubInputs[i] = wr.PublicInputs
		sigs[i] = json.RawMessage(wr.SigJSON)

		raw := &ballotRaw{}
		for j := 0; j < NumFields; j++ {
			raw.C1X[j], _ = new(big.Int).SetString(wr.C1X[j], 10)
			raw.C1Y[j], _ = new(big.Int).SetString(wr.C1Y[j], 10)
			raw.C2X[j], _ = new(big.Int).SetString(wr.C2X[j], 10)
			raw.C2Y[j], _ = new(big.Int).SetString(wr.C2Y[j], 10)
		}
		results[i] = &BallotResult{
			VoteID:       wr.VoteID,
			AddressLo16:  wr.AddressLo16,
			RawBallot:    raw,
			ProofJSON:    json.RawMessage(wr.ProofJSON),
			PublicInputs: wr.PublicInputs,
			SigJSON:      json.RawMessage(wr.SigJSON),
		}
	}

	return &BatchProveComponents{
		VK:           json.RawMessage(ballotproof.CircomVerificationKey),
		Proofs:       proofs,
		PublicInputs: pubInputs,
		Sigs:         sigs,
		Results:      results,
	}, nil
}
