package integration

// ballot_worker_test.go implements the child (worker) side of subprocess-based
// ballot proof generation. TestMain intercepts BALLOT_WORKER_MODE before any
// test framework setup; the wire types and parent-side logic live in
// ballot_worker.go so they are available during a plain `go build`.
//
// Worker flow:
//   Parent: write ballotWorkerInput JSON → spawn subprocess → read ballotWorkerOutput JSON
//   Child:  read input → call GenerateBallotBatch → write output → os.Exit(0)

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	nodesig "github.com/vocdoni/davinci-node/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-node/types"
)

// TestMain intercepts the worker mode before any test framework setup.
func TestMain(m *testing.M) {
	if os.Getenv("BALLOT_WORKER_MODE") == "1" {
		runBallotWorkerMode()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// ---- child (worker) side ----

func runBallotWorkerMode() {
	inputPath := os.Getenv("BALLOT_WORKER_INPUT")
	outputPath := os.Getenv("BALLOT_WORKER_OUTPUT")
	if inputPath == "" || outputPath == "" {
		fmt.Fprintln(os.Stderr, "ballot worker: missing BALLOT_WORKER_INPUT/OUTPUT env vars")
		os.Exit(1)
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ballot worker: read input: %v\n", err)
		os.Exit(1)
	}
	var inp ballotWorkerInput
	if err := json.Unmarshal(raw, &inp); err != nil {
		fmt.Fprintf(os.Stderr, "ballot worker: parse input: %v\n", err)
		os.Exit(1)
	}

	// Reconstruct processID
	var processID types.ProcessID
	copy(processID[:], inp.ProcessID)

	// Reconstruct encryption key from decimal big.Int strings
	x, ok1 := new(big.Int).SetString(inp.EncKeyX, 10)
	y, ok2 := new(big.Int).SetString(inp.EncKeyY, 10)
	if !ok1 || !ok2 {
		fmt.Fprintln(os.Stderr, "ballot worker: bad enc key coords")
		os.Exit(1)
	}
	encKey := bjjgnark.New().(*bjjgnark.BJJ).SetPoint(x, y).(*bjjgnark.BJJ)

	// Reconstruct voters deterministically from CensusIdx (same seed formula as NewElection)
	voters := make([]*Voter, len(inp.Voters))
	for i, wv := range inp.Voters {
		seed := make([]byte, 32)
		for j := range seed {
			seed[j] = byte((wv.CensusIdx*7 + j*3 + 42) % 256)
		}
		signer, err := nodesig.NewSignerFromSeed(seed)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ballot worker: voter %d signer: %v\n", i, err)
			os.Exit(1)
		}
		addrBytes := signer.Address().Bytes()
		weight, ok := new(big.Int).SetString(wv.WeightStr, 10)
		if !ok {
			fmt.Fprintf(os.Stderr, "ballot worker: voter %d weight parse\n", i)
			os.Exit(1)
		}
		voters[i] = &Voter{
			Signer:        signer,
			AddressBytes:  addrBytes,
			AddressBigInt: new(big.Int).SetBytes(addrBytes),
			CensusIdx:     wv.CensusIdx,
			Weight:        weight,
		}
	}

	batch, err := GenerateBallotBatch(processID, encKey, voters, inp.SeedBase)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ballot worker: GenerateBallotBatch: %v\n", err)
		os.Exit(1)
	}

	// Serialize output
	wo := ballotWorkerOutput{Results: make([]workerBallotResult, len(batch.Results))}
	for i, r := range batch.Results {
		wr := workerBallotResult{
			VoteID:       r.VoteID,
			AddressLo16:  r.AddressLo16,
			ProofJSON:    string(r.ProofJSON),
			PublicInputs: r.PublicInputs,
			SigJSON:      string(r.SigJSON),
		}
		if r.RawBallot != nil {
			for j := 0; j < 8; j++ {
				wr.C1X[j] = r.RawBallot.C1X[j].String()
				wr.C1Y[j] = r.RawBallot.C1Y[j].String()
				wr.C2X[j] = r.RawBallot.C2X[j].String()
				wr.C2Y[j] = r.RawBallot.C2Y[j].String()
			}
		}
		wo.Results[i] = wr
	}

	outData, err := json.Marshal(wo)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ballot worker: marshal output: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outputPath, outData, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "ballot worker: write output: %v\n", err)
		os.Exit(1)
	}
}
