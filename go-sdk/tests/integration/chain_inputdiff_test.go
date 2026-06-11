// chain_inputdiff_test.go is a debug aid: builds one chained-mode batch,
// assembles the ZisK input locally (gen-input CLI + Encode*Block, the
// path validated by TestGenChainInputs) and via the service (SubmitProve),
// then byte-compares the two. Gated by CHAIN_INPUT_DIFF=1.
package integration

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/vocdoni/davinci-node/circuits/ballotproof"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func TestChainInputDiff(t *testing.T) {
	if os.Getenv("CHAIN_INPUT_DIFF") == "" {
		t.Skip("set CHAIN_INPUT_DIFF=1 to run")
	}
	batchSize := envInt("CHAIN_BATCH_SIZE", 2)

	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("service not available: %v", err)
	}

	election, err := NewElection(batchSize)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	voters := election.Voters[:batchSize]
	batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, 42)
	if err != nil {
		t.Fatalf("GenerateBallotBatch: %v", err)
	}
	reencBlock, reencBallots, err := election.BuildReencBlock(batch.Results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	stateBlock, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock: %v", err)
	}
	censusProofs, err := election.BuildCensusProofs(voters)
	if err != nil {
		t.Fatalf("BuildCensusProofs: %v", err)
	}

	// Local assembly (chain_gen path).
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "verification_key.json"), ballotproof.CircomVerificationKey, 0o600); err != nil {
		t.Fatal(err)
	}
	for i, res := range batch.Results {
		idx := i + 1
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", idx)), res.ProofJSON, 0o600)
		pubBytes, _ := json.Marshal(res.PublicInputs)
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("public_%d.json", idx)), pubBytes, 0o600)
		os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", idx)), res.SigJSON, 0o600)
	}
	outBin := filepath.Join(tmpDir, "base.bin")
	cmd := exec.Command(findGenInputBin(t),
		"--proofs-dir", tmpDir, "--output", outBin, "--nproofs", strconv.Itoa(batchSize))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-input: %v\n%s", err, out)
	}
	local, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatal(err)
	}
	stateBytes, err := davinci.EncodeStateBlock(stateBlock)
	if err != nil {
		t.Fatalf("EncodeStateBlock: %v", err)
	}
	censusBytes, err := davinci.EncodeCensusBlock(censusProofs)
	if err != nil {
		t.Fatalf("EncodeCensusBlock: %v", err)
	}
	reencBytes, err := davinci.EncodeReencBlock(reencBlock)
	if err != nil {
		t.Fatalf("EncodeReencBlock: %v", err)
	}
	local = append(local, stateBytes...)
	local = append(local, censusBytes...)
	local = append(local, reencBytes...)
	assertCircuitValid(t, local, "local input")

	// Service assembly.
	req := batch.ToProveRequest()
	req.State = stateBlock
	req.CensusProofs = censusProofs
	req.Reencryption = reencBlock
	req.Output = "stark"
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("SubmitProve: %v", err)
	}
	// The /inputs endpoint is gated until the job completes.
	if _, err := client.WaitForJob(jobID, proofTimeout()); err != nil {
		t.Fatalf("WaitForJob: %v", err)
	}
	svc, err := client.FetchInputs(jobID)
	if err != nil {
		t.Fatalf("FetchInputs: %v", err)
	}

	// input.bin = u64 LE payload length + payload + zero pad.
	if len(svc) < 8 {
		t.Fatalf("service input too short: %d", len(svc))
	}
	plen := binary.LittleEndian.Uint64(svc[:8])
	t.Logf("local payload %d bytes, service payload %d bytes", len(local), plen)
	payload := svc[8 : 8+int(plen)]
	if int(plen) != len(local) {
		t.Errorf("payload length mismatch: service %d, local %d", plen, len(local))
	}
	n := len(payload)
	if len(local) < n {
		n = len(local)
	}
	for i := 0; i < n; i++ {
		if payload[i] != local[i] {
			lo := i - 32
			if lo < 0 {
				lo = 0
			}
			hi := i + 64
			if hi > n {
				hi = n
			}
			t.Fatalf("first difference at offset %d\nservice: %x\nlocal:   %x", i, payload[lo:hi], local[lo:hi])
		}
	}
	t.Logf("inputs identical for %d bytes", n)
}
