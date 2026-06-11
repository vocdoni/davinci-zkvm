// chain_gen_test.go generates chained-mode test artifacts for the
// circuit-aggregator guest: N sequential valid batch inputs from one
// election (no KZG block) plus the chain config JSON consumed by the
// agg-input CLI. Gated by CHAIN_OUT_DIR; runs ziskemu on each input to
// assert overall_ok=1 before writing.
//
//	CHAIN_OUT_DIR=/tmp/chain CHAIN_BATCHES=2 CHAIN_BATCH_SIZE=2 \
//	  go test ./integration -run TestGenChainInputs -v
package integration

import (
	"encoding/hex"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/davinci-node/circuits/ballotproof"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func TestGenChainInputs(t *testing.T) {
	outDir := os.Getenv("CHAIN_OUT_DIR")
	if outDir == "" {
		t.Skip("set CHAIN_OUT_DIR to generate chained-mode inputs")
	}
	nBatches := envInt("CHAIN_BATCHES", 2)
	votersPerBatch := envInt("CHAIN_BATCH_SIZE", 2)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	election, err := NewElection(nBatches * votersPerBatch)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}

	// Chain config for the aggregator guest (all 32-byte fields LE hex).
	bLen := arbo.HashFunctionSha256.Len()
	le32 := func(bi *big.Int) string {
		return hex.EncodeToString(arbo.BigIntToBytes(bLen, bi))
	}
	rx, ry := election.EncKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	censusRoot, ok := election.Census.Root()
	if !ok {
		t.Fatal("census tree has no root")
	}
	cfg := map[string]any{
		"process_id":    le32(new(big.Int).SetBytes(election.ProcessID[:])),
		"ballot_mode":   le32(big.NewInt(0x01)),
		"enc_x":         le32(tx),
		"enc_y":         le32(ty),
		"census_origin": election.CensusOrigin,
		"census_root":   le32(censusRoot),
	}
	cfgJSON, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "config.json"), cfgJSON, 0o644); err != nil {
		t.Fatalf("write config.json: %v", err)
	}
	t.Logf("genesis root (LE): %s", election.OldRoot)

	genInputBin := findGenInputBin(t)
	roots := []string{election.OldRoot}

	for b := 0; b < nBatches; b++ {
		voters := election.Voters[b*votersPerBatch : (b+1)*votersPerBatch]
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, int64(42+100*b))
		if err != nil {
			t.Fatalf("batch %d: GenerateBallotBatch: %v", b, err)
		}

		tmpDir := t.TempDir()
		vkPath := filepath.Join(tmpDir, "verification_key.json")
		if err := os.WriteFile(vkPath, ballotproof.CircomVerificationKey, 0o600); err != nil {
			t.Fatalf("write vk: %v", err)
		}
		for i, res := range batch.Results {
			idx := i + 1
			if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("proof_%d.json", idx)), res.ProofJSON, 0o600); err != nil {
				t.Fatalf("write proof_%d: %v", idx, err)
			}
			pubBytes, err := json.Marshal(res.PublicInputs)
			if err != nil {
				t.Fatalf("marshal public_%d: %v", idx, err)
			}
			if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("public_%d.json", idx)), pubBytes, 0o600); err != nil {
				t.Fatalf("write public_%d: %v", idx, err)
			}
			if err := os.WriteFile(filepath.Join(tmpDir, fmt.Sprintf("sig_%d.json", idx)), res.SigJSON, 0o600); err != nil {
				t.Fatalf("write sig_%d: %v", idx, err)
			}
		}

		outBin := filepath.Join(tmpDir, "base.bin")
		cmd := exec.Command(genInputBin,
			"--proofs-dir", tmpDir,
			"--output", outBin,
			"--nproofs", strconv.Itoa(votersPerBatch))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("batch %d: gen-input: %v\n%s", b, err, out)
		}
		baseBin, err := os.ReadFile(outBin)
		if err != nil {
			t.Fatalf("read base bin: %v", err)
		}

		reencData, reencBallots, err := election.BuildReencBlock(batch.Results)
		if err != nil {
			t.Fatalf("batch %d: BuildReencBlock: %v", b, err)
		}
		stateData, _, err := election.BuildStateBlock(voters, batch.Results, reencBallots)
		if err != nil {
			t.Fatalf("batch %d: BuildStateBlock: %v", b, err)
		}
		stateBytes, err := davinci.EncodeStateBlock(stateData)
		if err != nil {
			t.Fatalf("batch %d: EncodeStateBlock: %v", b, err)
		}
		censusProofs, err := election.BuildCensusProofs(voters)
		if err != nil {
			t.Fatalf("batch %d: BuildCensusProofs: %v", b, err)
		}
		censusBytes, err := davinci.EncodeCensusBlock(censusProofs)
		if err != nil {
			t.Fatalf("batch %d: EncodeCensusBlock: %v", b, err)
		}
		reencBytes, err := davinci.EncodeReencBlock(reencData)
		if err != nil {
			t.Fatalf("batch %d: EncodeReencBlock: %v", b, err)
		}

		// Chained mode: no KZG block.
		var input []byte
		input = append(input, baseBin...)
		input = append(input, stateBytes...)
		input = append(input, censusBytes...)
		input = append(input, reencBytes...)

		// Frame with the u64 LE length prefix expected by read_input_slice,
		// matching the service's job input.bin format (cargo-zisk prove
		// consumes these files directly).
		framed := make([]byte, 8+len(input))
		binary.LittleEndian.PutUint64(framed[:8], uint64(len(input)))
		copy(framed[8:], input)
		inPath := filepath.Join(outDir, fmt.Sprintf("input_%d.bin", b))
		if err := os.WriteFile(inPath, framed, 0o644); err != nil {
			t.Fatalf("write %s: %v", inPath, err)
		}
		assertCircuitValid(t, input, fmt.Sprintf("chain batch %d", b))
		roots = append(roots, election.OldRoot)
		t.Logf("batch %d: %s  root %s -> %s", b, inPath, roots[b], roots[b+1])
	}

	rootsJSON, _ := json.MarshalIndent(roots, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "roots.json"), rootsJSON, 0o644); err != nil {
		t.Fatalf("write roots.json: %v", err)
	}
}
