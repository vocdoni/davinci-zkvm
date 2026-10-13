// emusteps_test.go measures the vote-batch guest on ziskemu. It writes the
// steady batch of TestPlonkBenchmark (size new votes plus size silent
// refreshes, from the cached ballots) as a guest input and runs
// `ziskemu -X --save-stats` on it. Gated by EMU_STEPS_OUT=<dir>; honours
// BENCH_SIZES (default 256,512) and BALLOT_NUM_FIELDS. Needs ziskemu and
// gen-input, no prover.
package integration

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
)

func TestEmuSteps(t *testing.T) {
	out := os.Getenv("EMU_STEPS_OUT")
	if out == "" {
		t.Skip("set EMU_STEPS_OUT to measure emulator steps")
	}
	ziskemu, err := exec.LookPath("ziskemu")
	if err != nil {
		t.Skip("ziskemu not in PATH")
	}
	elf := os.Getenv("CIRCUIT_ELF_PATH")
	if elf == "" {
		elf = "../../../circuit/elf/circuit.elf"
	}
	if os.Getenv("DAVINCI_TEST_ELECTION_SEED") == "" {
		t.Setenv("DAVINCI_TEST_ELECTION_SEED", "plonk-bench")
	}
	sizes := []int{256, 512}
	if v := os.Getenv("BENCH_SIZES"); v != "" {
		sizes = nil
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n <= 0 {
				t.Fatalf("bad BENCH_SIZES entry %q", s)
			}
			sizes = append(sizes, n)
		}
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, size := range sizes {
		// The first batch only moves the harness state; the steady one is run.
		election, err := NewElection(2 * size)
		if err != nil {
			t.Fatalf("NewElection: %v", err)
		}
		first, err := CachedBallotBatch(election, election.Voters[:size], 42)
		if err != nil {
			t.Fatalf("CachedBallotBatch: %v", err)
		}
		_, reenc1, err := election.BuildReencBlock(election.OldRoot, first.Results)
		if err != nil {
			t.Fatalf("BuildReencBlock: %v", err)
		}
		if _, _, err := election.BuildStateBlock(election.Voters[:size], first.Results, reenc1); err != nil {
			t.Fatalf("BuildStateBlock: %v", err)
		}
		voters := election.Voters[size : 2*size]
		batch, err := CachedBallotBatch(election, voters, 43)
		if err != nil {
			t.Fatalf("CachedBallotBatch: %v", err)
		}
		input := steadyInput(t, election, voters, batch.Results)

		name := filepath.Join(out, fmt.Sprintf("steady-%d-nf%d", size, election.NumFields))
		var framed []byte
		framed = binary.LittleEndian.AppendUint64(framed, uint64(len(input)))
		framed = append(framed, input...)
		framed = append(framed, make([]byte, (8-len(input)%8)%8)...)
		if err := os.WriteFile(name+".bin", framed, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(ziskemu, "-e", elf, "-i", name+".bin", "-o", name+".out",
			"-X", "--save-stats", name+".stats")
		report, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ziskemu: %v\n%s", err, report)
		}
		if err := os.WriteFile(name+".txt", report, 0o644); err != nil {
			t.Fatal(err)
		}
		regs, err := os.ReadFile(name + ".out")
		if err != nil {
			t.Fatal(err)
		}
		if ok := binary.LittleEndian.Uint32(regs[0:]); ok != 1 {
			t.Fatalf("size %d: guest rejected the batch: fail_mask %#x", size, binary.LittleEndian.Uint32(regs[4:]))
		}
		t.Logf("size %d nf %d: %d blobs, report in %s.txt", size, election.NumFields,
			binary.LittleEndian.Uint32(regs[4*davinci.OutputNBlobs:]), name)
	}
}

// steadyInput assembles the guest input of one batch the way the cheat
// harness does: gen-input's proof section, then STATETX, CENSUS, REENCBLK
// and KZGBLK.
func steadyInput(t *testing.T, e *Election, voters []*Voter, results []*BallotResult) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "verification_key.json"), ballotproof.CircomVerificationKey, 0o600); err != nil {
		t.Fatal(err)
	}
	for i, res := range results {
		pub, err := json.Marshal(res.PublicInputs)
		if err != nil {
			t.Fatal(err)
		}
		for name, b := range map[string][]byte{"proof": res.ProofJSON, "public": pub, "sig": res.SigJSON} {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s_%d.json", name, i+1)), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	bin := filepath.Join(dir, "input.bin")
	cmd := exec.Command(findGenInputBin(t), "--proofs-dir", dir, "--output", bin, "--nproofs", strconv.Itoa(len(results)))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("gen-input: %v\n%s", err, out)
	}
	base, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}

	oldRoot := e.OldRoot
	reenc, reencBallots, err := e.BuildReencBlock(oldRoot, results)
	if err != nil {
		t.Fatalf("BuildReencBlock: %v", err)
	}
	state, _, err := e.BuildStateBlock(voters, results, reencBallots)
	if err != nil {
		t.Fatalf("BuildStateBlock: %v", err)
	}
	kzg, _, err := e.BuildKZGBlock(oldRoot)
	if err != nil {
		t.Fatalf("BuildKZGBlock: %v", err)
	}
	stateBin, err := davinci.EncodeStateBlock(state)
	if err != nil {
		t.Fatal(err)
	}
	reencBin, err := davinci.EncodeReencBlock(reenc)
	if err != nil {
		t.Fatal(err)
	}
	kzgBin, err := encodeKZGRequest(kzg)
	if err != nil {
		t.Fatal(err)
	}
	input := append(base, stateBin...)
	input = append(input, eligibilityBlock(t, e, voters)...)
	input = append(input, reencBin...)
	return append(input, kzgBin...)
}
