package integration

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func TestDeterministicBallotFields(t *testing.T) {
	got := deterministicBallotFields(42)
	want := [8]uint64{10, 2, 11, 3, 12, 4, 0, 0}
	if got != want {
		t.Fatalf("deterministicBallotFields(42) = %v, want %v", got, want)
	}
}

func requireWasmPkg(t *testing.T) string {
	t.Helper()
	root := findDavinciStarkRoot()
	if _, err := os.Stat(filepath.Join(root, "pkg", "davinci_stark.js")); err != nil {
		t.Skip("davinci-stark wasm package not built")
	}
	return root
}

func TestGenerateStarkKeypair(t *testing.T) {
	requireWasmPkg(t)
	pkHex, err := generateStarkKeypair([]byte("integration-test-stark-keypair-seed"))
	if err != nil {
		t.Fatalf("generateStarkKeypair: %v", err)
	}
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		t.Fatalf("decode pk hex: %v", err)
	}
	if len(pk) != 40 {
		t.Fatalf("public key length = %d, want 40", len(pk))
	}
}

func TestGenerateStarkBallotBatch(t *testing.T) {
	requireWasmPkg(t)
	election, err := NewElection(1)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	pkHex, err := generateStarkKeypair([]byte("integration-test-stark-enc-key"))
	if err != nil {
		t.Fatalf("generateStarkKeypair: %v", err)
	}
	batch, err := GenerateStarkBallotBatch(election.ProcessID, pkHex, election.Voters[:1], 42)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}
	if len(batch.Results) != 1 {
		t.Fatalf("results length = %d, want 1", len(batch.Results))
	}
	res := batch.Results[0]
	if res.VoteID == 0 {
		t.Fatalf("VoteID must be non-zero")
	}
	if len(res.ProofData) == 0 {
		t.Fatalf("proof data must be non-empty")
	}
	if res.Bundle.PublicValues.Weight() != 42 {
		t.Fatalf("weight = %d, want 42", res.Bundle.PublicValues.Weight())
	}
	if res.Bundle.PublicValues.VoteID != res.VoteID {
		t.Fatalf("bundle voteID = %d, result voteID = %d", res.Bundle.PublicValues.VoteID, res.VoteID)
	}
	if got := res.Bundle.PublicValues.ProcessID(); got == [4]uint64{} {
		t.Fatalf("process id must not be zero")
	}
}

func TestGenerateStarkBallotBatchUsesConfiguredConcurrencyAndKeepsOrder(t *testing.T) {
	election, err := NewElection(8)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	pkHex := stringsRepeatHex("11", 40)

	t.Setenv("DAVINCI_STARK_MAX_CONCURRENCY", "3")

	originalRunner := starkNodeRunner
	defer func() { starkNodeRunner = originalRunner }()

	var inFlight int32
	var maxInFlight int32
	var seq uint64
	starkNodeRunner = func(payload map[string]any) (map[string]any, error) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			prev := atomic.LoadInt32(&maxInFlight)
			if cur <= prev || atomic.CompareAndSwapInt32(&maxInFlight, prev, cur) {
				break
			}
		}
		defer atomic.AddInt32(&inFlight, -1)

		time.Sleep(20 * time.Millisecond)

		addressHex := payload["address_hex"].(string)
		processIDHex := payload["process_id_hex"].(string)
		weightHex := payload["weight_hex"].(string)
		voteID := atomic.AddUint64(&seq, 1)
		raw := syntheticStarkProofBlobForTest(processIDHex, addressHex, weightHex, voteID)
		return map[string]any{"proof_data_hex": hex.EncodeToString(raw)}, nil
	}

	batch, err := GenerateStarkBallotBatch(election.ProcessID, pkHex, election.Voters, 100)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}
	if len(batch.Results) != len(election.Voters) {
		t.Fatalf("results length = %d, want %d", len(batch.Results), len(election.Voters))
	}
	if got := atomic.LoadInt32(&maxInFlight); got < 2 || got > 3 {
		t.Fatalf("max in-flight proofs = %d, want between 2 and 3", got)
	}
	for i, voter := range election.Voters {
		wantAddr := encodeLEHexToLimbs4ForTest(addressToLEHex(voter.AddressBytes))
		if batch.Results[i].Bundle.PublicValues.Address != wantAddr {
			t.Fatalf("result %d address limbs = %v, want %v", i, batch.Results[i].Bundle.PublicValues.Address, wantAddr)
		}
	}
}

func TestGenerateStarkBallotBatchCreatesFullConfiguredBatch(t *testing.T) {
	election, err := NewElection(128)
	if err != nil {
		t.Fatalf("NewElection: %v", err)
	}
	pkHex := stringsRepeatHex("22", 40)

	originalRunner := starkNodeRunner
	defer func() { starkNodeRunner = originalRunner }()

	var calls int32
	starkNodeRunner = func(payload map[string]any) (map[string]any, error) {
		atomic.AddInt32(&calls, 1)
		addressHex := payload["address_hex"].(string)
		processIDHex := payload["process_id_hex"].(string)
		weightHex := payload["weight_hex"].(string)
		raw := syntheticStarkProofBlobForTest(processIDHex, addressHex, weightHex, 7)
		return map[string]any{"proof_data_hex": hex.EncodeToString(raw)}, nil
	}

	batch, err := GenerateStarkBallotBatch(election.ProcessID, pkHex, election.Voters, 10)
	if err != nil {
		t.Fatalf("GenerateStarkBallotBatch: %v", err)
	}
	if len(batch.Results) != 128 || len(batch.StarkProofs) != 128 || len(batch.Sigs) != 128 {
		t.Fatalf("batch lengths = (%d,%d,%d), want (128,128,128)", len(batch.Results), len(batch.StarkProofs), len(batch.Sigs))
	}
	if got := atomic.LoadInt32(&calls); got != 128 {
		t.Fatalf("proof invocations = %d, want 128", got)
	}
}

func syntheticStarkProofBlobForTest(processIDHex, addressHex, weightHex string, voteID uint64) []byte {
	var pv davinci.StarkPublicValues
	pv.Address = encodeLEHexToLimbs4ForTest(addressHex)
	processID := encodeLEHexToLimbs4ForTest(processIDHex)
	copy(pv.InputsPreimage[0:4], processID[:])
	pv.InputsPreimage[113] = binary.LittleEndian.Uint64(mustDecodeHexForTest(weightHex)[:8])
	pv.VoteID = voteID
	proofBytes := []byte{0xaa, 0xbb, 0xcc}
	out := make([]byte, 4+len(proofBytes)+davinci.StarkPublicValueBytes)
	binary.LittleEndian.PutUint32(out[:4], uint32(len(proofBytes)))
	copy(out[4:], proofBytes)
	copy(out[4+len(proofBytes):], pv.Encode())
	return out
}

func encodeLEHexToLimbs4ForTest(hexLE string) [4]uint64 {
	raw := mustDecodeHexForTest(hexLE)
	var out [4]uint64
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(raw[i*8 : (i+1)*8])
	}
	return out
}

func mustDecodeHexForTest(s string) []byte {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return raw
}

func stringsRepeatHex(pair string, n int) string {
	out := make([]byte, 0, n*2)
	for i := 0; i < n; i++ {
		out = append(out, pair[0], pair[1])
	}
	return string(out)
}
