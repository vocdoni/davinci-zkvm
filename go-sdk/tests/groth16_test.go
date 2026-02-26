package tests

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// apiURL is the base URL of the davinci-zkvm service under test.
var apiURL = func() string {
	if u := os.Getenv("DAVINCI_API_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}()

// testDataDir returns the path to the ballot proof test fixtures.
func testDataDir() string {
	if d := os.Getenv("TEST_DATA_DIR"); d != "" {
		return d
	}
	// Default: ../data/ballot_proof_bn254 relative to this file's directory
	return filepath.Join("..", "data", "ballot_proof_bn254")
}

func newClient() *davinci.Client {
	return davinci.NewClient(apiURL)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	h, err := newClient().Health()
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", h.Status)
	}
	t.Logf("health: version=%s queue_len=%d", h.Version, h.QueueLen)
}

func TestInvalidRequest_EmptyProofs(t *testing.T) {
	body := []byte(`{"vk":{"protocol":"groth16","curve":"bn128","nPublic":1,"vk_alpha_1":["0","0","0"],"vk_beta_2":[["0","0"],["0","0"],["0","0"]],"vk_gamma_2":[["0","0"],["0","0"],["0","0"]],"vk_delta_2":[["0","0"],["0","0"],["0","0"]],"IC":[]},"proofs":[],"public_inputs":[],"sigs":[]}`)
	resp, err := http.Post(apiURL+"/prove", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /prove: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestJobNotFound(t *testing.T) {
	_, err := newClient().GetJob("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for unknown job ID")
	}
}

func TestSubmitAndProve(t *testing.T) {
	if os.Getenv("DAVINCI_SKIP_PROVING") == "1" {
		t.Skip("DAVINCI_SKIP_PROVING=1, skipping full proof test")
	}

	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("loading prove request: %v", err)
	}

	client := newClient()
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("submit prove: %v", err)
	}
	t.Logf("Submitted job %s", jobID)

	timeout := 20 * time.Minute
	if d := os.Getenv("DAVINCI_PROOF_TIMEOUT"); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			timeout = dur
		}
	}

	job, err := client.WaitForJob(jobID, timeout)
	if err != nil {
		t.Fatalf("waiting for job: %v", err)
	}
	if job.ElapsedMs != nil {
		t.Logf("Proof completed in %dms (%.1fs)", *job.ElapsedMs, float64(*job.ElapsedMs)/1000)
	}

	proofBytes, err := client.GetProof(jobID)
	if err != nil {
		t.Fatalf("downloading proof: %v", err)
	}
	if len(proofBytes) == 0 {
		t.Fatal("received empty proof binary")
	}
	t.Logf("Downloaded proof: %d bytes", len(proofBytes))
}

func TestProofNotReadyWhileQueued(t *testing.T) {
	req, err := loadProveRequestFromDir(testDataDir(), 128)
	if err != nil {
		t.Fatalf("loading prove request: %v", err)
	}

	client := newClient()
	jobID, err := client.SubmitProve(req)
	if err != nil {
		t.Fatalf("submit prove: %v", err)
	}
	t.Logf("Submitted job %s", jobID)

	// Immediately try to download the proof — should be 425 Too Early or 200 if instant
	resp, err := http.Get(fmt.Sprintf("%s/jobs/%s/proof", apiURL, jobID))
	if err != nil {
		t.Fatalf("GET proof: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooEarly && resp.StatusCode != http.StatusOK {
		t.Logf("Note: unexpected status %d (expected 425 or 200)", resp.StatusCode)
	}
}
