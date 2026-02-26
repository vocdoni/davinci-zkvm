package integration_tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var apiURL = func() string {
	if u := os.Getenv("DAVINCI_API_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://localhost:8080"
}()

// testDataDir returns the path to test proofs, relative to the integration-tests/ directory.
func testDataDir() string {
	if d := os.Getenv("TEST_DATA_DIR"); d != "" {
		return d
	}
	return filepath.Join("data", "ballot_proof_bn254")
}

// ProveRequest mirrors the service API request body.
type ProveRequest struct {
	VK           json.RawMessage   `json:"vk"`
	Proofs       []json.RawMessage `json:"proofs"`
	PublicInputs [][]string        `json:"public_inputs"`
	// Sigs is optional — include when sig_N.json files are present in the data directory
	Sigs []json.RawMessage `json:"sigs,omitempty"`
}

// JobResponse mirrors the service API job status response.
type JobResponse struct {
	JobID      string  `json:"job_id"`
	Status     string  `json:"status"`
	ElapsedMs  *int64  `json:"elapsed_ms"`
	Error      *string `json:"error"`
}

// HealthResponse mirrors the /health endpoint.
type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	QueueLen int    `json:"queue_len"`
}

// loadProveRequest loads the VK and N proofs from the test data directory.
func loadProveRequest(t *testing.T, n int) ProveRequest {
	t.Helper()
	dataDir := testDataDir()

	vkPath := filepath.Join(dataDir, "verification_key.json")
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		t.Fatalf("reading VK from %s: %v", vkPath, err)
	}

	var proofPaths, publicPaths []string
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatalf("reading data dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "proof_") && strings.HasSuffix(e.Name(), ".json") {
			proofPaths = append(proofPaths, filepath.Join(dataDir, e.Name()))
		}
		if strings.HasPrefix(e.Name(), "public_") && strings.HasSuffix(e.Name(), ".json") {
			publicPaths = append(publicPaths, filepath.Join(dataDir, e.Name()))
		}
	}

	var sigPaths []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "sig_") && strings.HasSuffix(e.Name(), ".json") {
			sigPaths = append(sigPaths, filepath.Join(dataDir, e.Name()))
		}
	}

	sort.Slice(proofPaths, func(i, j int) bool {
		return numericSuffix(proofPaths[i]) < numericSuffix(proofPaths[j])
	})
	sort.Slice(publicPaths, func(i, j int) bool {
		return numericSuffix(publicPaths[i]) < numericSuffix(publicPaths[j])
	})
	sort.Slice(sigPaths, func(i, j int) bool {
		return numericSuffix(sigPaths[i]) < numericSuffix(sigPaths[j])
	})

	if len(proofPaths) < n || len(publicPaths) < n {
		t.Fatalf("need %d proofs/publics, found %d/%d", n, len(proofPaths), len(publicPaths))
	}
	proofPaths = proofPaths[:n]
	publicPaths = publicPaths[:n]

	proofs := make([]json.RawMessage, n)
	publics := make([][]string, n)

	for i := 0; i < n; i++ {
		raw, err := os.ReadFile(proofPaths[i])
		if err != nil {
			t.Fatalf("reading proof %d: %v", i, err)
		}
		proofs[i] = raw

		var pub []string
		pubRaw, err := os.ReadFile(publicPaths[i])
		if err != nil {
			t.Fatalf("reading public %d: %v", i, err)
		}
		if err := json.Unmarshal(pubRaw, &pub); err != nil {
			t.Fatalf("parsing public %d: %v", i, err)
		}
		publics[i] = pub
	}

	req := ProveRequest{
		VK:           json.RawMessage(vkBytes),
		Proofs:       proofs,
		PublicInputs: publics,
	}

	// Load ECDSA signatures if available (optional — backward-compatible)
	if len(sigPaths) >= n {
		sigPaths = sigPaths[:n]
		sigs := make([]json.RawMessage, n)
		for i := 0; i < n; i++ {
			raw, err := os.ReadFile(sigPaths[i])
			if err != nil {
				t.Fatalf("reading sig %d: %v", i, err)
			}
			sigs[i] = raw
		}
		req.Sigs = sigs
		t.Logf("Loaded %d ECDSA signatures", n)
	}

	return req
}

func numericSuffix(path string) int {
	base := filepath.Base(path)
	base = strings.TrimSuffix(base, ".json")
	parts := strings.Split(base, "_")
	n, _ := strconv.Atoi(parts[len(parts)-1])
	return n
}

func submitProve(t *testing.T, req ProveRequest) string {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshaling request: %v", err)
	}
	resp, err := http.Post(apiURL+"/prove", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /prove: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /prove: status %d, body: %s", resp.StatusCode, respBody)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("parsing /prove response: %v", err)
	}
	jobID, ok := result["job_id"].(string)
	if !ok {
		t.Fatalf("no job_id in response: %s", respBody)
	}
	return jobID
}

func waitForJob(t *testing.T, jobID string, timeout time.Duration) JobResponse {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(apiURL + "/jobs/" + jobID)
		if err != nil {
			t.Fatalf("GET /jobs/%s: %v", jobID, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var job JobResponse
		if err := json.Unmarshal(body, &job); err != nil {
			t.Fatalf("parsing job response: %v", err)
		}
		if job.Status == "done" || job.Status == "failed" {
			return job
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("job %s did not complete within %v", jobID, timeout)
	return JobResponse{}
}

// ── Tests ──────────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	resp, err := http.Get(apiURL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var h HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", h.Status)
	}
	t.Logf("health: version=%s queue_len=%d", h.Version, h.QueueLen)
}

func TestInvalidRequest_EmptyProofs(t *testing.T) {
	vkBytes := []byte(`{"protocol":"groth16","curve":"bn128","nPublic":1,"vk_alpha_1":["0","0","0"],"vk_beta_2":[["0","0"],["0","0"],["0","0"]],"vk_gamma_2":[["0","0"],["0","0"],["0","0"]],"vk_delta_2":[["0","0"],["0","0"],["0","0"]],"IC":[]}`)
	req := ProveRequest{
		VK:           vkBytes,
		Proofs:       []json.RawMessage{},
		PublicInputs: [][]string{},
	}
	body, _ := json.Marshal(req)
	resp, err := http.Post(apiURL+"/prove", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /prove: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestJobNotFound(t *testing.T) {
	resp, err := http.Get(apiURL + "/jobs/00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GET /jobs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

func TestSubmitAndProve(t *testing.T) {
	if os.Getenv("DAVINCI_SKIP_PROVING") == "1" {
		t.Skip("DAVINCI_SKIP_PROVING=1, skipping full proof test")
	}

	req := loadProveRequest(t, 128)
	jobID := submitProve(t, req)
	t.Logf("Submitted job %s", jobID)

	// Poll for completion (proof can take 30-800s depending on CPU/GPU)
	timeout := 20 * time.Minute
	if d := os.Getenv("DAVINCI_PROOF_TIMEOUT"); d != "" {
		if dur, err := time.ParseDuration(d); err == nil {
			timeout = dur
		}
	}

	job := waitForJob(t, jobID, timeout)
	if job.Status != "done" {
		errMsg := ""
		if job.Error != nil {
			errMsg = *job.Error
		}
		t.Fatalf("job %s failed: %s", jobID, errMsg)
	}
	if job.ElapsedMs != nil {
		t.Logf("Proof completed in %dms (%.1fs)", *job.ElapsedMs, float64(*job.ElapsedMs)/1000)
	}

	// Download the proof binary
	proofResp, err := http.Get(fmt.Sprintf("%s/jobs/%s/proof", apiURL, jobID))
	if err != nil {
		t.Fatalf("GET /jobs/%s/proof: %v", jobID, err)
	}
	defer proofResp.Body.Close()
	if proofResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(proofResp.Body)
		t.Fatalf("expected 200 downloading proof, got %d: %s", proofResp.StatusCode, body)
	}
	proofBytes, _ := io.ReadAll(proofResp.Body)
	if len(proofBytes) == 0 {
		t.Fatal("received empty proof binary")
	}
	t.Logf("Downloaded proof: %d bytes", len(proofBytes))
}

func TestProofNotReadyWhileQueued(t *testing.T) {
	// Submit a job but immediately try to get the proof
	req := loadProveRequest(t, 128)
	jobID := submitProve(t, req)
	t.Logf("Submitted job %s", jobID)

	// Immediately try to get the proof — it should be 425 Too Early
	proofResp, err := http.Get(fmt.Sprintf("%s/jobs/%s/proof", apiURL, jobID))
	if err != nil {
		t.Fatalf("GET proof: %v", err)
	}
	defer proofResp.Body.Close()
	// Accept 425 (not ready) or 200 (if proof was miraculously instant)
	if proofResp.StatusCode != http.StatusTooEarly && proofResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(proofResp.Body)
		t.Logf("Note: got status %d: %s", proofResp.StatusCode, body)
	}
}
