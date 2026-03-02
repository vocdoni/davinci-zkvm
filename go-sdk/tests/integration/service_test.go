// service_test.go contains API service tests that submit jobs to a running
// davinci-zkvm HTTP service. All tests in this file require the service to be
// reachable at apiURL (default: http://localhost:8080).
//
// Start the service with: docker compose up -d --build
package integration

import (
	"net/http"
	"strings"
	"testing"
)

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
