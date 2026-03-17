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
	h, err := requireCompatibleService(t).Health()
	if err != nil {
		t.Fatalf("health check failed: %v", err)
	}
	if h.Status != "ok" {
		t.Fatalf("expected status=ok, got %q", h.Status)
	}
	t.Logf("health: version=%s zisk=%s queue_len=%d", h.Version, h.ZiskVersion, h.QueueLen)
}

func TestInvalidRequest_EmptyProofs(t *testing.T) {
	requireCompatibleService(t)
	body := []byte(`{"stark_proofs":[],"sigs":[]}`)
	resp, err := http.Post(apiURL+"/prove", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /prove: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 400 or 422, got %d", resp.StatusCode)
	}
}

func TestJobNotFound(t *testing.T) {
	_, err := requireCompatibleService(t).GetJob("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("expected error for unknown job ID")
	}
}

func TestServiceContractErrorsAreNotLegacy(t *testing.T) {
	requireCompatibleService(t)
	body := []byte(`{"state":{"voters_count":2,"overwritten_count":0,"process_id":"0x00","old_state_root":"0x00","new_state_root":"0x00","vote_id_smt":[],"ballot_smt":[],"process_smt":[],"ecgfp5_ballot_proofs":{"old_results_add":[],"old_results_sub":[],"voter_ballots":[],"overwritten_ballots":null}}}`)
	resp, err := http.Post(apiURL+"/prove", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("POST /prove: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected malformed state payload to fail with 400 or 422, got %d", resp.StatusCode)
	}
}
