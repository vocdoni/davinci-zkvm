package davinci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a davinci-zkvm HTTP API client.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// NewClient returns a new Client targeting the given base URL (e.g. "http://localhost:8080").
// Trailing slashes are stripped.
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Health calls GET /health and returns the response.
func (c *Client) Health() (*HealthResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/health")
	if err != nil {
		return nil, fmt.Errorf("GET /health: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /health: status %d", resp.StatusCode)
	}
	var h HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return nil, fmt.Errorf("decode /health: %w", err)
	}
	return &h, nil
}

// SubmitProve posts a ProveRequest to POST /prove and returns the job ID.
func (c *Client) SubmitProve(req *ProveRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/prove", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST /prove: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("POST /prove: status %d: %s", resp.StatusCode, respBody)
	}
	var result ProveResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode /prove response: %w", err)
	}
	return result.JobID, nil
}

// GetJob calls GET /jobs/{id} and returns the job status.
func (c *Client) GetJob(jobID string) (*JobResponse, error) {
	resp, err := c.httpClient.Get(c.baseURL + "/jobs/" + jobID)
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("job %s not found", jobID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s: status %d: %s", jobID, resp.StatusCode, body)
	}
	var job JobResponse
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("decode job response: %w", err)
	}
	return &job, nil
}

// WaitForJob polls GET /jobs/{id} until the job is done or failed, or the timeout elapses.
// It returns an error if the job failed or if the timeout was exceeded.
func (c *Client) WaitForJob(jobID string, timeout time.Duration) (*JobResponse, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job, err := c.GetJob(jobID)
		if err != nil {
			return nil, err
		}
		switch job.Status {
		case "done":
			return job, nil
		case "failed":
			errMsg := ""
			if job.Error != nil {
				errMsg = *job.Error
			}
			return job, fmt.Errorf("job %s failed: %s", jobID, errMsg)
		}
		time.Sleep(5 * time.Second)
	}
	return nil, fmt.Errorf("job %s did not complete within %v", jobID, timeout)
}

// FetchSnark downloads the SNARK for a completed job as a typed
// [PlonkSnark] ready to feed to the on-chain `ZiskVerifier.verifySnarkProof`
// contract.
func (c *Client) FetchSnark(jobID string) (*PlonkSnark, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/snark", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/snark: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/snark: status %d: %s", jobID, resp.StatusCode, body)
	}
	var p plonkSnarkJSON
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode snark response: %w", err)
	}
	return p.toPlonkSnark()
}

// SubmitFold posts a FoldRequest to POST /fold and returns the job ID.
// All referenced jobs must already be done; the service assembles the
// aggregator input from their on-disk proofs.
func (c *Client) SubmitFold(req *FoldRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/fold", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST /fold: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("POST /fold: status %d: %s", resp.StatusCode, respBody)
	}
	var result ProveResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode /fold response: %w", err)
	}
	return result.JobID, nil
}

// SubmitFinalize posts a FinalizeRequest to POST /finalize and returns the
// job ID. The referenced fold job must already be done; the resulting job
// produces the final PLONK SNARK.
func (c *Client) SubmitFinalize(req *FinalizeRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	resp, err := c.httpClient.Post(c.baseURL+"/finalize", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST /finalize: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("POST /finalize: status %d: %s", resp.StatusCode, respBody)
	}
	var result ProveResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode /finalize response: %w", err)
	}
	return result.JobID, nil
}

// FetchStarkInfo returns the program_vk / zisk_vk of a completed STARK job.
func (c *Client) FetchStarkInfo(jobID string) (*StarkInfo, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/stark", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/stark: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/stark: status %d: %s", jobID, resp.StatusCode, body)
	}
	var info StarkInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode stark response: %w", err)
	}
	return &info, nil
}

// FetchStarkProof downloads the raw vadcop-final STARK blob of a completed
// STARK job (debug / archival; folding happens server-side from job IDs).
func (c *Client) FetchStarkProof(jobID string) ([]byte, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/proof/stark", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/proof/stark: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/proof/stark: status %d: %s", jobID, resp.StatusCode, body)
	}
	return body, nil
}

// FetchStarkRaw downloads the raw bincode `proof.bin` of a completed STARK
// job (GET /jobs/{id}/snark/raw). This is the blob the aggregator guest's
// loader expects; ship it to another worker with [Client.ImportStark] to fold
// a scattered batch on a single fold worker.
func (c *Client) FetchStarkRaw(jobID string) ([]byte, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/snark/raw", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/snark/raw: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/snark/raw: status %d: %s", jobID, resp.StatusCode, body)
	}
	return body, nil
}

// ImportStark uploads a raw STARK `proof.bin` (POST /jobs/import) and returns
// the new local job ID registered as a completed BatchStark job on this
// worker. Use it to gather batch STARKs proved elsewhere onto a single fold
// worker before calling [Client.SubmitFold].
func (c *Client) ImportStark(proofBin []byte) (string, error) {
	resp, err := c.httpClient.Post(c.baseURL+"/jobs/import", "application/octet-stream", bytes.NewReader(proofBin))
	if err != nil {
		return "", fmt.Errorf("POST /jobs/import: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST /jobs/import: status %d: %s", resp.StatusCode, respBody)
	}
	var result ProveResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode /jobs/import response: %w", err)
	}
	return result.JobID, nil
}

// FetchPublics downloads the raw committed publics of a completed job
// (256 bytes: the guest's u32 output registers, little-endian).
func (c *Client) FetchPublics(jobID string) ([]byte, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/publics", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/publics: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/publics: status %d: %s", jobID, resp.StatusCode, body)
	}
	return body, nil
}

// FetchInputs downloads the raw `input.bin` blob the SNARK was generated
// over. Useful for audit, re-proving, or off-chain bookkeeping; not
// required for on-chain verification.
func (c *Client) FetchInputs(jobID string) ([]byte, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/inputs", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/inputs: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/inputs: status %d: %s", jobID, resp.StatusCode, body)
	}
	return body, nil
}
