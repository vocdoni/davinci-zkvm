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

// GetProof downloads the proof binary for a completed job.
// Returns the raw proof bytes.
func (c *Client) GetProof(jobID string) ([]byte, error) {
	resp, err := c.httpClient.Get(fmt.Sprintf("%s/jobs/%s/proof", c.baseURL, jobID))
	if err != nil {
		return nil, fmt.Errorf("GET /jobs/%s/proof: %w", jobID, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET /jobs/%s/proof: status %d: %s", jobID, resp.StatusCode, body)
	}
	return body, nil
}
