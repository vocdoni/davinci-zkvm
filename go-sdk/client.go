package davinci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	return NewClientWithHTTP(baseURL, &http.Client{Timeout: 30 * time.Second})
}

// NewClientWithHTTP returns a Client using the given http.Client, for callers
// that need a custom transport, TLS config, or timeout.
func NewClientWithHTTP(baseURL string, hc *http.Client) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: hc,
	}
}

// maxResponseBytes caps how much of a response body is read into memory.
// The largest legitimate payloads are raw STARK blobs (a few hundred MB at
// most); the cap only guards against a misbehaving endpoint streaming
// unbounded data.
const maxResponseBytes = 1 << 30

// readBody reads the response body up to maxResponseBytes.
func readBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// maxErrBody caps how much of an error response body lands in error strings.
const maxErrBody = 4 << 10

// errBody truncates b for inclusion in an error message.
func errBody(b []byte) string {
	if len(b) > maxErrBody {
		return string(b[:maxErrBody]) + "...(truncated)"
	}
	return string(b)
}

// jobPath builds a /jobs/{id}{suffix} path with the job ID escaped.
func jobPath(jobID, suffix string) string {
	return "/jobs/" + url.PathEscape(jobID) + suffix
}

// get performs a GET against path and returns the response body, requiring
// HTTP 200. The returned error already carries the path and status, so callers
// surface it directly without re-wrapping.
func (c *Client) get(path string) ([]byte, error) {
	resp, err := c.httpClient.Get(c.baseURL + path)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("GET %s: read body: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, errBody(body))
	}
	return body, nil
}

// Health calls GET /health and returns the response.
func (c *Client) Health() (*HealthResponse, error) {
	body, err := c.get("/health")
	if err != nil {
		return nil, err
	}
	var h HealthResponse
	if err := json.Unmarshal(body, &h); err != nil {
		return nil, fmt.Errorf("decode /health: %w", err)
	}
	return &h, nil
}

// postForJobID posts body to path, requires wantStatus, and returns the
// job ID from the {job_id} response.
func (c *Client) postForJobID(path, contentType string, body []byte, wantStatus int) (string, error) {
	resp, err := c.httpClient.Post(c.baseURL+path, contentType, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := readBody(resp)
	if err != nil {
		return "", fmt.Errorf("POST %s: read body: %w", path, err)
	}
	if resp.StatusCode != wantStatus {
		return "", fmt.Errorf("POST %s: status %d: %s", path, resp.StatusCode, errBody(respBody))
	}
	var result ProveResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode %s response: %w", path, err)
	}
	return result.JobID, nil
}

// SubmitProve posts a ProveRequest to POST /prove and returns the job ID.
func (c *Client) SubmitProve(req *ProveRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	return c.postForJobID("/prove", "application/json", body, http.StatusAccepted)
}

// GetJob calls GET /jobs/{id} and returns the job status.
func (c *Client) GetJob(jobID string) (*JobResponse, error) {
	body, err := c.get(jobPath(jobID, ""))
	if err != nil {
		return nil, err
	}
	var job JobResponse
	if err := json.Unmarshal(body, &job); err != nil {
		return nil, fmt.Errorf("decode job response: %w", err)
	}
	return &job, nil
}

// maxPollErrs is how many consecutive poll failures are tolerated before a
// long-running wait gives up. A single transient network error should not
// abort a multi-minute proving job.
const maxPollErrs = 5

// WaitForJob polls GET /jobs/{id} until the job is done or failed, or the timeout elapses.
// It returns an error if the job failed or if the timeout was exceeded.
// Transient poll errors are tolerated up to maxPollErrs consecutive failures.
func (c *Client) WaitForJob(jobID string, timeout time.Duration) (*JobResponse, error) {
	deadline := time.Now().Add(timeout)
	pollErrs := 0
	for time.Now().Before(deadline) {
		job, err := c.GetJob(jobID)
		if err != nil {
			pollErrs++
			if pollErrs >= maxPollErrs {
				return nil, fmt.Errorf("poll job %s: %w", jobID, err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		pollErrs = 0
		switch job.Status {
		case JobStatusDone:
			return job, nil
		case JobStatusFailed:
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
	body, err := c.get(jobPath(jobID, "/snark"))
	if err != nil {
		return nil, err
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
	return c.postForJobID("/fold", "application/json", body, http.StatusAccepted)
}

// SubmitFinalize posts a FinalizeRequest to POST /finalize and returns the
// job ID. The referenced fold job must already be done; the resulting job
// produces the final PLONK SNARK.
func (c *Client) SubmitFinalize(req *FinalizeRequest) (string, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}
	return c.postForJobID("/finalize", "application/json", body, http.StatusAccepted)
}

// FetchStarkInfo returns the program_vk / zisk_vk of a completed STARK job.
func (c *Client) FetchStarkInfo(jobID string) (*StarkInfo, error) {
	body, err := c.get(jobPath(jobID, "/stark"))
	if err != nil {
		return nil, err
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
	return c.get(jobPath(jobID, "/proof/stark"))
}

// FetchStarkRaw downloads the raw bincode `proof.bin` of a completed STARK
// job (GET /jobs/{id}/snark/raw). This is the blob the aggregator guest's
// loader expects; ship it to another worker with [Client.ImportStark] to fold
// a scattered batch on a single fold worker.
func (c *Client) FetchStarkRaw(jobID string) ([]byte, error) {
	return c.get(jobPath(jobID, "/snark/raw"))
}

// ImportStark uploads a raw STARK `proof.bin` (POST /jobs/import) and returns
// the new local job ID registered as a completed BatchStark job on this
// worker. Use it to gather batch STARKs proved elsewhere onto a single fold
// worker before calling [Client.SubmitFold].
func (c *Client) ImportStark(proofBin []byte) (string, error) {
	return c.postForJobID("/jobs/import", "application/octet-stream", proofBin, http.StatusOK)
}

// ImportKind selects the job kind of an imported STARK.
type ImportKind string

// Import kinds accepted by POST /jobs/import.
const (
	// ImportBatch registers a vote batch STARK, usable in FoldRequest.BatchJobs.
	ImportBatch ImportKind = "batch"
	// ImportFold registers a fold STARK, usable as FoldRequest.PrevFoldJob or
	// FinalizeRequest.FoldJob. It moves a fold chain to another worker.
	ImportFold ImportKind = "fold"
)

// ImportStarkAs is [Client.ImportStark] with an explicit job kind
// (POST /jobs/import?kind=...). The aggregator re-verifies an imported fold
// proof in-guest against the bound fold vk, as it does for imported batches.
func (c *Client) ImportStarkAs(proofBin []byte, kind ImportKind) (string, error) {
	path := "/jobs/import?kind=" + url.QueryEscape(string(kind))
	return c.postForJobID(path, "application/octet-stream", proofBin, http.StatusOK)
}

// FetchPublics downloads the raw committed publics of a completed job
// (256 bytes: the guest's u32 output registers, little-endian).
func (c *Client) FetchPublics(jobID string) ([]byte, error) {
	return c.get(jobPath(jobID, "/publics"))
}

// FetchInputs downloads the raw `input.bin` blob the SNARK was generated
// over. Useful for audit, re-proving, or off-chain bookkeeping; not
// required for on-chain verification.
func (c *Client) FetchInputs(jobID string) ([]byte, error) {
	return c.get(jobPath(jobID, "/inputs"))
}
