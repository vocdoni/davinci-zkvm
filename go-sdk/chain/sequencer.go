// sequencer.go orchestrates a chained-mode election against the
// davinci-zkvm service: STARK batch proves, fold cadence, and the final
// finalize + PLONK step with the external vk-binding checks.
package chain

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// Sequencer drives one election chain. It owns the State, tracks the
// batch jobs not yet folded, and folds every FoldEvery batches. Not safe
// for concurrent use.
type Sequencer struct {
	// FoldEvery is the fold cadence: a fold is submitted automatically
	// once this many batch proofs are pending. <= 0 disables automatic
	// folding (call Fold explicitly).
	FoldEvery int
	// Timeout bounds each WaitForJob call.
	Timeout time.Duration

	client   *davinci.Client
	state    *State
	chainCfg davinci.ChainConfig

	aggVK   string // aggregator program_vk, learned on first fold
	batchVK string // vote-batch program_vk, learned on first batch

	pending   []string // completed batch jobs not yet folded
	lastFold  string   // last completed fold job, "" before genesis
	foldCount uint32   // completed fold steps (excluding bootstrap)
}

// FinalResult is the outcome of Finalize: the verified chain digest, the
// on-chain-ready PLONK and the plaintext results.
type FinalResult struct {
	JobID   string
	Digest  *Digest
	Snark   *davinci.PlonkSnark
	Results []uint64
}

// NewSequencer creates the genesis state for cfg and a sequencer bound
// to client.
func NewSequencer(client *davinci.Client, cfg Config, foldEvery int, timeout time.Duration) (*Sequencer, error) {
	state, err := NewState(cfg)
	if err != nil {
		return nil, err
	}
	return &Sequencer{
		FoldEvery: foldEvery,
		Timeout:   timeout,
		client:    client,
		state:     state,
		chainCfg:  *state.ChainConfig(),
	}, nil
}

// State returns the sequencer's process state.
func (s *Sequencer) State() *State { return s.state }

// AggregatorVK returns the aggregator program_vk ("" until the first fold).
func (s *Sequencer) AggregatorVK() string { return s.aggVK }

// BatchVK returns the vote-batch program_vk ("" until the first batch).
func (s *Sequencer) BatchVK() string { return s.batchVK }

// LastFoldJob returns the most recent completed fold job ID.
func (s *Sequencer) LastFoldJob() string { return s.lastFold }

// FoldCount returns the number of completed fold steps. The digest's
// StepCount counts folds, not batches: one fold may cover several.
func (s *Sequencer) FoldCount() uint32 { return s.foldCount }

// PendingBatches returns the completed batch jobs not yet folded.
func (s *Sequencer) PendingBatches() []string { return append([]string(nil), s.pending...) }

// ProveBatch applies votes to the state, fills the request's state and
// re-encryption blocks, proves the batch as a STARK and waits for it.
// req must already carry the ballots, ballot proofs and census material;
// its State, Reencryption and Output fields are overwritten. When the
// fold cadence is reached, a fold is submitted before returning.
func (s *Sequencer) ProveBatch(votes []Vote, req *davinci.ProveRequest) (string, error) {
	stateBlock, reencBlock, err := s.state.ApplyBatch(votes)
	if err != nil {
		return "", fmt.Errorf("ApplyBatch: %w", err)
	}
	req.State = stateBlock
	req.Reencryption = reencBlock
	req.KZG = nil
	req.Output = "stark"

	jobID, err := s.runJob("batch", func() (string, error) { return s.client.SubmitProve(req) })
	if err != nil {
		return "", err
	}
	if s.batchVK == "" {
		info, err := s.client.FetchStarkInfo(jobID)
		if err != nil {
			return "", fmt.Errorf("FetchStarkInfo %s: %w", jobID, err)
		}
		s.batchVK = info.ProgramVK
	}
	s.pending = append(s.pending, jobID)

	if s.FoldEvery > 0 && len(s.pending) >= s.FoldEvery {
		if _, err := s.Fold(); err != nil {
			return jobID, err
		}
	}
	return jobID, nil
}

// Fold folds all pending batch proofs into the chain. The first call
// runs a bootstrap fold to learn the aggregator program_vk (the guest
// cannot know its own vk), then the genesis fold bound to it. Returns
// the new fold job ID, or "" if nothing was pending.
func (s *Sequencer) Fold() (string, error) {
	if len(s.pending) == 0 {
		return "", nil
	}

	if s.aggVK == "" {
		bootID, err := s.foldJob(&davinci.FoldRequest{
			Config:    s.chainCfg,
			BatchJobs: s.pending[:1],
		})
		if err != nil {
			return "", fmt.Errorf("bootstrap fold: %w", err)
		}
		info, err := s.client.FetchStarkInfo(bootID)
		if err != nil {
			return "", fmt.Errorf("bootstrap fold info: %w", err)
		}
		s.aggVK = info.ProgramVK
	}

	req := &davinci.FoldRequest{
		Config:    s.chainCfg,
		BatchJobs: s.pending,
	}
	if s.lastFold == "" {
		// Genesis fold: bind the learned aggregator vk explicitly.
		req.FoldVK = s.aggVK
	} else {
		req.PrevFoldJob = s.lastFold
	}
	foldID, err := s.foldJob(req)
	if err != nil {
		return "", err
	}
	s.lastFold = foldID
	s.foldCount++
	s.pending = nil
	return foldID, nil
}

func (s *Sequencer) foldJob(req *davinci.FoldRequest) (string, error) {
	return s.runJob("fold", func() (string, error) { return s.client.SubmitFold(req) })
}

// maxJobAttempts bounds how many times a failed job is resubmitted with
// the same input. ZisK occasionally flakes at the recursion stage even
// after the service's own in-place retries; the input is identical, so
// resubmitting is always safe.
const maxJobAttempts = 3

// runJob submits a job and waits for it, resubmitting on failure up to
// maxJobAttempts times.
func (s *Sequencer) runJob(kind string, submit func() (string, error)) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= maxJobAttempts; attempt++ {
		id, err := submit()
		if err != nil {
			return "", fmt.Errorf("submit %s: %w", kind, err)
		}
		if _, err := s.client.WaitForJob(id, s.Timeout); err == nil {
			return id, nil
		} else {
			lastErr = fmt.Errorf("%s job %s (attempt %d/%d): %w", kind, id, attempt, maxJobAttempts, err)
		}
	}
	return "", lastErr
}

// Digest fetches and parses the digest of a fold or finalize job.
func (s *Sequencer) Digest(jobID string) (*Digest, error) {
	publics, err := s.client.FetchPublics(jobID)
	if err != nil {
		return nil, fmt.Errorf("FetchPublics %s: %w", jobID, err)
	}
	return ParseDigest(publics)
}

// Finalize folds any pending batches, decrypts the accumulators with
// privKey, proves the results in-guest and wraps the chain in the final
// PLONK. It verifies the returned digest against the local state and
// performs the external vk-binding checks before returning.
func (s *Sequencer) Finalize(privKey *big.Int) (*FinalResult, error) {
	if _, err := s.Fold(); err != nil {
		return nil, err
	}
	if s.lastFold == "" {
		return nil, fmt.Errorf("nothing to finalize: no fold in the chain")
	}

	payload, results, err := s.state.ResultsPayload(privKey)
	if err != nil {
		return nil, fmt.Errorf("ResultsPayload: %w", err)
	}
	finID, err := s.runJob("finalize", func() (string, error) {
		return s.client.SubmitFinalize(&davinci.FinalizeRequest{
			Config:  s.chainCfg,
			FoldJob: s.lastFold,
			FoldVK:  s.aggVK,
			Results: *payload,
		})
	})
	if err != nil {
		return nil, err
	}

	digest, err := s.Digest(finID)
	if err != nil {
		return nil, err
	}
	snark, err := s.client.FetchSnark(finID)
	if err != nil {
		return nil, fmt.Errorf("FetchSnark %s: %w", finID, err)
	}

	// Circuit-release anchor: verify the service-learned VKs match the
	// pinned CircuitRelease. Without this, a malicious service can substitute
	// backdoored circuit ELFs (new VKs) and the sequencer will accept them as
	// the baseline. The constants must be refreshed after every ELF rebuild.
	if CircuitRelease.IsSet() {
		if err := CircuitRelease.Verify(s.aggVK, s.batchVK); err != nil {
			return nil, fmt.Errorf("circuit release check (refreeze "+
				"CircuitRelease after ELF rebuild): %w", err)
		}
	}

	// Config-commitment check: the digest must bind the same election
	// parameters and circuit VKs the sequencer declared. This prevents a
	// malicious service from substituting different parameters (e.g. a fake
	// census root or encryption key) — the commitment in the digest would
	// not match the locally recomputed one.
	batchVKWords, err := VKWords(s.batchVK)
	if err != nil {
		return nil, fmt.Errorf("batch vk words: %w", err)
	}
	foldVKWords, err := VKWords(s.aggVK)
	if err != nil {
		return nil, fmt.Errorf("fold vk words: %w", err)
	}
	expectedCC, err := s.state.ConfigCommitment(batchVKWords, foldVKWords)
	if err != nil {
		return nil, fmt.Errorf("config commitment: %w", err)
	}
	if !bytes.Equal(digest.ConfigCommitment, expectedCC[:]) {
		return nil, fmt.Errorf("config commitment mismatch: the digest does " +
			"not bind the declared election parameters and circuit VKs — " +
			"possible parameter or circuit substitution")
	}

	// Consistency against the local state and the external vk binding.
	if digest.Mode != ModeFinalize {
		return nil, fmt.Errorf("finalize digest mode = %d, want %d", digest.Mode, ModeFinalize)
	}
	if digest.StateRootHex() != s.state.Root() {
		return nil, fmt.Errorf("digest state root %s != local root %s",
			digest.StateRootHex(), s.state.Root())
	}
	if digest.StepCount != s.foldCount {
		return nil, fmt.Errorf("digest step_count = %d, want %d folds", digest.StepCount, s.foldCount)
	}
	voters, overwrites := s.state.Voters()
	if uint64(digest.TotalVoters) != voters || uint64(digest.TotalOverwrites) != overwrites {
		return nil, fmt.Errorf("digest counts (%d, %d) != local (%d, %d)",
			digest.TotalVoters, digest.TotalOverwrites, voters, overwrites)
	}
	proofVK := "0x" + hex.EncodeToString(snark.ProgramVK[:])
	if err := digest.VerifyBinding(proofVK, s.batchVK); err != nil {
		return nil, err
	}
	for i, r := range results {
		if uint64(digest.Results[i]) != r {
			return nil, fmt.Errorf("digest result[%d] = %d, want %d", i, digest.Results[i], r)
		}
	}
	return &FinalResult{
		JobID:   finID,
		Digest:  digest,
		Snark:   snark,
		Results: results,
	}, nil
}
