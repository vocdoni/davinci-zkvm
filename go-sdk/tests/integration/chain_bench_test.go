// chain_bench_test.go benchmarks the chained-mode pipeline end to end
// through the go-sdk/chain orchestrator, with a per-phase timing
// breakdown (batch proves, folds, finalize). All ballot inputs (Groth16
// proofs, signatures, census proofs) are generated BEFORE the clock
// starts — the benchmark measures how long it takes to produce the
// final election proof once the votes exist, which is the service-side
// question. Generated ballots are cached on disk (BENCH_CACHE_DIR) and
// reused across runs and batch sizes. Gated by CHAIN_BENCH=1; needs a
// running service with a GPU.
//
//	CHAIN_BENCH=1 DAVINCI_API_URL=http://127.0.0.1:8090 \
//	  BENCH_VOTES=1024 BENCH_BATCH_SIZE=64 BENCH_FOLD_EVERY=4 \
//	  go test ./integration -run TestChainBenchmark -v -timeout 120m
package integration

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/chain"
	davinciSolidity "github.com/vocdoni/davinci-zkvm/go-sdk/solidity"
)

// cachedVoter is one pre-generated vote: ballot proof, signature, census
// proof and the raw ciphertext needed to replay it through the sequencer.
type cachedVoter struct {
	CensusIdx          int
	VoteID             uint64
	AddressLo16        uint64
	Proof              []byte
	Sig                []byte
	PublicInputs       []string
	CensusProof        davinci.CensusProof
	C1X, C1Y, C2X, C2Y [NumFields]*big.Int
}

// ballotCache is a fully pre-generated election: per-voter records are
// independent, so the same cache serves any batch size that divides the
// vote count.
type ballotCache struct {
	ProcessID    []byte
	EncKey       []byte // bjj-marshaled public key
	EncPrivKey   *big.Int
	CensusRoot   *big.Int
	CensusOrigin uint64
	GenesisRoot  string
	GenTime      time.Duration
	VK           []byte
	Voters       []*cachedVoter
}

// benchCachePath keys the cache file by vote count only; batch size is a
// replay-time decision.
func benchCachePath(totalVotes int) string {
	dir := os.Getenv("BENCH_CACHE_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "benchmark", "cache")
	}
	return filepath.Join(dir, fmt.Sprintf("ballots-%d.gob", totalVotes))
}

// generateBallotCache builds a fresh election and all its ballot inputs
// (the part a real deployment receives from voters' devices).
func generateBallotCache(totalVotes int) (*ballotCache, error) {
	election, err := NewElection(totalVotes)
	if err != nil {
		return nil, fmt.Errorf("NewElection: %w", err)
	}
	censusRoot, ok := election.Census.Root()
	if !ok {
		return nil, fmt.Errorf("census tree has no root")
	}
	c := &ballotCache{
		ProcessID:    election.ProcessID[:],
		EncKey:       election.EncKey.Marshal(),
		EncPrivKey:   election.EncPrivKey,
		CensusRoot:   censusRoot,
		CensusOrigin: uint64(election.CensusOrigin),
		GenesisRoot:  election.OldRoot,
	}
	start := time.Now()
	const genChunk = 64
	for off := 0; off < totalVotes; off += genChunk {
		end := off + genChunk
		if end > totalVotes {
			end = totalVotes
		}
		voters := election.Voters[off:end]
		batch, err := GenerateBallotBatch(election.ProcessID, election.EncKey, voters, int64(42+off))
		if err != nil {
			return nil, fmt.Errorf("GenerateBallotBatch at %d: %w", off, err)
		}
		censusProofs, err := election.BuildCensusProofs(voters)
		if err != nil {
			return nil, fmt.Errorf("BuildCensusProofs at %d: %w", off, err)
		}
		if c.VK == nil {
			c.VK = batch.VK
		}
		for i, res := range batch.Results {
			c.Voters = append(c.Voters, &cachedVoter{
				CensusIdx:    voters[i].CensusIdx,
				VoteID:       res.VoteID,
				AddressLo16:  res.AddressLo16,
				Proof:        batch.Proofs[i],
				Sig:          batch.Sigs[i],
				PublicInputs: batch.PublicInputs[i],
				CensusProof:  censusProofs[i],
				C1X:          res.RawBallot.C1X,
				C1Y:          res.RawBallot.C1Y,
				C2X:          res.RawBallot.C2X,
				C2Y:          res.RawBallot.C2Y,
			})
		}
	}
	c.GenTime = time.Since(start)
	return c, nil
}

// loadOrGenerateBallots returns the cached election for totalVotes,
// generating and saving it on a cache miss.
func loadOrGenerateBallots(t *testing.T, totalVotes int) (*ballotCache, bool) {
	path := benchCachePath(totalVotes)
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		var c ballotCache
		if err := gob.NewDecoder(f).Decode(&c); err != nil {
			t.Fatalf("decode ballot cache %s: %v (delete it to regenerate)", path, err)
		}
		if len(c.Voters) != totalVotes {
			t.Fatalf("ballot cache %s has %d voters, want %d (delete it to regenerate)", path, len(c.Voters), totalVotes)
		}
		return &c, true
	}
	t.Logf("no ballot cache at %s, generating %d ballots (slow, one-time)", path, totalVotes)
	c, err := generateBallotCache(totalVotes)
	if err != nil {
		t.Fatalf("generateBallotCache: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create ballot cache: %v", err)
	}
	defer f.Close()
	if err := gob.NewEncoder(f).Encode(c); err != nil {
		t.Fatalf("encode ballot cache: %v", err)
	}
	return c, false
}

// batchRequest assembles the prove request and sequencer votes for
// voters [a, b) out of the cache.
func (c *ballotCache) batchRequest(a, b int) (*davinci.ProveRequest, []chain.Vote) {
	n := b - a
	req := &davinci.ProveRequest{
		VK:           json.RawMessage(c.VK),
		Proofs:       make([]json.RawMessage, n),
		PublicInputs: make([][]string, n),
		Sigs:         make([]json.RawMessage, n),
		CensusProofs: make([]davinci.CensusProof, n),
	}
	votes := make([]chain.Vote, n)
	for i := 0; i < n; i++ {
		v := c.Voters[a+i]
		req.Proofs[i] = json.RawMessage(v.Proof)
		req.PublicInputs[i] = v.PublicInputs
		req.Sigs[i] = json.RawMessage(v.Sig)
		req.CensusProofs[i] = v.CensusProof
		ballot := elgamal.NewBallot(bjjgnark.New())
		for j := 0; j < 8; j++ {
			ballot.Ciphertexts[j] = &elgamal.Ciphertext{
				C1: bjjgnark.New().SetPoint(v.C1X[j], v.C1Y[j]),
				C2: bjjgnark.New().SetPoint(v.C2X[j], v.C2Y[j]),
			}
		}
		votes[i] = chain.Vote{
			CensusIdx:   v.CensusIdx,
			VoteID:      v.VoteID,
			AddressLo16: v.AddressLo16,
			Ballot:      ballot,
		}
	}
	return req, votes
}

func TestChainBenchmark(t *testing.T) {
	if os.Getenv("CHAIN_BENCH") == "" {
		t.Skip("set CHAIN_BENCH=1 to run the chained-mode benchmark")
	}
	totalVotes := envInt("BENCH_VOTES", 1024)
	batchSize := envInt("BENCH_BATCH_SIZE", 64)
	foldEvery := envInt("BENCH_FOLD_EVERY", 4)
	nBatches := totalVotes / batchSize
	if nBatches*batchSize != totalVotes {
		t.Fatalf("BENCH_VOTES (%d) must be a multiple of BENCH_BATCH_SIZE (%d)", totalVotes, batchSize)
	}

	client := newClient()
	if err := checkServiceURL(apiURL + "/jobs"); err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v", apiURL, err)
	}

	// Untimed: ballot inputs are produced on voters' devices. The clock
	// only covers what the sequencer + service do once votes exist.
	cache, fromDisk := loadOrGenerateBallots(t, totalVotes)
	t.Logf("ballot inputs: %d votes ready (generation %v, cached=%v)", totalVotes, cache.GenTime, fromDisk)

	encKey := bjjgnark.New().(*bjjgnark.BJJ)
	if err := encKey.Unmarshal(cache.EncKey); err != nil {
		t.Fatalf("unmarshal cached enc key: %v", err)
	}
	// FoldEvery = 0: folds are timed explicitly below.
	seq, err := chain.NewSequencer(client, chain.Config{
		ProcessID:    new(big.Int).SetBytes(cache.ProcessID),
		BallotMode:   big.NewInt(0x01),
		EncKey:       encKey,
		CensusOrigin: cache.CensusOrigin,
		CensusRoot:   cache.CensusRoot,
	}, 0, proofTimeout())
	if err != nil {
		t.Fatalf("NewSequencer: %v", err)
	}
	if seq.State().Root() != cache.GenesisRoot {
		t.Fatalf("genesis root mismatch: chain %s, cache %s (stale cache?)", seq.State().Root(), cache.GenesisRoot)
	}

	benchStart := time.Now()
	var (
		proveTotal, foldTotal time.Duration
		proveTimes, foldTimes []time.Duration
	)
	for b := 0; b < nBatches; b++ {
		req, votes := cache.batchRequest(b*batchSize, (b+1)*batchSize)

		start := time.Now()
		if _, err := seq.ProveBatch(votes, req); err != nil {
			t.Fatalf("batch %d: ProveBatch: %v", b, err)
		}
		proveTimes = append(proveTimes, time.Since(start))
		proveTotal += proveTimes[len(proveTimes)-1]

		if len(seq.PendingBatches()) >= foldEvery {
			start := time.Now()
			if _, err := seq.Fold(); err != nil {
				t.Fatalf("fold after batch %d: %v", b, err)
			}
			foldTimes = append(foldTimes, time.Since(start))
			foldTotal += foldTimes[len(foldTimes)-1]
			t.Logf("fold %d (after batch %d): %v", len(foldTimes), b, foldTimes[len(foldTimes)-1])
		}
	}

	finalizeStart := time.Now()
	final, err := seq.Finalize(cache.EncPrivKey)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	finalizeTime := time.Since(finalizeStart)
	wallTotal := time.Since(benchStart)

	verifyStart := time.Now()
	if err := davinciSolidity.VerifyOnSimulated(solidityDir(), final.Snark); err != nil {
		t.Errorf("on-chain verification failed: %v", err)
	}
	verifyTime := time.Since(verifyStart)

	avg := func(ds []time.Duration) time.Duration {
		if len(ds) == 0 {
			return 0
		}
		var sum time.Duration
		for _, d := range ds {
			sum += d
		}
		return sum / time.Duration(len(ds))
	}

	serviceTotal := proveTotal + foldTotal + finalizeTime
	t.Logf("=== chained-mode benchmark ===")
	t.Logf("votes=%d  batch_size=%d  batches=%d  fold_every=%d  folds=%d",
		totalVotes, batchSize, nBatches, foldEvery, seq.FoldCount())
	t.Logf("batch STARK proves: total %v  avg %v", proveTotal, avg(proveTimes))
	t.Logf("folds: total %v  avg %v", foldTotal, avg(foldTimes))
	t.Logf("finalize (CP verify + PLONK wrap): %v", finalizeTime)
	t.Logf("service-side total: %v  (%.2f votes/s)", serviceTotal, float64(totalVotes)/serviceTotal.Seconds())
	t.Logf("wall total (incl client side): %v  (%.2f votes/s)", wallTotal, float64(totalVotes)/wallTotal.Seconds())
	t.Logf("on-chain verify (simulated): %v", verifyTime)
	t.Logf("results: %v  total_voters=%d  step_count=%d",
		final.Results, final.Digest.TotalVoters, final.Digest.StepCount)
}
