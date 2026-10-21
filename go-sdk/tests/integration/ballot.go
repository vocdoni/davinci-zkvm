// ballot.go provides ballot proof generation for the integration test suite.
//
// It wraps davinci-node's BallotProofForTestDeterministic, which uses
// go-rapidsnark (CGO) with the embedded ballot_proof.wasm from davinci-circom
// to generate real BN254 Groth16 ballot proofs.
package integration

import (
	ecdsapkg "crypto/ecdsa"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	ballotprooftest "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/test/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	nodesig "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/types"
)

// sigJSON is the on-disk format expected by input-gen for ECDSA signatures.
type sigJSON struct {
	PublicKeyX string `json:"public_key_x"` // 0x-prefixed 32-byte big-endian hex
	PublicKeyY string `json:"public_key_y"` // 0x-prefixed 32-byte big-endian hex
	SignatureR string `json:"signature_r"`  // 0x-prefixed 32-byte big-endian hex
	SignatureS string `json:"signature_s"`  // 0x-prefixed 32-byte big-endian hex
	SignatureV byte   `json:"signature_v"`  // recovery bit (debug only)
	VoteID     uint64 `json:"vote_id"`
	Address    string `json:"address"` // decimal uint160
}

// Voter holds all data for a single voter across multiple transitions.
type Voter struct {
	// Signer is the secp256k1 ECDSA key. Ethereum address = Signer.Address().
	Signer *nodesig.Signer
	// AddressBytes is the 20-byte Ethereum address (same as Signer.Address()).
	AddressBytes []byte
	// AddressBigInt is the address as a *big.Int for census leaf packing.
	AddressBigInt *big.Int
	// CensusIdx is the voter's 0-based index in the census lean-IMT.
	CensusIdx int
	// Weight is the voting weight assigned to this voter.
	Weight *big.Int
}

// BallotResult holds the output of a single ballot proof generation.
type BallotResult struct {
	// VoteID is the unique 64-bit vote identifier computed by the ballot circuit.
	// It is used as the arbo SMT key for the voteID insertion.
	VoteID uint64
	// AddressLo16 is the lower 16 bits of the voter's address, kept in the
	// cached ballot records. The ballot slot is davinci.SlotKey(address).
	AddressLo16 uint64
	// RawBallot stores the ciphertext data for re-encryption and tally.
	RawBallot *ballotRaw
	// ProofJSON is the snarkjs Groth16 proof (JSON).
	ProofJSON json.RawMessage
	// PublicInputs are the proof's 71 public signals as the circuit output
	// them. The guest derives the same values; they are never sent.
	PublicInputs []string
	// SigJSON is the ECDSA signature in input-gen format (JSON).
	SigJSON json.RawMessage
}

// ballotRaw holds the raw ciphertext data extracted from an elgamal.Ballot.
type ballotRaw struct {
	// Fields contains the NumFields ciphertext pairs (C1, C2) as (x, y) big.Int pairs.
	C1X, C1Y, C2X, C2Y [davinci.NumFields]*big.Int
}

// GenerateBallotBatch generates one Groth16 ballot proof per voter and returns
// all data needed to build the ProveRequest and protocol blocks.
//
// processID is the DAVINCI election process ID (31 bytes).
// encKey is the ElGamal BabyJubJub public key used to encrypt ballots.
// voters is the list of voters in this batch.
// seedBase is used to generate deterministic ballot fields (voter i uses seedBase+i).
func GenerateBallotBatch(
	processID types.ProcessID,
	encKey ecc.Point,
	voters []*Voter,
	seedBase int64,
) (*BatchProveComponents, error) {
	// Delegate to a subprocess so that all wasmer/rapidsnark CGO memory
	// (~128 MB WASM linear memory per proof) is reclaimed by the OS on exit.
	// Worker mode bypasses this to avoid infinite recursion.
	if len(voters) > 16 && os.Getenv("BALLOT_WORKER_MODE") != "1" {
		return generateBallotBatchViaSubprocess(processID, encKey.(*bjjgnark.BJJ), voters, seedBase)
	}

	n := len(voters)
	vkBytes := ballotproof.CircomVerificationKey

	proofs := make([]json.RawMessage, n)
	pubInputs := make([][]string, n)
	sigs := make([]json.RawMessage, n)
	results := make([]*BallotResult, n)

	for i, v := range voters {
		seed := seedBase + int64(i)
		res, err := ballotprooftest.DeterministicBallotProofWeight(
			v.AddressBytes, processID, encKey, seed, v.Weight)
		if err != nil {
			return nil, fmt.Errorf("voter %d ballot proof: %w", i, err)
		}

		voteID := res.VoteID.Uint64()
		addrBig := new(big.Int).SetBytes(v.AddressBytes)
		addrLo16 := addrBig.Uint64() & 0xFFFF

		// Parse the 71 public signals (kept for checks, never sent).
		var pubSigs []string
		if err := json.Unmarshal([]byte(res.PubInputs), &pubSigs); err != nil {
			return nil, fmt.Errorf("parse public inputs %d: %w", i, err)
		}

		// Sign the vote envelope with the voter's secp256k1 key: the process
		// id, the vote id and the original ballot the proof commits to
		// (public signals 7..70, circuit order).
		sigBytes65, err := signVoteEnvelope(v, processID, voteID, pubSigs)
		if err != nil {
			return nil, fmt.Errorf("voter %d: %w", i, err)
		}

		// The circuit recovers the public key via `ecdsa_recover_secp256k1(r, s, z, recid)`,
		// so SignatureV must be the real parity bit (0 or 1): [r(32) || s(32) || v(1)].
		ecdsaKey := (*ecdsapkg.PrivateKey)(v.Signer)
		sigData := sigJSON{
			PublicKeyX: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.X),
			PublicKeyY: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.Y),
			SignatureR: "0x" + hex.EncodeToString(sigBytes65[:32]),
			SignatureS: "0x" + hex.EncodeToString(sigBytes65[32:64]),
			SignatureV: sigBytes65[64],
			VoteID:     voteID,
			Address:    addrBig.String(),
		}
		sigBytes, err := json.Marshal(sigData)
		if err != nil {
			return nil, fmt.Errorf("marshal sig %d: %w", i, err)
		}

		// Extract raw ciphertext data from the ballot for re-encryption.
		raw := extractBallotRaw(res)

		// rapidsnark omits the "curve" field; gen-input requires it.
		proofJSON, err := injectCurveField(res.Proof, "bn128")
		if err != nil {
			return nil, fmt.Errorf("inject curve field %d: %w", i, err)
		}
		proofs[i] = json.RawMessage(proofJSON)
		pubInputs[i] = pubSigs
		sigs[i] = sigBytes
		results[i] = &BallotResult{
			VoteID:       voteID,
			AddressLo16:  addrLo16,
			RawBallot:    raw,
			ProofJSON:    json.RawMessage(proofJSON),
			PublicInputs: pubSigs,
			SigJSON:      sigBytes,
		}

	}

	return &BatchProveComponents{
		VK:           json.RawMessage(vkBytes),
		Proofs:       proofs,
		PublicInputs: pubInputs,
		Sigs:         sigs,
		Results:      results,
	}, nil
}

// signVoteEnvelope signs davinci.VoteEnvelopeDigest for one ballot: pubSigs
// are its 71 public signals, whose last BallotFields entries are the original
// ciphertexts in circuit order. Returns r ‖ s ‖ v, v in {0, 1}.
func signVoteEnvelope(v *Voter, processID types.ProcessID, voteID uint64, pubSigs []string) ([]byte, error) {
	if len(pubSigs) != davinci.BallotPublicInputs {
		return nil, fmt.Errorf("%d public signals, want %d", len(pubSigs), davinci.BallotPublicInputs)
	}
	coords := make([]*big.Int, davinci.BallotFields)
	for j := range coords {
		c, ok := new(big.Int).SetString(pubSigs[davinci.BallotPublicInputs-davinci.BallotFields+j], 10)
		if !ok {
			return nil, fmt.Errorf("public signal %d is not decimal", j)
		}
		coords[j] = c
	}
	sig, err := davinci.SignVote((*ecdsapkg.PrivateKey)(v.Signer), processID.MathBigInt(), voteID, coords)
	if err != nil {
		return nil, fmt.Errorf("sign vote envelope: %w", err)
	}
	return sig, nil
}

// BatchProveComponents holds the proof data for one batch of ballots.
type BatchProveComponents struct {
	// VK is the circom verification key JSON.
	VK json.RawMessage
	// Proofs are the snarkjs Groth16 proof JSONs.
	Proofs []json.RawMessage
	// PublicInputs are the circuit's public signals for each proof (not sent).
	PublicInputs [][]string
	// Sigs are the ECDSA signature JSONs for each voter.
	Sigs []json.RawMessage
	// Results contains the per-voter ballot results.
	Results []*BallotResult
}

// ToProveRequest builds a davinci.ProveRequest from the batch components.
func (b *BatchProveComponents) ToProveRequest() *davinci.ProveRequest {
	return &davinci.ProveRequest{
		VK:     b.VK,
		Proofs: b.Proofs,
		Sigs:   b.Sigs,
	}
}

// extractBallotRaw copies the NumFields ciphertext big.Int values out of a BallotProofResult.
// BallotProofResult.Ballot has TE (Twisted Edwards) coordinates. We convert back to RTE
// (Reduced Twisted Edwards) before calling SetPoint, which expects RTE form.
func extractBallotRaw(res *ballotprooftest.BallotProofResult) *ballotRaw {
	// Convert TE → RTE so SetPoint receives the expected coordinate form.
	rteBallot := res.Ballot.FromTEtoRTE()
	raw := &ballotRaw{}
	for i := 0; i < davinci.NumFields; i++ {
		if i < len(rteBallot.Ciphertexts) && rteBallot.Ciphertexts[i] != nil {
			x1, y1 := rteBallot.Ciphertexts[i].C1.Point()
			x2, y2 := rteBallot.Ciphertexts[i].C2.Point()
			raw.C1X[i] = new(big.Int).Set(x1)
			raw.C1Y[i] = new(big.Int).Set(y1)
			raw.C2X[i] = new(big.Int).Set(x2)
			raw.C2Y[i] = new(big.Int).Set(y2)
		} else {
			// Identity element in RTE form: (0, 1).
			raw.C1X[i] = big.NewInt(0)
			raw.C1Y[i] = big.NewInt(1)
			raw.C2X[i] = big.NewInt(0)
			raw.C2Y[i] = big.NewInt(1)
		}
	}
	return raw
}

// injectCurveField adds the "curve" key to a snarkjs proof JSON if it is absent.
// rapidsnark v0.0.12 omits this field; gen-input requires it.
func injectCurveField(proofJSON string, curve string) (string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(proofJSON), &m); err != nil {
		return "", err
	}
	if _, ok := m["curve"]; !ok {
		curveJSON, _ := json.Marshal(curve)
		m["curve"] = json.RawMessage(curveJSON)
	}
	out, err := json.Marshal(m)
	return string(out), err
}

// CachedBallotBatch is GenerateBallotBatch with an on-disk gob cache. The
// proofs bind the encryption key, so the cache is only used when the election
// is seeded (DAVINCI_TEST_ELECTION_SEED); the file name carries the seed, the
// field count, the voter range and the ballot seed. Files live in
// BENCH_CACHE_DIR (default benchmark/cache).
func CachedBallotBatch(e *Election, voters []*Voter, seedBase int64) (*BatchProveComponents, error) {
	seed := os.Getenv("DAVINCI_TEST_ELECTION_SEED")
	if seed == "" || len(voters) == 0 {
		return GenerateBallotBatch(e.ProcessID, e.EncKey, voters, seedBase)
	}
	_, nf := ballotModeLeaf()
	// "v3": signatures cover the vote envelope; older caches hold vote-id signatures.
	tag := sha256.Sum256([]byte(seed + "|v3"))
	name := fmt.Sprintf("plonk-ballots-nf%d-v%d-%d-s%d-%s.gob",
		nf, voters[0].CensusIdx, voters[len(voters)-1].CensusIdx, seedBase, hex.EncodeToString(tag[:4]))
	dir := os.Getenv("BENCH_CACHE_DIR")
	if dir == "" {
		dir = filepath.Join("..", "..", "..", "benchmark", "cache")
	}
	path := filepath.Join(dir, name)
	if f, err := os.Open(path); err == nil {
		var b BatchProveComponents
		decErr := gob.NewDecoder(f).Decode(&b)
		f.Close()
		if decErr == nil && len(b.Results) == len(voters) {
			return &b, nil
		}
	}
	b, err := GenerateBallotBatch(e.ProcessID, e.EncKey, voters, seedBase)
	if err != nil {
		return nil, err
	}
	// Best effort: a cache write failure just means the next run regenerates.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return b, nil
	}
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return b, nil
	}
	if err := gob.NewEncoder(f).Encode(b); err != nil {
		f.Close()
		os.Remove(tmp)
		return b, nil
	}
	f.Close()
	_ = os.Rename(tmp, path)
	return b, nil
}
