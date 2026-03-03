// ballot.go provides ballot proof generation for the integration test suite.
//
// It wraps davinci-node's BallotProofForTestDeterministic, which uses
// go-rapidsnark (CGO) with the embedded ballot_proof.wasm from davinci-circom
// to generate real BN254 Groth16 ballot proofs.
package integration

import (
	ecdsapkg "crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/vocdoni/davinci-node/circuits/ballotproof"
	ballotprooftest "github.com/vocdoni/davinci-node/circuits/test/ballotproof"
	"github.com/vocdoni/davinci-node/crypto"
	"github.com/vocdoni/davinci-node/crypto/ecc"
	nodesig "github.com/vocdoni/davinci-node/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// sigJSON is the on-disk format expected by input-gen for ECDSA signatures.
type sigJSON struct {
	PublicKeyX string `json:"public_key_x"` // 0x-prefixed 32-byte big-endian hex
	PublicKeyY string `json:"public_key_y"` // 0x-prefixed 32-byte big-endian hex
	SignatureR string `json:"signature_r"`   // 0x-prefixed 32-byte big-endian hex
	SignatureS string `json:"signature_s"`   // 0x-prefixed 32-byte big-endian hex
	SignatureV byte   `json:"signature_v"`   // recovery bit (debug only)
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
	// AddressLo16 is the lower 16 bits of the voter's address, used in the
	// ballot SMT key: key = BallotMin + (censusIdx << 16) + addrLo16.
	AddressLo16 uint64
	// RawBallot stores the ciphertext data for re-encryption and tally.
	RawBallot *ballotRaw
	// ProofJSON is the snarkjs Groth16 proof (JSON).
	ProofJSON json.RawMessage
	// PublicInputs is the array of public signals: [address, voteID, inputsHash].
	PublicInputs []string
	// SigJSON is the ECDSA signature in input-gen format (JSON).
	SigJSON json.RawMessage
}

// ballotRaw holds the raw ciphertext data extracted from an elgamal.Ballot.
type ballotRaw struct {
	// Fields contains the 8 ciphertext pairs (C1, C2) as (x, y) big.Int pairs.
	C1X, C1Y, C2X, C2Y [8]*big.Int
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
	n := len(voters)
	vkBytes := ballotproof.CircomVerificationKey

	proofs := make([]json.RawMessage, n)
	pubInputs := make([][]string, n)
	sigs := make([]json.RawMessage, n)
	results := make([]*BallotResult, n)

	for i, v := range voters {
		seed := seedBase + int64(i)
		res, err := ballotprooftest.BallotProofForTestDeterministic(
			v.AddressBytes, processID, encKey, seed)
		if err != nil {
			return nil, fmt.Errorf("voter %d ballot proof: %w", i, err)
		}

		voteID := res.VoteID.Uint64()
		addrBig := new(big.Int).SetBytes(v.AddressBytes)
		addrLo16 := addrBig.Uint64() & 0xFFFF

		// Sign the voteID with the voter's secp256k1 key.
		sig, err := v.Signer.Sign(crypto.PadToSign(res.VoteID.Bytes()))
		if err != nil {
			return nil, fmt.Errorf("voter %d ecdsa sign: %w", i, err)
		}

		// Extract secp256k1 public key coordinates.
		ecdsaKey := (*ecdsapkg.PrivateKey)(v.Signer)
		sigData := sigJSON{
			PublicKeyX: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.X),
			PublicKeyY: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.Y),
			SignatureR: fmt.Sprintf("0x%064x", sig.R),
			SignatureS: fmt.Sprintf("0x%064x", sig.S),
			SignatureV: 0,
			VoteID:     voteID,
			Address:    addrBig.String(),
		}
		sigBytes, err := json.Marshal(sigData)
		if err != nil {
			return nil, fmt.Errorf("marshal sig %d: %w", i, err)
		}

		// Parse public signals: [address_dec, voteID_dec, inputsHash_dec].
		var pubSigs []string
		if err := json.Unmarshal([]byte(res.PubInputs), &pubSigs); err != nil {
			return nil, fmt.Errorf("parse public inputs %d: %w", i, err)
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

// BatchProveComponents holds the proof data for one batch of ballots.
type BatchProveComponents struct {
	// VK is the circom verification key JSON.
	VK json.RawMessage
	// Proofs are the snarkjs Groth16 proof JSONs.
	Proofs []json.RawMessage
	// PublicInputs are the public signal arrays for each proof.
	PublicInputs [][]string
	// Sigs are the ECDSA signature JSONs for each voter.
	Sigs []json.RawMessage
	// Results contains the per-voter ballot results.
	Results []*BallotResult
}

// ToProveRequest builds a davinci.ProveRequest from the batch components.
func (b *BatchProveComponents) ToProveRequest() *davinci.ProveRequest {
	return &davinci.ProveRequest{
		VK:           b.VK,
		Proofs:       b.Proofs,
		PublicInputs: b.PublicInputs,
		Sigs:         b.Sigs,
	}
}

// extractBallotRaw copies the 8 ciphertext big.Int values out of a BallotProofResult.
// BallotProofResult.Ballot has TE (Twisted Edwards) coordinates. We convert back to RTE
// (Reduced Twisted Edwards) before calling SetPoint, which expects RTE form.
func extractBallotRaw(res *ballotprooftest.BallotProofResult) *ballotRaw {
	// Convert TE → RTE so SetPoint receives the expected coordinate form.
	rteBallot := res.Ballot.FromTEtoRTE()
	raw := &ballotRaw{}
	for i := 0; i < 8; i++ {
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
