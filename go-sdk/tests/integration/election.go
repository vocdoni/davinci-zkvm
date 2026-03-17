// election.go manages the DAVINCI election state used by the active STARK/ecgfp5
// integration suites. It owns the shared arbo SHA-256 process tree, the census
// membership structure, CSP signing state, and the ecgfp5 tally state mirrored
// by the zkVM guest.
package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/davinci-node/crypto/blobs"
	nodesig "github.com/vocdoni/davinci-node/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	leanimt "github.com/vocdoni/lean-imt-go"
)

const (
	procLevels    = 256
	ballotMin     = uint64(0x10)
	keyResultsAdd = uint64(0x04)
	keyResultsSub = uint64(0x05)
)

var configKeys = []uint64{0x00, 0x02, 0x03, 0x06}

type Election struct {
	ProcessID types.ProcessID
	Voters    []*Voter

	ProcTree *arbo.Tree
	Census   *leanimt.LeanIMT[*big.Int]
	OldRoot  string

	CspKey       *ecdsa.PrivateKey
	CensusOrigin int

	StarkEncKeyHex string
	StarkEncSkHex  string
	ResultsAddG5   [8]davinci.Ecgfp5Ciphertext
	ResultsSubG5   [8]davinci.Ecgfp5Ciphertext
	VotedBallotsG5 map[int][8]davinci.Ecgfp5Ciphertext
}

func newProcessTree(processIDBI *big.Int, censusOrigin uint64) (*arbo.Tree, string, error) {
	procDB := memdb.New()
	procTree, err := arbo.NewTree(arbo.Config{
		Database:     procDB,
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		return nil, "", fmt.Errorf("arbo.NewTree: %w", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	configValsBI := []*big.Int{
		processIDBI,
		big.NewInt(0),
		big.NewInt(0),
		new(big.Int).SetUint64(censusOrigin),
	}
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configValsBI[i]),
		); err != nil {
			return nil, "", fmt.Errorf("procTree.Add config[%d]: %w", i, err)
		}
	}

	zeroLeaf := new(big.Int)
	for _, k := range []uint64{keyResultsAdd, keyResultsSub} {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, zeroLeaf),
		); err != nil {
			return nil, "", fmt.Errorf("procTree.Add results key 0x%02x: %w", k, err)
		}
	}

	rootBytes, err := procTree.Root()
	if err != nil {
		return nil, "", fmt.Errorf("initial root: %w", err)
	}
	return procTree, "0x" + hex.EncodeToString(pad32(rootBytes)), nil
}

func deterministicVoters(nVoters int) ([]*Voter, error) {
	voters := make([]*Voter, nVoters)
	for i := 0; i < nVoters; i++ {
		seed := make([]byte, 32)
		for j := range seed {
			seed[j] = byte((i*7 + j*3 + 42) % 256)
		}
		signer, err := nodesig.NewSignerFromSeed(seed)
		if err != nil {
			return nil, fmt.Errorf("voter %d signer: %w", i, err)
		}
		addrBytes := signer.Address().Bytes()
		voters[i] = &Voter{
			Signer:        signer,
			AddressBytes:  addrBytes,
			AddressBigInt: new(big.Int).SetBytes(addrBytes),
			CensusIdx:     i,
			Weight:        big.NewInt(42),
		}
	}
	return voters, nil
}

func NewElection(nVoters int) (*Election, error) {
	var processID types.ProcessID
	copy(processID[:], "DAVINCI_INTEGRATION_TEST")
	processIDBI := new(big.Int).SetBytes(processID[:])

	procTree, oldRoot, err := newProcessTree(processIDBI, 1)
	if err != nil {
		return nil, err
	}

	voters, err := deterministicVoters(nVoters)
	if err != nil {
		return nil, err
	}

	imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("leanimt.New: %w", err)
	}
	for _, v := range voters {
		imt.Insert(packAddressWeight(v.AddressBigInt, v.Weight))
	}

	return &Election{
		ProcessID:    processID,
		Voters:       voters,
		ProcTree:     procTree,
		Census:       imt,
		OldRoot:      oldRoot,
		CensusOrigin: 1,
	}, nil
}

func NewCSPElection(nVoters int) (*Election, error) {
	var processID types.ProcessID
	copy(processID[:], "DAVINCI_CSP_INTEGR_T")
	processID[20] = 0x01
	processID[23] = 0x04
	processID[30] = 0x01
	processIDBI := new(big.Int).SetBytes(processID[:])

	procTree, oldRoot, err := newProcessTree(processIDBI, 4)
	if err != nil {
		return nil, err
	}

	cspKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey (CSP): %w", err)
	}

	voters, err := deterministicVoters(nVoters)
	if err != nil {
		return nil, err
	}

	return &Election{
		ProcessID:    processID,
		Voters:       voters,
		ProcTree:     procTree,
		OldRoot:      oldRoot,
		CspKey:       cspKey,
		CensusOrigin: 4,
	}, nil
}

func (e *Election) BuildCspData(batchVoters []*Voter) (*davinci.CspData, error) {
	if e.CspKey == nil {
		return nil, fmt.Errorf("election is not in CSP mode (no CSP key)")
	}

	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	pidBE := pad32(pidBI.Bytes())

	proofs := make([]davinci.CspProof, len(batchVoters))
	for i, v := range batchVoters {
		var payload [92]byte
		copy(payload[:32], pidBE)
		copy(payload[32:52], v.AddressBytes)
		v.Weight.FillBytes(payload[52:84])
		binary.BigEndian.PutUint64(payload[84:92], uint64(v.CensusIdx))

		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(payload))
		envelope := append([]byte(prefix), payload[:]...)
		hash := crypto.Keccak256(envelope)

		sig, err := crypto.Sign(hash, e.CspKey)
		if err != nil {
			return nil, fmt.Errorf("CSP sign voter %d: %w", i, err)
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])

		proofs[i] = davinci.CspProof{
			R:            fmt.Sprintf("0x%064x", r),
			S:            fmt.Sprintf("0x%064x", s),
			VoterAddress: fmt.Sprintf("0x%040x", new(big.Int).SetBytes(v.AddressBytes)),
			Weight:       fmt.Sprintf("0x%064x", v.Weight),
			Index:        uint64(v.CensusIdx),
		}
	}

	return &davinci.CspData{
		CspPubKeyX: fmt.Sprintf("0x%064x", e.CspKey.PublicKey.X),
		CspPubKeyY: fmt.Sprintf("0x%064x", e.CspKey.PublicKey.Y),
		Proofs:     proofs,
	}, nil
}

func (e *Election) processIDArboHex() string {
	bLen := arbo.HashFunctionSha256.Len()
	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	return "0x" + hex.EncodeToString(arbo.BigIntToBytes(bLen, pidBI))
}

func (e *Election) ProcessIDHex() string {
	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	return "0x" + hex.EncodeToString(pad32(pidBI.Bytes()))
}

func (e *Election) BuildCensusProofs(batchVoters []*Voter) ([]davinci.CensusProof, error) {
	root, ok := e.Census.Root()
	if !ok {
		return nil, fmt.Errorf("census tree has no root")
	}
	proofs := make([]davinci.CensusProof, len(batchVoters))
	for i, v := range batchVoters {
		proof, err := e.Census.GenerateProof(v.CensusIdx)
		if err != nil {
			return nil, fmt.Errorf("GenerateProof[%d]: %w", i, err)
		}
		sibs := make([]string, len(proof.Siblings))
		for j, s := range proof.Siblings {
			sibs[j] = bigIntToFr32(s)
		}
		proofs[i] = davinci.CensusProof{
			Root:     bigIntToFr32(root),
			Leaf:     bigIntToFr32(proof.Leaf),
			Index:    proof.Index,
			Siblings: sibs,
		}
	}
	return proofs, nil
}

func (e *Election) BuildKZGBlock(batchIdx int, oldRoot string) (*davinci.KZGRequest, error) {
	var blob types.Blob
	for i := 0; i < 16; i++ {
		big.NewInt(int64(batchIdx*16 + i + 1)).FillBytes(blob[i*32 : (i+1)*32])
	}

	kzgCommitment, err := blob.ComputeCommitment()
	if err != nil {
		return nil, fmt.Errorf("ComputeCommitment: %w", err)
	}
	var comm48 [48]byte
	copy(comm48[:], kzgCommitment[:])

	pidHex := e.ProcessIDHex()
	rootBEHex := arboHexToBEHex(oldRoot)
	kzgZ := deriveKZGZ(pidHex, rootBEHex, comm48)

	kzgY, err := blobs.EvaluateBarycentricNative(&blob, kzgZ, false)
	if err != nil {
		return nil, fmt.Errorf("EvaluateBarycentricNative: %w", err)
	}
	var yClaimed [32]byte
	kzgY.FillBytes(yClaimed[:])

	return &davinci.KZGRequest{
		ProcessID:      pidHex,
		RootHashBefore: rootBEHex,
		Commitment:     "0x" + hex.EncodeToString(comm48[:]),
		YClaimed:       "0x" + hex.EncodeToString(yClaimed[:]),
		Blob:           "0x" + hex.EncodeToString(blob[:]),
	}, nil
}
