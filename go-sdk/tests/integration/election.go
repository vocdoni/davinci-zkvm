// election.go manages the DAVINCI election state for integration testing.
//
// An Election holds the process state arbo-SHA256 tree, the census lean-IMT,
// the ElGamal encryption key pair, and all voter accounts. It provides methods
// to build each protocol block for a state-transition batch.
package integration

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/vocdoni/davinci-node/crypto/blobs"
	bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-node/crypto/ecc"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	nodesig "github.com/vocdoni/davinci-node/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-node/types"
	leanimt "github.com/vocdoni/lean-imt-go"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

const (
	// procLevels is the number of levels in the arbo SHA-256 process state tree.
	procLevels = 256
	// ballotMin is the minimum key for ballot SMT entries (matches circuit constant).
	ballotMin = uint64(0x10)
	// voteIDMin is the minimum key for voteID SMT entries (bit 63 set).
	voteIDMin = uint64(0x8000_0000_0000_0000)
	// keyResultsAdd is the arbo state tree key for the accumulated ResultsAdd ballot.
	keyResultsAdd = uint64(0x04)
	// keyResultsSub is the arbo state tree key for the accumulated ResultsSub ballot.
	keyResultsSub = uint64(0x05)
)

// configKeys are the process config keys stored in the state tree at election setup.
// These are read-only per batch (verified via process read-proofs in the circuit).
var configKeys = []uint64{0x00, 0x02, 0x03, 0x06}

// Election holds all state for a DAVINCI election in the integration test.
type Election struct {
	// ProcessID is the 31-byte DAVINCI process identifier used in ballot proofs.
	ProcessID types.ProcessID
	// EncKey is the BabyJubJub ElGamal public key used to encrypt ballots.
	EncKey *bjjgnark.BJJ
	// EncPrivKey is the private scalar used to decrypt the accumulated tally.
	EncPrivKey *big.Int
	// Voters is the ordered list of all registered voters.
	Voters []*Voter
	// ProcTree is the arbo SHA-256 state tree (shared across all transitions).
	ProcTree *arbo.Tree
	// Census is the lean-IMT built from all voters.
	Census *leanimt.LeanIMT[*big.Int]
	// censusLeaves are the leaf values (packed address+weight) for each voter.
	censusLeaves []*big.Int
	// OldRoot is the current state root (updated after each batch).
	OldRoot string
	// configVals are the process config BigInt values inserted at setup.
	configVals []*big.Int
	// ResultsAdd is the Fr-wise accumulated sum of all re-encrypted ballot coordinates.
	// Uses coordinate-wise Fr addition to match the circuit's ballot_add().
	ResultsAdd frAccumBallot
	// ResultsSub is the Fr-wise accumulated sum of overwritten ballot coordinates.
	ResultsSub frAccumBallot
	// VotedBallots maps voter CensusIdx → their last re-encrypted ballot stored in the
	// state tree. Used to detect overwrites and to compute ResultsSub contributions.
	VotedBallots map[int]*elgamal.Ballot
	// CspKey is the CSP's secp256k1 private key (nil for Merkle census mode).
	CspKey *ecdsa.PrivateKey
	// CensusOrigin is the census type: 1 = lean-IMT, 4 = CSP ECDSA.
	CensusOrigin int
}

// NewElection creates a new test election with nVoters registered voters.
// It builds the process state tree (with config), the census IMT, and
// generates random ElGamal and ECDSA keys.
func NewElection(nVoters int) (*Election, error) {
	// ── ProcessID (for ballot proofs and state tree key 0x00) ────────────────
	var processID types.ProcessID
	copy(processID[:], "DAVINCI_INTEGRATION_TEST")
	processIDBI := new(big.Int).SetBytes(processID[:])

	// ── ElGamal encryption key ───────────────────────────────────────────────
	// Generated BEFORE tree setup because the encryption key hash is stored
	// in the process config tree under key 0x03.
	encKeyPoint, encPrivKey, err := elgamal.GenerateKey(bjjgnark.New())
	if err != nil {
		return nil, fmt.Errorf("elgamal.GenerateKey: %w", err)
	}
	encKey := encKeyPoint.(*bjjgnark.BJJ)

	// Compute the encryption key leaf value: SHA-256(X_BE32 || Y_BE32).
	// This binds the re-encryption public key to the state tree, enforced by
	// the circuit's cross-block binding check (FAIL_BINDING).
	encKeyHashBI := encKeyLeafValue(encKey)

	// ── Process state tree ───────────────────────────────────────────────────
	procDB := memdb.New()
	procTree, err := arbo.NewTree(arbo.Config{
		Database:     procDB,
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("arbo.NewTree: %w", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	// Config values stored under their respective keys.
	// The circuit validates these keys and cross-checks processID and encKey.
	configValsBI := []*big.Int{
		processIDBI,        // 0x00 = ProcessID (must match STATETX block header)
		big.NewInt(0x01),   // 0x02 = BallotMode
		encKeyHashBI,       // 0x03 = EncryptionKey (SHA-256 of pubkey coordinates)
		big.NewInt(0x01),   // 0x06 = CensusOrigin
	}
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configValsBI[i]),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add config[%d]: %w", i, err)
		}
	}

	// ── ResultsAdd (0x04) and ResultsSub (0x05) ──────────────────────────────
	zeroAccum := newZeroFrAccum()
	zeroLeafBI := frAccumLeafHash(zeroAccum)
	for _, k := range []uint64{keyResultsAdd, keyResultsSub} {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, zeroLeafBI),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add results key 0x%02x: %w", k, err)
		}
	}

	rootBytes, err := procTree.Root()
	if err != nil {
		return nil, fmt.Errorf("initial root: %w", err)
	}
	oldRoot := "0x" + hex.EncodeToString(pad32(rootBytes))

	// ── Voters ───────────────────────────────────────────────────────────────
	voters := make([]*Voter, nVoters)
	for i := 0; i < nVoters; i++ {
		seed := make([]byte, 32)
		// Deterministic seed per voter index.
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

	// ── Census lean-IMT ──────────────────────────────────────────────────────
	imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("leanimt.New: %w", err)
	}
	leaves := make([]*big.Int, nVoters)
	for i, v := range voters {
		leaves[i] = packAddressWeight(v.AddressBigInt, v.Weight)
		imt.Insert(leaves[i])
	}

	return &Election{
		ProcessID:    processID,
		EncKey:       encKey,
		EncPrivKey:   encPrivKey,
		Voters:       voters,
		ProcTree:     procTree,
		Census:       imt,
		censusLeaves: leaves,
		OldRoot:      oldRoot,
		configVals:   configValsBI,
		ResultsAdd:   newZeroFrAccum(),
		ResultsSub:   newZeroFrAccum(),
		VotedBallots: make(map[int]*elgamal.Ballot),
		CensusOrigin: 1,
	}, nil
}

// NewCSPElection creates a test election using CSP ECDSA census (censusOrigin=4).
// Instead of a lean-IMT census tree, voters are authenticated by the CSP's signature.
// The CSP's Ethereum address serves as the census root.
func NewCSPElection(nVoters int) (*Election, error) {
	// Build a valid ProcessID: addr(20) + version(4) + nonce(7).
	// Use the same structure as NewElection but with a distinct identifier.
	var processID types.ProcessID
	copy(processID[:], "DAVINCI_CSP_INTEGR_T") // 20 bytes for addr
	processID[20] = 0x01                        // version bytes (must be non-zero)
	processID[21] = 0x00
	processID[22] = 0x00
	processID[23] = 0x04                        // censusOrigin hint
	processID[24] = 0x00                        // nonce
	processID[25] = 0x00
	processID[26] = 0x00
	processID[27] = 0x00
	processID[28] = 0x00
	processID[29] = 0x00
	processID[30] = 0x01
	processIDBI := new(big.Int).SetBytes(processID[:])

	encKeyPoint, encPrivKey, err := elgamal.GenerateKey(bjjgnark.New())
	if err != nil {
		return nil, fmt.Errorf("elgamal.GenerateKey: %w", err)
	}
	encKey := encKeyPoint.(*bjjgnark.BJJ)
	encKeyHashBI := encKeyLeafValue(encKey)

	// Generate CSP secp256k1 key pair.
	cspKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey (CSP): %w", err)
	}

	// Process state tree setup (same as Merkle, but censusOrigin=4).
	procDB := memdb.New()
	procTree, err := arbo.NewTree(arbo.Config{
		Database:     procDB,
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("arbo.NewTree: %w", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	configValsBI := []*big.Int{
		processIDBI,        // 0x00 = ProcessID
		big.NewInt(0x01),   // 0x02 = BallotMode
		encKeyHashBI,       // 0x03 = EncryptionKey hash
		big.NewInt(0x04),   // 0x06 = CensusOrigin = CSP
	}
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configValsBI[i]),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add config[%d]: %w", i, err)
		}
	}

	// ResultsAdd (0x04) and ResultsSub (0x05).
	zeroAccum := newZeroFrAccum()
	zeroLeafBI := frAccumLeafHash(zeroAccum)
	for _, k := range []uint64{keyResultsAdd, keyResultsSub} {
		if err := procTree.Add(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, zeroLeafBI),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add results key 0x%02x: %w", k, err)
		}
	}

	rootBytes, err := procTree.Root()
	if err != nil {
		return nil, fmt.Errorf("initial root: %w", err)
	}
	oldRoot := "0x" + hex.EncodeToString(pad32(rootBytes))

	// Voters (same key generation as Merkle mode).
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

	return &Election{
		ProcessID:    processID,
		EncKey:       encKey,
		EncPrivKey:   encPrivKey,
		Voters:       voters,
		ProcTree:     procTree,
		OldRoot:      oldRoot,
		configVals:   configValsBI,
		ResultsAdd:   newZeroFrAccum(),
		ResultsSub:   newZeroFrAccum(),
		VotedBallots: make(map[int]*elgamal.Ballot),
		CspKey:       cspKey,
		CensusOrigin: 4,
	}, nil
}

// BuildCspData builds the CSP ECDSA census block for a batch of voters.
// Each voter's eligibility is signed by the CSP key using Ethereum personal-sign:
//   message = "\x19Ethereum Signed Message:\n92" || processID(32BE) || address(20) || weight(32BE) || index(8BE)
func (e *Election) BuildCspData(batchVoters []*Voter) (*davinci.CspData, error) {
	if e.CspKey == nil {
		return nil, fmt.Errorf("election is not in CSP mode (no CSP key)")
	}

	// ProcessID as 32-byte big-endian.
	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	pidBE := pad32(pidBI.Bytes())

	proofs := make([]davinci.CspProof, len(batchVoters))
	for i, v := range batchVoters {
		// Build CSP payload: processID(32BE) || address(20) || weight(32BE) || index(8BE)
		var payload [92]byte
		copy(payload[:32], pidBE)
		copy(payload[32:52], v.AddressBytes)
		v.Weight.FillBytes(payload[52:84])
		binary.BigEndian.PutUint64(payload[84:92], uint64(v.CensusIdx))

		// Ethereum personal-sign envelope.
		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(payload))
		envelope := append([]byte(prefix), payload[:]...)
		hash := crypto.Keccak256(envelope)

		sig, err := crypto.Sign(hash, e.CspKey)
		if err != nil {
			return nil, fmt.Errorf("CSP sign voter %d: %w", i, err)
		}
		// sig = [R(32) || S(32) || V(1)]
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

// processIDArboHex returns the processID as arbo-LE hex for the STATETX block.
// The service's hex32_to_smt_fr interprets this as LE bytes → LE u64 words.
// This value matches the arbo leaf value for process config key 0x00.
func (e *Election) processIDArboHex() string {
	bLen := arbo.HashFunctionSha256.Len()
	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	return "0x" + hex.EncodeToString(arbo.BigIntToBytes(bLen, pidBI))
}

// ProcessIDHex returns the processID as standard BE hex for the KZG block
// and Z derivation. The service's be_hex32_to_fr_le interprets this as
// BE bytes → LE u64 words. Both methods produce the same FrRaw in the circuit.
func (e *Election) ProcessIDHex() string {
	pidBI := new(big.Int).SetBytes(e.ProcessID[:])
	return "0x" + hex.EncodeToString(pad32(pidBI.Bytes()))
}

// BuildStateBlock builds the STATETX protocol block for a batch of voters.
//
// It inserts or updates each voter's voteID and ballot key in the process state tree,
// accumulates the re-encrypted ballots into the ResultsAdd leaf (key 0x04), and, when
// any voter is casting a replacement ballot, also updates the ResultsSub leaf (key 0x05)
// with the homomorphic sum of the replaced old ballots.
//
// Returns the StateTransitionData, the list of overwritten (old) re-encrypted ballots
// (may be empty), and an error.  e.OldRoot is advanced to the new root on success.
// reencBallots must have the same length as ballotResults.
func (e *Election) BuildStateBlock(batchVoters []*Voter, ballotResults []*BallotResult, reencBallots []*elgamal.Ballot) (*davinci.StateTransitionData, []*elgamal.Ballot, error) {
	n := len(batchVoters)
	if n != len(ballotResults) {
		return nil, nil, fmt.Errorf("voter/result count mismatch: %d vs %d", n, len(ballotResults))
	}
	if len(reencBallots) != n {
		return nil, nil, fmt.Errorf("reencBallots count mismatch: got %d want %d", len(reencBallots), n)
	}

	bLen := arbo.HashFunctionSha256.Len()
	processSmtProofs, err := buildArboReadProofs(e.ProcTree, configKeys, bLen, procLevels)
	if err != nil {
		return nil, nil, fmt.Errorf("buildArboReadProofs: %w", err)
	}

	// Insert voteID keys for each voter (always a fresh INSERT — even for overwrites,
	// each ballot submission carries a new unique voteID).
	var voteIDChain []davinci.SmtEntry
	for i, res := range ballotResults {
		entry, err := buildArboInsertEntry(
			e.ProcTree,
			new(big.Int).SetUint64(res.VoteID),
			new(big.Int).SetUint64(uint64(1000+i)),
			procLevels,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("voteID insert[%d]: %w", i, err)
		}
		voteIDChain = append(voteIDChain, entry)
	}

	// Insert or update ballot keys for each voter.
	// A voter casting their first ballot triggers an INSERT; a voter replacing
	// a prior ballot triggers an UPDATE.  The stored value is the SHA-256 leaf hash
	// of the new re-encrypted ballot.
	var ballotChain []davinci.SmtEntry
	var overwrittenBallots []*elgamal.Ballot
	for i, v := range batchVoters {
		res := ballotResults[i]
		key := ballotMin + uint64(v.CensusIdx)<<16 + res.AddressLo16
		newLeafVal := ballotLeafHash(reencBallots[i])

		if oldBallot, isOverwrite := e.VotedBallots[v.CensusIdx]; isOverwrite {
			// Voter is replacing a prior ballot: UPDATE the existing arbo leaf.
			entry, err := buildArboUpdateEntry(
				e.ProcTree,
				new(big.Int).SetUint64(key),
				newLeafVal,
				procLevels,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot update[%d] (voter %d): %w", i, v.CensusIdx, err)
			}
			ballotChain = append(ballotChain, entry)
			overwrittenBallots = append(overwrittenBallots, oldBallot)
		} else {
			// First ballot for this voter: INSERT a new arbo leaf.
			entry, err := buildArboInsertEntry(
				e.ProcTree,
				new(big.Int).SetUint64(key),
				newLeafVal,
				procLevels,
			)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot insert[%d] (voter %d): %w", i, v.CensusIdx, err)
			}
			ballotChain = append(ballotChain, entry)
		}
		// Record this voter's latest re-encrypted ballot for future overwrite detection.
		e.VotedBallots[v.CensusIdx] = reencBallots[i]
	}

	// ── ResultsAdd: accumulate re-encrypted ballots and update key 0x04 ──────
	// Snapshot old accumulators for BallotProofData before mutation.
	oldResultsAdd := e.ResultsAdd
	oldResultsSub := e.ResultsSub

	// Accumulate using coordinate-wise Fr addition (matches circuit's ballot_add).
	newResultsAdd := e.ResultsAdd
	for _, rb := range reencBallots {
		newResultsAdd = frAccumAdd(newResultsAdd, frAccumFromBallot(rb))
	}
	newResultsAddLeaf := frAccumLeafHash(newResultsAdd)

	resultsAddEntry, err := buildArboUpdateEntry(
		e.ProcTree,
		new(big.Int).SetUint64(keyResultsAdd),
		newResultsAddLeaf,
		procLevels,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ResultsAdd update: %w", err)
	}
	e.ResultsAdd = newResultsAdd

	// ── ResultsSub: when any voter overwrote a ballot, update key 0x05 ───────
	var resultsSubEntry *davinci.SmtEntry
	if len(overwrittenBallots) > 0 {
		newResultsSub := e.ResultsSub
		for _, ob := range overwrittenBallots {
			newResultsSub = frAccumAdd(newResultsSub, frAccumFromBallot(ob))
		}
		newResultsSubLeaf := frAccumLeafHash(newResultsSub)

		entry, err := buildArboUpdateEntry(
			e.ProcTree,
			new(big.Int).SetUint64(keyResultsSub),
			newResultsSubLeaf,
			procLevels,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("ResultsSub update: %w", err)
		}
		e.ResultsSub = newResultsSub
		resultsSubEntry = &entry
	}

	// Read new root AFTER all insertions + ResultsAdd + (optional) ResultsSub updates.
	newRootBytes, err := e.ProcTree.Root()
	if err != nil {
		return nil, nil, fmt.Errorf("tree.Root (new): %w", err)
	}
	newRoot := "0x" + hex.EncodeToString(pad32(newRootBytes))

	oldRoot := e.OldRoot
	e.OldRoot = newRoot

	// Build BallotProofData for the result accumulator verification.
	voterBallotStrs := make([][]string, n)
	for i, rb := range reencBallots {
		voterBallotStrs[i] = ballotToFrStrings(rb)
	}
	overwrittenBallotStrs := make([][]string, len(overwrittenBallots))
	for i, ob := range overwrittenBallots {
		overwrittenBallotStrs[i] = ballotToFrStrings(ob)
	}
	ballotProofs := &davinci.BallotProofData{
		OldResultsAdd:      frAccumToStrings(oldResultsAdd),
		OldResultsSub:      frAccumToStrings(oldResultsSub),
		VoterBallots:       voterBallotStrs,
		OverwrittenBallots: overwrittenBallotStrs,
	}

	return &davinci.StateTransitionData{
		VotersCount:      uint64(n),
		OverwrittenCount: uint64(len(overwrittenBallots)),
		ProcessID:        e.processIDArboHex(),
		OldStateRoot:     oldRoot,
		NewStateRoot:     newRoot,
		VoteIDSmt:        voteIDChain,
		BallotSmt:        ballotChain,
		ResultsAddSmt:    &resultsAddEntry,
		ResultsSubSmt:    resultsSubEntry,
		ProcessSmt:       processSmtProofs,
		BallotProofs:     ballotProofs,
	}, overwrittenBallots, nil
}

// BuildCensusProofs builds lean-IMT Poseidon membership proofs for batchVoters.
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

// BuildReencBlock builds the REENCBLK protocol block for a batch.
// It re-encrypts each voter's ElGamal ballot with a random k and returns
// the re-encryption data along with the re-encrypted ballots for tally accumulation.
func (e *Election) BuildReencBlock(ballotResults []*BallotResult) (*davinci.ReencryptionData, []*elgamal.Ballot, error) {
	pkX, pkY := bjjPointToFr32Hex(e.EncKey)
	entries := make([]davinci.ReencryptionEntry, len(ballotResults))
	reencBallots := make([]*elgamal.Ballot, len(ballotResults))

	for idx, res := range ballotResults {
		// Reconstruct the elgamal.Ballot from raw ciphertext data.
		// SetPoint returns a NEW point (doesn't modify in-place), so capture the return value.
		ballot := elgamal.NewBallot(bjjgnark.New())
		for i := 0; i < 8; i++ {
			c1 := bjjgnark.New().SetPoint(res.RawBallot.C1X[i], res.RawBallot.C1Y[i])
			c2 := bjjgnark.New().SetPoint(res.RawBallot.C2X[i], res.RawBallot.C2Y[i])
			ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
		}

		// Re-encrypt with a random k.
		rawK, err := rand.Int(rand.Reader, e.EncKey.Order())
		if err != nil {
			return nil, nil, fmt.Errorf("rand.Int[%d]: %w", idx, err)
		}
		reencBallot, _, err := ballot.Reencrypt(e.EncKey, rawK)
		if err != nil {
			return nil, nil, fmt.Errorf("Reencrypt[%d]: %w", idx, err)
		}
		reencBallots[idx] = reencBallot

		entry := davinci.ReencryptionEntry{K: bigIntToFr32(rawK)}
		for i := 0; i < 8; i++ {
			origC1x, origC1y := bjjPointToFr32Hex(ballot.Ciphertexts[i].C1)
			origC2x, origC2y := bjjPointToFr32Hex(ballot.Ciphertexts[i].C2)
			reencC1x, reencC1y := bjjPointToFr32Hex(reencBallot.Ciphertexts[i].C1)
			reencC2x, reencC2y := bjjPointToFr32Hex(reencBallot.Ciphertexts[i].C2)
			entry.Original[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: origC1x, Y: origC1y},
				C2: davinci.BjjPoint{X: origC2x, Y: origC2y},
			}
			entry.Reencrypted[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: reencC1x, Y: reencC1y},
				C2: davinci.BjjPoint{X: reencC2x, Y: reencC2y},
			}
		}
		entries[idx] = entry
	}

	return &davinci.ReencryptionData{
		EncryptionKeyX: pkX,
		EncryptionKeyY: pkY,
		Entries:        entries,
	}, reencBallots, nil
}

// BuildKZGBlock builds a KZG blob barycentric evaluation block.
//
// oldRoot is the state root BEFORE the current batch (rootHashBefore).
// The blob is deterministically derived from batchIdx.
// The evaluation point Z is derived via SHA-256(processID ‖ rootHashBefore ‖ commitment)
// as per circuit/src/kzg.rs.
func (e *Election) BuildKZGBlock(batchIdx int, oldRoot string) (*davinci.KZGRequest, error) {
	// Construct a deterministic blob for this batch.
	var blob types.Blob
	for i := 0; i < 16; i++ {
		big.NewInt(int64(batchIdx*16+i+1)).FillBytes(blob[i*32 : (i+1)*32])
	}

	kzgCommitment, err := blob.ComputeCommitment()
	if err != nil {
		return nil, fmt.Errorf("ComputeCommitment: %w", err)
	}
	var comm48 [48]byte
	copy(comm48[:], kzgCommitment[:])

	// Derive Z using SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48).
	// processID is the election's fixed identifier; rootHashBefore is the state
	// root before this batch. Both must be in big-endian hex format to match
	// the circuit's compute_z which converts FrRaw limbs to 32-byte BE.
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

// TallyAccumulator sums ElGamal ciphertexts across all batches so the final
// vote tally can be decrypted to verify the results.
type TallyAccumulator struct {
	// sumC1, sumC2 hold the accumulated sums for each of the 8 ballot fields.
	sumC1 [8]ecc.Point
	sumC2 [8]ecc.Point
	// count is the total number of ballots accumulated.
	count int
}

// NewTallyAccumulator creates a zero-initialized tally accumulator.
func NewTallyAccumulator() *TallyAccumulator {
	ta := &TallyAccumulator{}
	for i := 0; i < 8; i++ {
		// Use SetZero() to set the true BJJ identity (0, 1), not (0, 0).
		// bjjgnark.New() allocates (0, 0) which is NOT on the curve and acts
		// as an absorbing element in twisted-Edwards addition.
		c1 := bjjgnark.New()
		c1.SetZero()
		c2 := bjjgnark.New()
		c2.SetZero()
		ta.sumC1[i] = c1
		ta.sumC2[i] = c2
	}
	return ta
}

// Add accumulates a batch of re-encrypted ballots into the tally.
func (ta *TallyAccumulator) Add(ballots []*elgamal.Ballot) {
	for _, ballot := range ballots {
		for i := 0; i < 8; i++ {
			if ballot.Ciphertexts[i] == nil {
				continue
			}
			// sumC1 += c1; sumC2 += c2 (homomorphic ElGamal addition on BJJ).
			newC1 := bjjgnark.New()
			newC2 := bjjgnark.New()
			newC1.Add(ta.sumC1[i], ballot.Ciphertexts[i].C1)
			newC2.Add(ta.sumC2[i], ballot.Ciphertexts[i].C2)
			ta.sumC1[i] = newC1
			ta.sumC2[i] = newC2
		}
		ta.count++
	}
}

// Subtract removes a batch of re-encrypted ballots from the tally.
// This is used to cancel the contributions of ballots that were overwritten
// by a voter's later submission.
func (ta *TallyAccumulator) Subtract(ballots []*elgamal.Ballot) {
	for _, ballot := range ballots {
		for i := 0; i < 8; i++ {
			if ballot.Ciphertexts[i] == nil {
				continue
			}
			// newC1 = sumC1 - c1; newC2 = sumC2 - c2 (twisted-Edwards subtraction).
			negC1 := bjjgnark.New()
			negC2 := bjjgnark.New()
			negC1.Neg(ballot.Ciphertexts[i].C1)
			negC2.Neg(ballot.Ciphertexts[i].C2)
			newC1 := bjjgnark.New()
			newC2 := bjjgnark.New()
			newC1.Add(ta.sumC1[i], negC1)
			newC2.Add(ta.sumC2[i], negC2)
			ta.sumC1[i] = newC1
			ta.sumC2[i] = newC2
		}
		ta.count--
	}
}


// (the election private key) and returns the 8 vote field totals.
// Uses baby-step giant-step (BSGS) for discrete log recovery.
// The max value per field is count * maxFieldValue (maxFieldValue ≈ 15).
func (ta *TallyAccumulator) DecryptTally(privKey *big.Int) ([8]*big.Int, error) {
	var result [8]*big.Int
	// maxVal per field: count ballots, each with field values in [0, 15].
	maxVal := int64(ta.count) * 16
	for i := 0; i < 8; i++ {
		// M = C2 - privKey * C1.
		privC1 := bjjgnark.New()
		privC1.ScalarMult(ta.sumC1[i], privKey)

		negPrivC1 := bjjgnark.New()
		negPrivC1.Neg(privC1)

		M := bjjgnark.New()
		M.Add(ta.sumC2[i], negPrivC1)

		m, err := discreteLog(M, maxVal)
		if err != nil {
			return result, fmt.Errorf("field %d discrete log: %w", i, err)
		}
		result[i] = big.NewInt(m)
	}
	return result, nil
}

// discreteLog recovers m such that m*G == point, searching [0, maxVal].
// Uses baby-step giant-step (BSGS) for O(sqrt(maxVal)) time.
func discreteLog(point ecc.Point, maxVal int64) (int64, error) {
	if maxVal == 0 {
		return 0, nil
	}

	G := bjjgnark.New()
	G.SetGenerator()

	// Check if point is identity (m=0).
	// Must use SetZero() to get the true BJJ identity (0,1), not (0,0).
	identity := bjjgnark.New()
	identity.SetZero()
	if identity.Equal(point) {
		return 0, nil
	}

	// T = ceil(sqrt(maxVal+1)).
	T := int64(1)
	for T*T <= maxVal {
		T++
	}

	// Baby steps: table maps string repr → j for j*G, j in [0, T].
	baby := make(map[string]int64, T+1)
	// cur starts at identity (0,1); j=0 maps to identity, j=1 maps to G, etc.
	cur := bjjgnark.New()
	cur.SetZero()

	for j := int64(0); j <= T; j++ {
		x, y := cur.Point()
		key := x.String() + "," + y.String()
		baby[key] = j
		next := bjjgnark.New()
		next.Add(cur, G)
		cur = next
	}

	// Giant step: TG = T*G.
	TG := bjjgnark.New()
	TG.ScalarMult(G, big.NewInt(T))

	// Negate TG for gamma -= TG in each giant step.
	negTG := bjjgnark.New()
	negTG.Neg(TG)

	// Giant steps: gamma = point - i*TG.
	gamma := bjjgnark.New()
	gamma.Set(point)

	for i := int64(0); i <= T; i++ {
		x, y := gamma.Point()
		key := x.String() + "," + y.String()
		if j, ok := baby[key]; ok {
			m := i*T + j
			if m <= maxVal {
				return m, nil
			}
		}
		next := bjjgnark.New()
		next.Add(gamma, negTG)
		gamma = next
	}

	return 0, fmt.Errorf("discrete log not found in [0, %d]", maxVal)
}

// encKeyLeafValue computes the arbo leaf value for a BabyJubJub encryption key:
// SHA-256(X_BE32 || Y_BE32) → BigInt. This encoding matches the circuit's
// hash_enc_key function (circuit/src/main.rs), binding the re-encryption
// public key to the process config entry in the state tree.
func encKeyLeafValue(encKey *bjjgnark.BJJ) *big.Int {
	// Convert from Reduced Twisted Edwards to Twisted Edwards (circuit convention).
	rx, ry := encKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	// Serialize each coordinate as 32-byte big-endian.
	var buf [64]byte
	tx.FillBytes(buf[:32])
	ty.FillBytes(buf[32:])
	// SHA-256 → BigInt (stored as arbo LE bytes in the tree).
	digest := sha256.Sum256(buf[:])
	return new(big.Int).SetBytes(digest[:])
}

// ballotToFrStrings converts an ElGamal ballot (8 ciphertexts × 4 coordinates)
// to 32 big-endian hex strings suitable for BallotProofData.
// The order is: for each ciphertext i: C1.X, C1.Y, C2.X, C2.Y (TE coordinates).
func ballotToFrStrings(b *elgamal.Ballot) []string {
	out := make([]string, 32)
	for i := 0; i < 8; i++ {
		if b.Ciphertexts[i] == nil {
			// Zero ciphertext: identity point (0, 1) in TE
			out[i*4] = bigIntToFr32(big.NewInt(0))
			out[i*4+1] = bigIntToFr32(big.NewInt(1))
			out[i*4+2] = bigIntToFr32(big.NewInt(0))
			out[i*4+3] = bigIntToFr32(big.NewInt(1))
			continue
		}
		c1x, c1y := bjjPointToFr32Hex(b.Ciphertexts[i].C1)
		c2x, c2y := bjjPointToFr32Hex(b.Ciphertexts[i].C2)
		out[i*4] = c1x
		out[i*4+1] = c1y
		out[i*4+2] = c2x
		out[i*4+3] = c2y
	}
	return out
}
