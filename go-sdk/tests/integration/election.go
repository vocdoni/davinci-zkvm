// election.go manages the DAVINCI election state for integration testing.
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
	"os"
	"sort"

	"github.com/ethereum/go-ethereum/crypto"
	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
	nodesig "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/signatures/ethereum"
	spectestutil "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec/testutil"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/types"
	leanimt "github.com/vocdoni/lean-imt-go"
)

const (
	// procLevels is the number of levels in the arbo SHA-256 process state
	// tree (davinci-node StateTreeMaxLevels); keys are u64, hence keyLen.
	procLevels = 64
	keyLen     = 8
	// ballotMin is the minimum key for ballot SMT entries (matches circuit constant).
	ballotMin = uint64(0x10)
	// voteIDMin is the minimum key for voteID SMT entries (bit 63 set).
	voteIDMin = uint64(0x8000_0000_0000_0000)
	// keyResults is the arbo state tree key for the net accumulated Results ballot.
	keyResults = uint64(0x04)
)

// configKeys are the process config keys stored in the state tree at election setup.
// These are read-only per batch (verified via process read-proofs in the circuit).
var configKeys = []uint64{0x00, 0x02, 0x03, 0x06, 0x07}

// ballotVKLeaf returns the BallotVKHash config leaf (key 0x07) for the
// embedded circom ballot VK.
func ballotVKLeaf() *big.Int {
	v, err := davinci.BallotVKLeaf(ballotproof.CircomVerificationKey)
	if err != nil {
		panic(fmt.Sprintf("ballot VK leaf: %v", err))
	}
	return v
}

// ballotModeLeaf returns the packed BallotMode value stored at config key 0x02
// and its declared NumFields. The guest reads num_fields from the low byte of
// this leaf to drive its num_fields-aware reencryption/accumulator skip, so the
// padded ciphertext slots [NumFields, max) must carry the TE identity end-to-end.
func ballotModeLeaf() (*big.Int, int) {
	bm := spectestutil.FixedBallotMode()
	packed, err := bm.Pack()
	if err != nil {
		panic(fmt.Sprintf("pack fixed ballot mode: %v", err))
	}
	return packed, int(bm.NumFields)
}

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
	// Results is the net Fr-wise accumulator: Σ(all ballots) − Σ(overwritten ballots).
	// Uses coordinate-wise Fr add/sub to match the circuit's net accumulator.
	Results frAccumBallot
	// VotedBallots maps a ballot slot key → the last re-encrypted ballot stored
	// there. Used to detect overwrites and to subtract replaced ballots.
	VotedBallots map[uint64]wideBallot
	// SlotOverride replaces the slot the harness writes for a voter
	// (CensusIdx → key), for cheat tests that need a consistent state block
	// on a slot the guest must reject.
	SlotOverride map[int]uint64
	// RefreshExtra keys are appended to the silent-refresh selection, even
	// when the batch writes them, for cheat tests of the disjointness rule.
	RefreshExtra []uint64
	// CspKey is the CSP's secp256k1 private key (nil for Merkle census mode).
	CspKey *ecdsa.PrivateKey
	// CensusOrigin is the census type: 1 = lean-IMT, 4 = CSP ECDSA.
	CensusOrigin int
	// NumFields is the declared active ballot field count (BallotMode.NumFields).
	// Ciphertext slots [NumFields, NumFields_max) carry the TE identity so the
	// guest's num_fields-aware reencryption/accumulator can skip them.
	NumFields int
	// reencChain is the current batch's re-encryption chain. BuildReencBlock
	// creates it and stashes it here; BuildStateBlock continues it to derive
	// the silent-refresh scalars for the same batch.
	reencChain *elgamal.ReencChain

	// lastDA holds the DA blob inputs produced by BuildStateBlock for this
	// batch: vote id first-limbs, every (key, ballot) update — batch ballots
	// then silent refreshes — and the NEW net accumulator (BallotFields BE
	// hex coords). BuildKZGBlock reads them to build the transition blobs.
	// Rebuilt by every BuildStateBlock call; a BuildKZGBlock before the first
	// BuildStateBlock errors out.
	lastDA *daBatchState
}

// daBatchState is the per-batch DA blob input, stashed by BuildStateBlock and
// consumed by BuildKZGBlock. Kept private — tests that want to override any
// of these values must go through the RefreshKeysOverride knob or reach for
// the stash directly.
type daBatchState struct {
	VoteIDs     []uint64
	Updates     []davinci.SlotUpdate
	Accumulator []string
}

// NewElection creates a new test election with nVoters registered voters.
// It builds the process state tree (with config), the census IMT, and
// generates random ElGamal and ECDSA keys.
// voterSeed derives the signer seed of test voter i. It must be injective:
// the previous byte((i*7+j*3+42)%256) scheme repeated every 256 voters, so
// batches above 256 carried duplicate census leaves and the guest rejected
// them (FAIL_CENSUS) without anyone noticing.
func voterSeed(i int) []byte {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(i))
	h := sha256.Sum256(append([]byte("davinci-test-voter"), idx[:]...))
	return h[:]
}

func NewElection(nVoters int) (*Election, error) {
	// ProcessID (for ballot proofs and state tree key 0x00)
	var processID types.ProcessID
	copy(processID[:], "DAVINCI_INTEGRATION_TEST")
	processIDBI := new(big.Int).SetBytes(processID[:])

	// ElGamal encryption key
	// Generated BEFORE tree setup because the encryption key hash is stored
	// in the process config tree under key 0x03.
	// A seeded key (DAVINCI_TEST_ELECTION_SEED) makes the election, and so
	// every ballot proof, reproducible across runs; CachedBallotBatch keys
	// its on-disk cache on it.
	var (
		encKeyPoint ecc.Point
		encPrivKey  *big.Int
		err         error
	)
	if seed := os.Getenv("DAVINCI_TEST_ELECTION_SEED"); seed != "" {
		encKeyPoint, encPrivKey = elgamalKeyFromSeed(seed)
	} else {
		encKeyPoint, encPrivKey, err = elgamal.GenerateKey(bjjgnark.New())
		if err != nil {
			return nil, fmt.Errorf("elgamal.GenerateKey: %w", err)
		}
	}
	encKey := encKeyPoint.(*bjjgnark.BJJ)

	// Compute the encryption key leaf value: SHA-256(X_BE32 || Y_BE32).
	// This binds the re-encryption public key to the state tree, enforced by
	// the circuit's cross-block binding check (FAIL_BINDING).
	encKeyHashBI := encKeyLeafValue(encKey)

	// Process state tree
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
	bmLeaf, numFields := ballotModeLeaf()
	// Config values stored under their respective keys.
	// The circuit validates these keys and cross-checks processID and encKey.
	configValsBI := []*big.Int{
		processIDBI,      // 0x00 = ProcessID (must match STATETX block header)
		bmLeaf,           // 0x02 = BallotMode (low byte = NumFields, read by guest)
		encKeyHashBI,     // 0x03 = EncryptionKey (SHA-256 of pubkey coordinates)
		big.NewInt(0x01), // 0x06 = CensusOrigin
		ballotVKLeaf(),   // 0x07 = BallotVKHash (sha256 of VK wire bytes)
	}
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configValsBI[i]),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add config[%d]: %w", i, err)
		}
	}

	// Results (0x04): single net accumulator
	zeroAccum := newZeroFrAccum()
	zeroLeafBI := frAccumLeafHash(zeroAccum)
	if err := procTree.Add(
		arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(keyResults)),
		arbo.BigIntToBytes(bLen, zeroLeafBI),
	); err != nil {
		return nil, fmt.Errorf("procTree.Add results key 0x%02x: %w", keyResults, err)
	}

	rootBytes, err := procTree.Root()
	if err != nil {
		return nil, fmt.Errorf("initial root: %w", err)
	}
	oldRoot := "0x" + hex.EncodeToString(pad32(rootBytes))

	// Voters
	voters := make([]*Voter, nVoters)
	for i := 0; i < nVoters; i++ {
		seed := voterSeed(i)
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

	// Census lean-IMT
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
		Results:      newZeroFrAccum(),
		VotedBallots: make(map[uint64]wideBallot),
		CensusOrigin: 1,
		NumFields:    numFields,
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
	processID[20] = 0x01                       // version bytes (must be non-zero)
	processID[21] = 0x00
	processID[22] = 0x00
	processID[23] = 0x04 // censusOrigin hint
	processID[24] = 0x00 // nonce
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
	bmLeaf, numFields := ballotModeLeaf()
	configValsBI := []*big.Int{
		processIDBI,      // 0x00 = ProcessID
		bmLeaf,           // 0x02 = BallotMode (low byte = NumFields, read by guest)
		encKeyHashBI,     // 0x03 = EncryptionKey hash
		big.NewInt(0x04), // 0x06 = CensusOrigin = CSP
		ballotVKLeaf(),   // 0x07 = BallotVKHash (sha256 of VK wire bytes)
	}
	for i, k := range configKeys {
		if err := procTree.Add(
			arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configValsBI[i]),
		); err != nil {
			return nil, fmt.Errorf("procTree.Add config[%d]: %w", i, err)
		}
	}

	// Results (0x04): single net accumulator.
	zeroAccum := newZeroFrAccum()
	zeroLeafBI := frAccumLeafHash(zeroAccum)
	if err := procTree.Add(
		arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(keyResults)),
		arbo.BigIntToBytes(bLen, zeroLeafBI),
	); err != nil {
		return nil, fmt.Errorf("procTree.Add results key 0x%02x: %w", keyResults, err)
	}

	rootBytes, err := procTree.Root()
	if err != nil {
		return nil, fmt.Errorf("initial root: %w", err)
	}
	oldRoot := "0x" + hex.EncodeToString(pad32(rootBytes))

	// Voters (same key generation as Merkle mode).
	voters := make([]*Voter, nVoters)
	for i := 0; i < nVoters; i++ {
		seed := voterSeed(i)
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
		Results:      newZeroFrAccum(),
		VotedBallots: make(map[uint64]wideBallot),
		CspKey:       cspKey,
		CensusOrigin: 4,
		NumFields:    numFields,
	}, nil
}

// BuildCspData builds the CSP ECDSA census block for a batch of voters.
// Each voter's eligibility is signed by the CSP key using Ethereum personal-sign:
//
//	message = "\x19Ethereum Signed Message:\n92" || processID(32BE) || address(20) || weight(32BE) || index(8BE)
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
		// sig = [R(32) || S(32) || V(1)] where V is 0/1 (geth's go-ethereum convention).
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		recid := sig[64]

		proofs[i] = davinci.CspProof{
			R:            fmt.Sprintf("0x%064x", r),
			S:            fmt.Sprintf("0x%064x", s),
			Recid:        recid,
			VoterAddress: fmt.Sprintf("0x%040x", new(big.Int).SetBytes(v.AddressBytes)),
			Weight:       fmt.Sprintf("0x%064x", v.Weight),
			Index:        uint64(v.CensusIdx),
		}
	}

	// The CSP public key is recovered per-entry inside the circuit; no longer
	// transmitted alongside the per-voter proofs.
	return &davinci.CspData{Proofs: proofs}, nil
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
// It inserts or updates each voter's voteID and ballot key in the process state tree,
// and updates the single net Results leaf (key 0x04) with the homomorphic net sum
// Σ(all re-encrypted ballots) − Σ(overwritten old ballots).
// Returns the StateTransitionData, the list of overwritten (old) re-encrypted ballots
// (may be empty), and an error.  e.OldRoot is advanced to the new root on success.
// reencBallots must have the same length as ballotResults.
func (e *Election) BuildStateBlock(batchVoters []*Voter, ballotResults []*BallotResult, reencBallots []wideBallot) (*davinci.StateTransitionData, []wideBallot, error) {
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

	// Snapshot occupied-slot count and the pre-batch VotedBallots keys before the
	// ballot chain mutates the map. Refresh candidates = pre-batch slots not
	// touched by this batch.
	occupiedBefore := len(e.VotedBallots)
	preBatchSlots := make([]uint64, 0, occupiedBefore)
	for key := range e.VotedBallots {
		preBatchSlots = append(preBatchSlots, key)
	}

	// Insert voteID keys for each voter (always a fresh INSERT => even for overwrites,
	// each ballot submission carries a new unique voteID).
	var voteIDChain []davinci.SmtEntry
	for i, res := range ballotResults {
		entry, err := buildArboInsertEntry(
			e.ProcTree,
			new(big.Int).SetUint64(res.VoteID),
			big.NewInt(davinci.VoteIDLeafValue),
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
	var overwrittenBallots []wideBallot
	for i, v := range batchVoters {
		key, err := e.slotKey(v)
		if err != nil {
			return nil, nil, err
		}
		newLeafVal := ballotLeafHash(reencBallots[i])

		if oldBallot, isOverwrite := e.VotedBallots[key]; isOverwrite {
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
		// Record the slot's latest re-encrypted ballot for future overwrite detection.
		e.VotedBallots[key] = reencBallots[i]
	}

	// Snapshot old accumulator for BallotProofData before mutation.
	oldResults := e.Results

	// net = old + Σ(all ballots) − Σ(overwritten ballots), coordinate-wise on BJJ.
	// Refresh deltas (added below) also fold into newResults before the leaf hash.
	newResults := e.Results
	for _, rb := range reencBallots {
		newResults = frAccumAdd(newResults, frAccumFromBallot(rb))
	}
	for _, ob := range overwrittenBallots {
		newResults = frAccumSub(newResults, frAccumFromBallot(ob))
	}

	// Silent-refresh chain: re-randomize a target number of untouched occupied
	// slots so overwrites don't stand out. Sits between the ballot chain and the
	// Results transition; scalars continue the batch's re-encryption chain.
	batchSlots := make(map[uint64]bool, n)
	for _, v := range batchVoters {
		key, err := e.slotKey(v)
		if err != nil {
			return nil, nil, err
		}
		batchSlots[key] = true
	}
	candidates := make([]uint64, 0, len(preBatchSlots))
	for _, key := range preBatchSlots {
		if !batchSlots[key] {
			candidates = append(candidates, key)
		}
	}
	w := len(overwrittenBallots)
	target := davinci.RefreshTarget(n, w, occupiedBefore)
	selected, err := sampleN(candidates, target)
	if err != nil {
		return nil, nil, fmt.Errorf("refresh sample: %w", err)
	}
	selected = append(selected, e.RefreshExtra...)
	// Sort by ballot key ascending; the guest enforces strictly increasing keys.
	items := selected
	sort.Slice(items, func(i, j int) bool { return items[i] < items[j] })

	if len(items) > 0 && e.reencChain == nil {
		return nil, nil, fmt.Errorf("refresh needs seeded reencChain; call BuildReencBlock first")
	}

	var refreshChain []davinci.SmtEntry
	var refreshedBallots []wideBallot
	for _, key := range items {
		oldWide := e.VotedBallots[key]
		oldBallot := wideBallotToElgamalBallot(oldWide)
		newBallot, err := oldBallot.ReencryptChained(e.EncKey, e.reencChain, e.NumFields)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh reencrypt[%#x]: %w", key, err)
		}
		newWide := make(wideBallot, NumFields)
		for i := 0; i < NumFields; i++ {
			if i < e.NumFields {
				newWide[i] = newBallot.Ciphertexts[i]
			} else {
				newWide[i] = identityCiphertext()
			}
		}
		newLeafVal := ballotLeafHash(newWide)
		entry, err := buildArboUpdateEntry(
			e.ProcTree,
			new(big.Int).SetUint64(key),
			newLeafVal,
			procLevels,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("refresh update[%#x]: %w", key, err)
		}
		refreshChain = append(refreshChain, entry)
		refreshedBallots = append(refreshedBallots, oldWide)

		// Homomorphic re-encryption doesn't move the plaintext, but the leaf
		// value changes, so the net accumulator gets add(new) − sub(old).
		newResults = frAccumAdd(newResults, frAccumFromBallot(newWide))
		newResults = frAccumSub(newResults, frAccumFromBallot(oldWide))

		// Advance the stored ballot to its refreshed value.
		e.VotedBallots[key] = newWide
	}

	newResultsLeaf := frAccumLeafHash(newResults)

	resultsEntry, err := buildArboUpdateEntry(
		e.ProcTree,
		new(big.Int).SetUint64(keyResults),
		newResultsLeaf,
		procLevels,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Results update: %w", err)
	}
	e.Results = newResults

	// Read new root AFTER all insertions + Results update.
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
	refreshedBallotStrs := make([][]string, len(refreshedBallots))
	for i, rb := range refreshedBallots {
		refreshedBallotStrs[i] = ballotToFrStrings(rb)
	}
	ballotProofs := &davinci.BallotProofData{
		OldResults:         frAccumToStrings(oldResults),
		VoterBallots:       voterBallotStrs,
		OverwrittenBallots: overwrittenBallotStrs,
		RefreshedBallots:   refreshedBallotStrs,
	}

	// Stash the DA blob input the guest will rebuild from state so
	// BuildKZGBlock can produce commitments and openings byte-identical to
	// what the guest hashes. Batch ballot updates come first, then silent
	// refreshes; the cell builder stable-sorts everything by key anyway.
	da := &daBatchState{
		VoteIDs:     make([]uint64, n),
		Updates:     make([]davinci.SlotUpdate, 0, n+len(items)),
		Accumulator: frAccumToStrings(newResults),
	}
	for i, res := range ballotResults {
		da.VoteIDs[i] = res.VoteID
	}
	for i, v := range batchVoters {
		key, err := e.slotKey(v)
		if err != nil {
			return nil, nil, err
		}
		da.Updates = append(da.Updates, davinci.SlotUpdate{
			Key:    key,
			Ballot: voterBallotStrs[i],
		})
	}
	for _, key := range items {
		da.Updates = append(da.Updates, davinci.SlotUpdate{
			Key:    key,
			Ballot: ballotToFrStrings(e.VotedBallots[key]), // refreshed value
		})
	}
	e.lastDA = da

	return &davinci.StateTransitionData{
		VotersCount:      uint64(n),
		OverwrittenCount: uint64(len(overwrittenBallots)),
		OccupiedBefore:   uint64(occupiedBefore),
		ProcessID:        e.processIDArboHex(),
		OldStateRoot:     oldRoot,
		NewStateRoot:     newRoot,
		VoteIDSmt:        voteIDChain,
		BallotSmt:        ballotChain,
		RefreshSmt:       refreshChain,
		ResultsSmt:       &resultsEntry,
		ProcessSmt:       processSmtProofs,
		BallotProofs:     ballotProofs,
	}, overwrittenBallots, nil
}

// slotKey is the ballot slot the guest will derive for v: from the census
// index the CSP signed, or from the voter's address (davinci.SlotKey).
func (e *Election) slotKey(v *Voter) (uint64, error) {
	if key, ok := e.SlotOverride[v.CensusIdx]; ok {
		return key, nil
	}
	if e.CspKey != nil {
		return davinci.CSPSlotKey(uint64(v.CensusIdx)), nil
	}
	if len(v.AddressBytes) != 20 {
		return 0, fmt.Errorf("slot of voter %d: address has %d bytes", v.CensusIdx, len(v.AddressBytes))
	}
	return davinci.SlotKey([20]byte(v.AddressBytes)), nil
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
			Root: bigIntToFr32(root),
			Leaf: bigIntToFr32(proof.Leaf),
			// PathBits, not LeafIndex: the guest reads one path bit per
			// sibling and lean-IMT omits siblings on levels with a lone node,
			// so the two differ whenever the census size is not a power of two.
			Index:    proof.PathBits,
			Siblings: sibs,
		}
	}
	return proofs, nil
}

// BuildReencBlock builds the REENCBLK protocol block for a batch. It draws
// one sequencer-private seed, seeds the shared re-encryption chain with it
// and the state root before the batch, and re-encrypts every voter's active
// ciphertexts using the chained scalars. oldRoot is the state root before
// this batch (the same value the caller passes to BuildKZGBlock); it must
// match the STATETX old_root the batch is proved against, or the guest
// will derive a different scalar chain and reject the batch.
func (e *Election) BuildReencBlock(oldRoot string, ballotResults []*BallotResult) (*davinci.ReencryptionData, []wideBallot, error) {
	pkX, pkY := bjjPointToFr32Hex(e.EncKey)
	entries := make([]davinci.ReencryptionEntry, len(ballotResults))
	reencBallots := make([]wideBallot, len(ballotResults))

	nf := e.NumFields // active ciphertext count; slots [nf, NumFields) stay TE identity

	// TE identity (0,1) hex for padded slots. The guest reads num_fields from the
	// BallotMode leaf, asserts original == reencrypted == identity on every padded
	// slot, and skips the per-field EC work there.
	idZeroHex := bigIntToFr32(big.NewInt(0))
	idOneHex := bigIntToFr32(big.NewInt(1))
	idEntry := davinci.BjjCiphertext{
		C1: davinci.BjjPoint{X: idZeroHex, Y: idOneHex},
		C2: davinci.BjjPoint{X: idZeroHex, Y: idOneHex},
	}

	// One seed per batch; the chain binds every derived scalar to oldRoot so
	// no scalar repeats within or across transitions.
	seed, err := rand.Int(rand.Reader, e.EncKey.Order())
	if err != nil {
		return nil, nil, fmt.Errorf("rand reenc seed: %w", err)
	}
	oldRootInt, err := davinci.LeHexToBigInt(oldRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("parse oldRoot: %w", err)
	}
	reencChain := elgamal.NewReencChain(seed, oldRootInt)
	// Stash the chain so BuildStateBlock can continue it for silent-refresh
	// scalars (guest expects one shared chain: batch entries then refreshes).
	e.reencChain = reencChain

	for idx, res := range ballotResults {
		// Reconstruct the elgamal.Ballot: active fields from the cast ballot,
		// padded fields as the TE identity (so re-encryption leaves them identity).
		// SetPoint returns a NEW point (doesn't modify in-place), so capture it.
		ballot := elgamal.NewBallot(bjjgnark.New())
		for i := 0; i < NumFields; i++ {
			if i < nf {
				c1 := bjjgnark.New().SetPoint(res.RawBallot.C1X[i], res.RawBallot.C1Y[i])
				c2 := bjjgnark.New().SetPoint(res.RawBallot.C2X[i], res.RawBallot.C2Y[i])
				ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
			} else {
				ballot.Ciphertexts[i] = identityCiphertext()
			}
		}

		reencBallot, err := ballot.ReencryptChained(e.EncKey, reencChain, nf)
		if err != nil {
			return nil, nil, fmt.Errorf("ReencryptChained[%d]: %w", idx, err)
		}

		// Wide carrier: active re-encrypted fields + TE identity padding.
		// ReencryptChained already copies padded slots unchanged, but the
		// tally accumulator wants the shared identityCiphertext instance.
		wide := make(wideBallot, NumFields)
		for i := 0; i < NumFields; i++ {
			if i < nf {
				wide[i] = reencBallot.Ciphertexts[i]
			} else {
				wide[i] = identityCiphertext()
			}
		}
		reencBallots[idx] = wide

		var entry davinci.ReencryptionEntry
		for i := 0; i < NumFields; i++ {
			if i >= nf {
				entry.Original[i] = idEntry
				entry.Reencrypted[i] = idEntry
				continue
			}
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
		Seed:           bigIntToFr32(seed),
		Entries:        entries,
	}, reencBallots, nil
}

// identityCiphertext returns the TE identity ElGamal ciphertext ((0,1),(0,1)),
// used to pad ciphertext slots beyond the declared NumFields. SetZero gives the
// BJJ identity (0,1); New() would give (0,0), which is off-curve.
func identityCiphertext() *elgamal.Ciphertext {
	c1 := bjjgnark.New()
	c1.SetZero()
	c2 := bjjgnark.New()
	c2.SetZero()
	return &elgamal.Ciphertext{C1: c1, C2: c2}
}

// BuildKZGBlock builds the DA blob binding for the batch that BuildStateBlock
// just applied. It rebuilds the exact cell stream the guest constructs from
// verified state (vote ids, batch ballot updates, silent-refresh updates, and
// the NEW net accumulator), splits it into EIP-4844 blobs, commits and opens
// each at z_b = SHA-256(processID || rootBefore || commitment_b) mod r_bls.
// Returns the commitments-only KZGRequest plus the full TransitionBlobs so
// settlement tests can feed the on-chain point-evaluation precompile.
// oldRoot is the state root BEFORE the batch (rootHashBefore for z).
func (e *Election) BuildKZGBlock(oldRoot string) (*davinci.KZGRequest, *davinci.TransitionBlobs, error) {
	if e.lastDA == nil {
		return nil, nil, fmt.Errorf("BuildKZGBlock: no batch stashed — call BuildStateBlock first")
	}
	pidHex := e.ProcessIDHex()
	rootBEHex := arboHexToBEHex(oldRoot)
	pidBytes, err := hex.DecodeString(trimHexKZG(pidHex))
	if err != nil {
		return nil, nil, fmt.Errorf("processID hex: %w", err)
	}
	rootBytes, err := hex.DecodeString(trimHexKZG(rootBEHex))
	if err != nil {
		return nil, nil, fmt.Errorf("rootBefore hex: %w", err)
	}
	var pid32, rhb32 [32]byte
	copy(pid32[32-len(pidBytes):], pidBytes)
	copy(rhb32[32-len(rootBytes):], rootBytes)

	tb, err := davinci.BuildTransitionBlobs(
		e.NumFields,
		pid32, rhb32,
		e.lastDA.VoteIDs,
		e.lastDA.Updates,
		e.lastDA.Accumulator,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("BuildTransitionBlobs: %w", err)
	}
	return tb.Request(pidHex, rootBEHex), tb, nil
}

// trimHexKZG strips an optional 0x/0X prefix.
func trimHexKZG(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
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
		// Use SetZero() to get the true BJJ identity (0, 1).
		// New() allocates (0, 0), which is NOT on the curve and acts
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
// Only the 8 real fields contribute; synthetic fields (i >= 8) are
// encrypted-zero and irrelevant to the decrypted tally.
func (ta *TallyAccumulator) Add(ballots []wideBallot) {
	for _, ballot := range ballots {
		for i := 0; i < 8; i++ {
			if ballot[i] == nil {
				continue
			}
			// sumC1 += c1; sumC2 += c2 (homomorphic ElGamal addition on BJJ).
			newC1 := bjjgnark.New()
			newC2 := bjjgnark.New()
			newC1.Add(ta.sumC1[i], ballot[i].C1)
			newC2.Add(ta.sumC2[i], ballot[i].C2)
			ta.sumC1[i] = newC1
			ta.sumC2[i] = newC2
		}
		ta.count++
	}
}

// Subtract removes a batch of re-encrypted ballots from the tally.
// This is used to cancel the contributions of ballots that were overwritten
// by a voter's later submission.
func (ta *TallyAccumulator) Subtract(ballots []wideBallot) {
	for _, ballot := range ballots {
		for i := 0; i < 8; i++ {
			if ballot[i] == nil {
				continue
			}
			// newC1 = sumC1 - c1; newC2 = sumC2 - c2 (twisted-Edwards subtraction).
			negC1 := bjjgnark.New()
			negC2 := bjjgnark.New()
			negC1.Neg(ballot[i].C1)
			negC2.Neg(ballot[i].C2)
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

// ballotToFrStrings converts a wideBallot (NumFields ciphertexts × 4 coordinates)
// to BallotFields big-endian hex strings suitable for BallotProofData.
// The order is: for each ciphertext i: C1.X, C1.Y, C2.X, C2.Y (TE coordinates).
func ballotToFrStrings(b wideBallot) []string {
	out := make([]string, BallotFields)
	for i := 0; i < NumFields; i++ {
		if b[i] == nil {
			// Zero ciphertext: identity point (0, 1) in TE
			out[i*4] = bigIntToFr32(big.NewInt(0))
			out[i*4+1] = bigIntToFr32(big.NewInt(1))
			out[i*4+2] = bigIntToFr32(big.NewInt(0))
			out[i*4+3] = bigIntToFr32(big.NewInt(1))
			continue
		}
		c1x, c1y := bjjPointToFr32Hex(b[i].C1)
		c2x, c2y := bjjPointToFr32Hex(b[i].C2)
		out[i*4] = c1x
		out[i*4+1] = c1y
		out[i*4+2] = c2x
		out[i*4+3] = c2y
	}
	return out
}

// wideBallotToElgamalBallot lifts a wideBallot into an *elgamal.Ballot. Empty
// slots become the TE identity so ReencryptChained can copy them unchanged.
func wideBallotToElgamalBallot(wb wideBallot) *elgamal.Ballot {
	b := elgamal.NewBallot(bjjgnark.New())
	for i := 0; i < NumFields; i++ {
		if wb[i] != nil {
			b.Ciphertexts[i] = wb[i]
		} else {
			b.Ciphertexts[i] = identityCiphertext()
		}
	}
	return b
}

// sampleN picks k distinct entries from cand uniformly at random using
// crypto/rand. Returns all of cand when k >= len(cand). The returned slice is
// a permutation prefix and is safe to sort by the caller.
func sampleN[T any](cand []T, k int) ([]T, error) {
	if k <= 0 {
		return nil, nil
	}
	if k >= len(cand) {
		out := make([]T, len(cand))
		copy(out, cand)
		return out, nil
	}
	pool := make([]T, len(cand))
	copy(pool, cand)
	for i := 0; i < k; i++ {
		max := big.NewInt(int64(len(pool) - i))
		j, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("rand.Int: %w", err)
		}
		ji := int(j.Int64()) + i
		pool[i], pool[ji] = pool[ji], pool[i]
	}
	return pool[:k], nil
}

// elgamalKeyFromSeed derives a fixed ElGamal key from a test seed. Test use
// only: it exists so generated ballots can be cached across runs.
func elgamalKeyFromSeed(seed string) (ecc.Point, *big.Int) {
	h := sha256.Sum256([]byte("davinci-test-election|" + seed))
	curve := bjjgnark.New()
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, curve.Order())
	if d.Sign() == 0 {
		d.SetInt64(1)
	}
	pub := curve.New()
	pub.SetGenerator()
	pub.ScalarMult(pub, d)
	return pub, d
}
