// state.go owns the process state tree for a chained-mode election:
// genesis initialization from the immutable config, per-batch SMT
// transitions, homomorphic results accumulation and the decrypted-results
// payload for the finalize step.
package chain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"

	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/elgamal"
)

const (
	// procLevels is the number of levels in the arbo SHA-256 state tree
	// (davinci-node StateTreeMaxLevels). Keys are u64, hence keyLen.
	procLevels = 64
	keyLen     = 8
	// ballotMin is the minimum key for ballot SMT entries.
	ballotMin = uint64(0x10)
	// keyResults is the net accumulated results leaf.
	keyResults = uint64(0x04)
)

// configKeys are the process config keys inserted at genesis, in the
// order the aggregator guest recomputes the genesis root.
var configKeys = []uint64{0x00, 0x02, 0x03, 0x06, 0x07}

// Config is the immutable election configuration. The aggregator guest
// recomputes the genesis state root from these values and commits their
// hash, so they cannot change for the lifetime of the chain.
type Config struct {
	// ProcessID is the DAVINCI process identifier (state tree key 0x00).
	ProcessID *big.Int
	// BallotMode is the ballot mode word (key 0x02).
	BallotMode *big.Int
	// EncKey is the BabyJubJub ElGamal encryption public key. Its
	// SHA-256(X||Y) hash is stored under key 0x03.
	EncKey *bjjgnark.BJJ
	// CensusOrigin is the census type (key 0x06): 1 = lean-IMT, 4 = CSP.
	CensusOrigin uint64
	// CensusRoot is the census commitment checked against every batch
	// proof's publics.
	CensusRoot *big.Int
	// BallotVKHash is sha256 over the ballot Groth16 VK wire bytes
	// (key 0x07), from davinci.BallotVKLeaf. Pins the VK for the
	// lifetime of the process.
	BallotVKHash *big.Int
}

// Vote is one validated ballot ready for state application. Ballot proof
// and census/signature material travel separately in the ProveRequest;
// the state tree only needs the key parts and the ciphertexts.
type Vote struct {
	// Slot is the voter's ballot slot key: davinci.SlotKey(address) (or
	// CensusProof.SlotKey()) for a Merkle census, davinci.CSPSlotKey(index)
	// for a CSP census. The guest derives the same key and rejects any other.
	Slot uint64
	// VoteID is the unique vote identifier key (bit 63 set).
	VoteID uint64
	// Ballot is the voter-encrypted ElGamal ballot (before re-encryption).
	Ballot *elgamal.Ballot
}

// State is the sequencer's process state tree plus the running results
// accumulators. It mirrors exactly what the batch circuit verifies, so
// every ApplyBatch output is provable as-is.
type State struct {
	cfg  Config
	tree *arbo.Tree
	root string // current root, 0x-prefixed arbo LE hex
	// votedBallots is keyed by the ballot slot, so two votes only count as
	// an overwrite when they target the exact same leaf.
	results      accumBallot
	votedBallots map[uint64]*elgamal.Ballot
	voters       uint64
	overwrites   uint64
}

// NewState builds the genesis state tree from cfg: the five config
// leaves plus the identity net Results leaf. The resulting root
// matches the aggregator guest's in-circuit genesis computation.
func NewState(cfg Config) (*State, error) {
	if cfg.ProcessID == nil || cfg.BallotMode == nil || cfg.EncKey == nil || cfg.CensusRoot == nil || cfg.BallotVKHash == nil {
		return nil, fmt.Errorf("chain.Config: ProcessID, BallotMode, EncKey, CensusRoot and BallotVKHash are required")
	}
	if nf := cfg.numFields(); nf < 1 || nf > davinci.NumFields {
		return nil, fmt.Errorf("chain.Config: BallotMode declares num_fields = %d, want 1..%d", nf, davinci.NumFields)
	}
	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    procLevels,
		HashFunction: arbo.HashFunctionSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("arbo.NewTree: %w", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	configVals := []*big.Int{
		cfg.ProcessID,
		cfg.BallotMode,
		encKeyLeafValue(cfg.EncKey),
		new(big.Int).SetUint64(cfg.CensusOrigin),
		cfg.BallotVKHash,
	}
	for i, k := range configKeys {
		if err := tree.Add(
			arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(k)),
			arbo.BigIntToBytes(bLen, configVals[i]),
		); err != nil {
			return nil, fmt.Errorf("genesis config leaf 0x%02x: %w", k, err)
		}
	}
	zeroLeaf := accumLeafHash(newIdentityAccum())
	if err := tree.Add(
		arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(keyResults)),
		arbo.BigIntToBytes(bLen, zeroLeaf),
	); err != nil {
		return nil, fmt.Errorf("genesis results leaf 0x%02x: %w", keyResults, err)
	}

	rootBytes, err := tree.Root()
	if err != nil {
		return nil, fmt.Errorf("genesis root: %w", err)
	}
	return &State{
		cfg:          cfg,
		tree:         tree,
		root:         "0x" + hex.EncodeToString(pad32(rootBytes)),
		results:      newIdentityAccum(),
		votedBallots: make(map[uint64]*elgamal.Ballot),
	}, nil
}

// Root returns the current state root as 0x-prefixed arbo LE hex.
func (s *State) Root() string { return s.root }

// Voters returns the total applied (vote, overwrite) counts.
func (s *State) Voters() (total, overwrites uint64) { return s.voters, s.overwrites }

// ChainConfig converts the config to the service wire format (arbo LE hex).
func (s *State) ChainConfig() *davinci.ChainConfig {
	le32 := func(bi *big.Int) string {
		return hex.EncodeToString(arbo.BigIntToBytes(32, bi))
	}
	rx, ry := s.cfg.EncKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	return &davinci.ChainConfig{
		ProcessID:    le32(s.cfg.ProcessID),
		BallotMode:   le32(s.cfg.BallotMode),
		EncX:         le32(tx),
		EncY:         le32(ty),
		CensusOrigin: s.cfg.CensusOrigin,
		CensusRoot:   le32(s.cfg.CensusRoot),
		BallotVKHash: le32(s.cfg.BallotVKHash),
	}
}

// ApplyBatch re-encrypts each vote's ballot and applies the batch to the
// state tree: voteID inserts, ballot insert/update per voter, results
// accumulator updates. Returns the STATETX and REENCBLK blocks ready to
// attach to a ProveRequest. The state root advances on success.
//
// On error the tree may be partially mutated; discard the State and
// restore it from a Snapshot.
func (s *State) ApplyBatch(votes []Vote) (*davinci.StateTransitionData, *davinci.ReencryptionData, error) {
	n := len(votes)
	if n == 0 {
		return nil, nil, fmt.Errorf("empty batch")
	}
	if n > davinci.MaxBatchSize {
		return nil, nil, fmt.Errorf("batch size %d exceeds MaxBatchSize (%d)", n, davinci.MaxBatchSize)
	}
	// occupiedBefore counts distinct ballot slots present before this batch
	// touches the map. Equivalent to s.voters - s.overwrites, but the map
	// size is the ground truth (both counters are derived from it).
	occupiedBefore := len(s.votedBallots)
	seen := make(map[uint64]int, n)
	for i, v := range votes {
		if v.Slot < davinci.BallotMin || v.Slot > davinci.BallotMax {
			return nil, nil, fmt.Errorf("vote[%d]: slot %#x outside the ballot namespace", i, v.Slot)
		}
		// The guest rejects a batch that writes one slot twice.
		if j, dup := seen[v.Slot]; dup {
			return nil, nil, fmt.Errorf("vote[%d]: slot %#x already written by vote[%d]", i, v.Slot, j)
		}
		seen[v.Slot] = i
	}
	bLen := arbo.HashFunctionSha256.Len()

	// Re-encryption block first: the state tree stores the re-encrypted
	// ballot leaf hashes. One secret seed per batch drives the whole
	// scalar chain, bound to the state root before the batch — padded
	// slots [nf, NumFields) are copied unchanged and stay TE identity,
	// which the guest asserts before skipping their per-field work.
	nf := s.cfg.numFields()
	pkX, pkY := bjjPointToFr32Hex(s.cfg.EncKey)
	seed, err := rand.Int(rand.Reader, s.cfg.EncKey.Order())
	if err != nil {
		return nil, nil, fmt.Errorf("rand reenc seed: %w", err)
	}
	oldRootInt, err := davinci.LeHexToBigInt(s.root)
	if err != nil {
		return nil, nil, fmt.Errorf("parse oldRoot: %w", err)
	}
	chain := elgamal.NewReencChain(seed, oldRootInt)
	reencEntries := make([]davinci.ReencryptionEntry, n)
	reencBallots := make([]*elgamal.Ballot, n)
	for idx, v := range votes {
		reenc, err := v.Ballot.ReencryptChained(s.cfg.EncKey, chain, nf)
		if err != nil {
			return nil, nil, fmt.Errorf("reencrypt[%d]: %w", idx, err)
		}
		reencBallots[idx] = reenc

		var entry davinci.ReencryptionEntry
		for i := 0; i < davinci.NumFields; i++ {
			oc1x, oc1y := bjjPointToFr32Hex(v.Ballot.Ciphertexts[i].C1)
			oc2x, oc2y := bjjPointToFr32Hex(v.Ballot.Ciphertexts[i].C2)
			rc1x, rc1y := bjjPointToFr32Hex(reenc.Ciphertexts[i].C1)
			rc2x, rc2y := bjjPointToFr32Hex(reenc.Ciphertexts[i].C2)
			entry.Original[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: oc1x, Y: oc1y},
				C2: davinci.BjjPoint{X: oc2x, Y: oc2y},
			}
			entry.Reencrypted[i] = davinci.BjjCiphertext{
				C1: davinci.BjjPoint{X: rc1x, Y: rc1y},
				C2: davinci.BjjPoint{X: rc2x, Y: rc2y},
			}
		}
		reencEntries[idx] = entry
	}

	processSmtProofs, err := buildArboReadProofs(s.tree, configKeys, bLen, procLevels)
	if err != nil {
		return nil, nil, fmt.Errorf("config read proofs: %w", err)
	}

	// VoteID inserts: every submission carries a fresh unique voteID.
	voteIDChain := make([]davinci.SmtEntry, 0, n)
	for i, v := range votes {
		entry, err := buildArboInsertEntry(
			s.tree,
			new(big.Int).SetUint64(v.VoteID),
			big.NewInt(davinci.VoteIDLeafValue),
			procLevels,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("voteID insert[%d]: %w", i, err)
		}
		voteIDChain = append(voteIDChain, entry)
	}

	// Ballot insert (first vote) or update (overwrite).
	ballotChain := make([]davinci.SmtEntry, 0, n)
	var overwritten []*elgamal.Ballot
	batchKeys := make(map[uint64]struct{}, n)
	for i, v := range votes {
		key := v.Slot
		leaf := ballotLeafHash(reencBallots[i])
		if old, isOverwrite := s.votedBallots[key]; isOverwrite {
			entry, err := buildArboUpdateEntry(s.tree, new(big.Int).SetUint64(key), leaf, procLevels)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot update[%d]: %w", i, err)
			}
			ballotChain = append(ballotChain, entry)
			overwritten = append(overwritten, old)
		} else {
			entry, err := buildArboInsertEntry(s.tree, new(big.Int).SetUint64(key), leaf, procLevels)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot insert[%d]: %w", i, err)
			}
			ballotChain = append(ballotChain, entry)
		}
		batchKeys[key] = struct{}{}
		s.votedBallots[key] = reencBallots[i]
	}

	// Net results accumulator (BabyJubJub point add/sub per ciphertext):
	// NewResults = OldResults + Σ(all ballots) − Σ(overwritten ballots) +
	// Σ(refresh deltas). The refresh loop below extends the seed chain and
	// folds each delta (new_i - old_i) into newResults so the guest and host
	// agree on the accumulator that the Results transition will commit.
	oldResults := s.results

	newResults := s.results
	for _, rb := range reencBallots {
		newResults = accumAdd(newResults, accumFromBallot(rb))
	}
	for _, ob := range overwritten {
		newResults = accumSub(newResults, accumFromBallot(ob))
	}

	// Silent refresh pass: re-randomize a target number of occupied ballot
	// slots the batch itself did not write. Selection is uniform without
	// replacement over the candidate slots, drawn from crypto/rand — never
	// derived, never persisted. Refresh entries continue the same seed chain
	// as the batch's own re-encryptions, so no scalar is reused.
	w := len(overwritten)
	target := davinci.RefreshTarget(n, w, occupiedBefore)
	var (
		refreshChain     []davinci.SmtEntry
		refreshedOldStrs [][]string
	)
	if target > 0 {
		// Candidates: occupied keys before the batch, minus the keys this
		// batch wrote. Sorted ascending so the sampling and iteration order
		// are deterministic once the crypto/rand draws are fixed.
		cand := make([]uint64, 0, occupiedBefore-w)
		for key := range s.votedBallots {
			if _, hit := batchKeys[key]; hit {
				continue
			}
			cand = append(cand, key)
		}
		sort.Slice(cand, func(i, j int) bool { return cand[i] < cand[j] })

		var chosen []uint64
		if len(cand) <= target {
			// Full churn: refresh every candidate the tree exposes.
			chosen = cand
		} else {
			// Fisher-Yates partial shuffle: at step i pick a uniform index
			// in [i, len(cand)) via crypto/rand and swap it to position i.
			// After target steps the first target entries are a uniform
			// sample without replacement.
			for i := 0; i < target; i++ {
				remain := int64(len(cand) - i)
				jBI, err := rand.Int(rand.Reader, big.NewInt(remain))
				if err != nil {
					return nil, nil, fmt.Errorf("refresh sample: %w", err)
				}
				j := i + int(jBI.Int64())
				cand[i], cand[j] = cand[j], cand[i]
			}
			chosen = cand[:target]
		}
		sort.Slice(chosen, func(i, j int) bool { return chosen[i] < chosen[j] })

		refreshChain = make([]davinci.SmtEntry, 0, len(chosen))
		refreshedOldStrs = make([][]string, 0, len(chosen))
		for _, key := range chosen {
			old, ok := s.votedBallots[key]
			if !ok {
				return nil, nil, fmt.Errorf("refresh: missing ballot at key %#x", key)
			}
			refreshed, err := old.ReencryptChained(s.cfg.EncKey, chain, nf)
			if err != nil {
				return nil, nil, fmt.Errorf("refresh reenc[%#x]: %w", key, err)
			}
			entry, err := buildArboUpdateEntry(
				s.tree, new(big.Int).SetUint64(key), ballotLeafHash(refreshed), procLevels)
			if err != nil {
				return nil, nil, fmt.Errorf("refresh update[%#x]: %w", key, err)
			}
			refreshChain = append(refreshChain, entry)
			refreshedOldStrs = append(refreshedOldStrs, ballotToFrStrings(old))
			// Fold the delta (new - old) into the accumulator so the Results
			// transition below commits the homomorphic sum of the current
			// leaves — the guest applies the same delta from its derived
			// scalar, so the two agree without shipping the deltas.
			newResults = accumAdd(newResults, accumFromBallot(refreshed))
			newResults = accumSub(newResults, accumFromBallot(old))
			s.votedBallots[key] = refreshed
		}
	}

	resultsEntry, err := buildArboUpdateEntry(
		s.tree, new(big.Int).SetUint64(keyResults), accumLeafHash(newResults), procLevels)
	if err != nil {
		return nil, nil, fmt.Errorf("Results update: %w", err)
	}
	s.results = newResults

	newRootBytes, err := s.tree.Root()
	if err != nil {
		return nil, nil, fmt.Errorf("tree.Root: %w", err)
	}
	newRoot := "0x" + hex.EncodeToString(pad32(newRootBytes))
	oldRoot := s.root
	s.root = newRoot
	s.voters += uint64(n)
	s.overwrites += uint64(len(overwritten))

	voterBallotStrs := make([][]string, n)
	for i, rb := range reencBallots {
		voterBallotStrs[i] = ballotToFrStrings(rb)
	}
	overwrittenStrs := make([][]string, len(overwritten))
	for i, ob := range overwritten {
		overwrittenStrs[i] = ballotToFrStrings(ob)
	}

	state := &davinci.StateTransitionData{
		VotersCount:      uint64(n),
		OverwrittenCount: uint64(len(overwritten)),
		OccupiedBefore:   uint64(occupiedBefore),
		// STATETX carries the processID as arbo-LE hex (the leaf value
		// encoding for config key 0x00).
		ProcessID:    "0x" + hex.EncodeToString(arbo.BigIntToBytes(bLen, s.cfg.ProcessID)),
		OldStateRoot: oldRoot,
		NewStateRoot: newRoot,
		VoteIDSmt:    voteIDChain,
		BallotSmt:    ballotChain,
		RefreshSmt:   refreshChain,
		ResultsSmt:   &resultsEntry,
		ProcessSmt:   processSmtProofs,
		BallotProofs: &davinci.BallotProofData{
			OldResults:         accumToStrings(oldResults),
			VoterBallots:       voterBallotStrs,
			OverwrittenBallots: overwrittenStrs,
			RefreshedBallots:   refreshedOldStrs,
		},
	}
	reencData := &davinci.ReencryptionData{
		EncryptionKeyX: pkX,
		EncryptionKeyY: pkY,
		Seed:           bigIntToFr32(seed),
		Entries:        reencEntries,
	}
	return state, reencData, nil
}

// maxTallyMsg bounds the BSGS discrete-log search when decrypting one
// accumulator plaintext.
const maxTallyMsg = uint64(1) << 20

// ResultsPayload decrypts the net results accumulator with the election
// private key and assembles the finalize payload: TE coordinates,
// plaintexts, one Chaum-Pedersen proof per ciphertext and the inclusion
// siblings of the Results leaf. Returns the payload and the tally.
func (s *State) ResultsPayload(privKey *big.Int) (*davinci.ResultsPayload, []uint64, error) {
	le32 := func(v *big.Int) string {
		return hex.EncodeToString(arbo.BigIntToBytes(32, v))
	}
	decryptAcc := func(acc accumBallot) ([]string, []uint64, []davinci.CpProof, error) {
		coords := make([]string, davinci.BallotFields)
		for i, v := range acc {
			coords[i] = le32(v)
		}
		msgs := make([]uint64, davinci.NumFields)
		proofs := make([]davinci.CpProof, davinci.NumFields)
		for i := 0; i < davinci.NumFields; i++ {
			c1rx, c1ry := format.FromTEtoRTE(acc[i*4], acc[i*4+1])
			c2rx, c2ry := format.FromTEtoRTE(acc[i*4+2], acc[i*4+3])
			c1 := s.cfg.EncKey.New().SetPoint(c1rx, c1ry)
			c2 := s.cfg.EncKey.New().SetPoint(c2rx, c2ry)
			_, msg, err := elgamal.Decrypt(s.cfg.EncKey, privKey, c1, c2, maxTallyMsg)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("decrypt ciphertext %d: %w", i, err)
			}
			// BuildDecryptionProof mutates msg; pass a copy.
			proof, err := elgamal.BuildDecryptionProof(
				privKey, s.cfg.EncKey, c1, c2, new(big.Int).Set(msg))
			if err != nil {
				return nil, nil, nil, fmt.Errorf("decryption proof %d: %w", i, err)
			}
			a1rx, a1ry := proof.A1.Point()
			a1x, a1y := format.FromRTEtoTE(a1rx, a1ry)
			a2rx, a2ry := proof.A2.Point()
			a2x, a2y := format.FromRTEtoTE(a2rx, a2ry)
			proofs[i] = davinci.CpProof{
				A1X: le32(a1x), A1Y: le32(a1y),
				A2X: le32(a2x), A2Y: le32(a2y),
				Z: le32(proof.Z),
			}
			msgs[i] = msg.Uint64()
		}
		return coords, msgs, proofs, nil
	}

	coords, msgs, proofs, err := decryptAcc(s.results)
	if err != nil {
		return nil, nil, fmt.Errorf("Results: %w", err)
	}

	sibs, err := s.leafSiblings(keyResults)
	if err != nil {
		return nil, nil, err
	}

	results := make([]uint64, davinci.NumFields)
	copy(results, msgs)
	return &davinci.ResultsPayload{
		Ballot:   coords,
		Results:  msgs,
		CpProofs: proofs,
		Siblings: sibs,
	}, results, nil
}

// EncryptedResults returns the net results accumulator as BallotFields
// Twisted-Edwards little-endian hex coordinates: NumFields ElGamal ciphertexts,
// [c1x, c1y, c2x, c2y] per field. This is the ciphertext published to the
// keywarden at election end; decrypting it with the election private key yields
// the tally. It matches the Ballot field of ResultsPayload, so the keywarden
// sees exactly what finalize will decrypt.
func (s *State) EncryptedResults() []string {
	coords := make([]string, davinci.BallotFields)
	for i, v := range s.results {
		coords[i] = hex.EncodeToString(arbo.BigIntToBytes(32, v))
	}
	return coords
}

// leafSiblings returns the inclusion siblings of a state tree key,
// zero-padded to procLevels, as plain LE hex.
func (s *State) leafSiblings(key uint64) ([]string, error) {
	bLen := arbo.HashFunctionSha256.Len()
	keyBytes := arbo.BigIntToBytes(keyLen, new(big.Int).SetUint64(key))
	_, _, packed, exists, err := s.tree.GenProof(keyBytes)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("key 0x%02x not in state tree", key)
	}
	sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packed)
	if err != nil {
		return nil, err
	}
	zero := make([]byte, bLen)
	for len(sibs) < procLevels {
		sibs = append(sibs, zero)
	}
	out := make([]string, procLevels)
	for i, sib := range sibs[:procLevels] {
		out[i] = hex.EncodeToString(pad32(sib))
	}
	return out, nil
}

// numFields returns the declared active ballot field count, read from the low
// 8 bits of the packed BallotMode leaf — the same bits the guest uses to drive
// its per-field reencryption/accumulator skip. Slots [numFields, NumFields)
// are identity-padded.
func (c Config) numFields() int {
	return int(new(big.Int).And(c.BallotMode, big.NewInt(0xff)).Int64())
}

// encKeyLeafValue computes the config leaf for the encryption key:
// SHA-256(X_BE32 || Y_BE32) over the TE coordinates, matching the batch
// circuit's hash_enc_key and the aggregator genesis computation.
func encKeyLeafValue(encKey *bjjgnark.BJJ) *big.Int {
	rx, ry := encKey.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	var buf [64]byte
	tx.FillBytes(buf[:32])
	ty.FillBytes(buf[32:])
	digest := sha256.Sum256(buf[:])
	return new(big.Int).SetBytes(digest[:])
}
