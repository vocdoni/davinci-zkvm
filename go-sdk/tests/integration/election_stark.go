package integration

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func zeroEcgfp5Ballot() [8]davinci.Ecgfp5Ciphertext {
	var out [8]davinci.Ecgfp5Ciphertext
	zero := "0x" + hex.EncodeToString(make([]byte, 40))
	for i := range out {
		out[i] = davinci.Ecgfp5Ciphertext{C1: zero, C2: zero}
	}
	return out
}

func packedBallotModeBigInt() *big.Int {
	mode := packStarkBallotMode(defaultStarkBallotMode())
	bytesLE := make([]byte, 32)
	for i, limb := range mode {
		for j := 0; j < 8; j++ {
			bytesLE[i*8+j] = byte(limb >> (8 * j))
		}
	}
	return arbo.BytesToBigInt(bytesLE)
}

// ConfigureForStark switches the election process config to the ecgfp5/davinci-stark path.
func (e *Election) ConfigureForStark() error {
	skSeed := make([]byte, 40)
	if _, err := rand.Read(skSeed); err != nil {
		return fmt.Errorf("rand stark sk: %w", err)
	}
	skHex := "0x" + hex.EncodeToString(skSeed)
	pkHex, err := ecgfp5DerivePubkey(skHex)
	if err != nil {
		return fmt.Errorf("ecgfp5DerivePubkey: %w", err)
	}
	encKeyHashBI, err := ecgfp5HashEncKey(pkHex)
	if err != nil {
		return fmt.Errorf("ecgfp5HashEncKey: %w", err)
	}
	zeroLeaf, err := ecgfp5LeafHash(zeroEcgfp5Ballot())
	if err != nil {
		return fmt.Errorf("ecgfp5LeafHash(zero): %w", err)
	}

	bLen := arbo.HashFunctionSha256.Len()
	if err := e.ProcTree.Update(
		arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(0x02)),
		arbo.BigIntToBytes(bLen, packedBallotModeBigInt()),
	); err != nil {
		return fmt.Errorf("update ballot mode: %w", err)
	}
	if err := e.ProcTree.Update(
		arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(0x03)),
		arbo.BigIntToBytes(bLen, encKeyHashBI),
	); err != nil {
		return fmt.Errorf("update encryption key hash: %w", err)
	}
	for _, key := range []uint64{keyResultsAdd, keyResultsSub} {
		if err := e.ProcTree.Update(
			arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(key)),
			arbo.BigIntToBytes(bLen, zeroLeaf),
		); err != nil {
			return fmt.Errorf("reset results leaf 0x%02x: %w", key, err)
		}
	}
	root, err := e.ProcTree.Root()
	if err != nil {
		return fmt.Errorf("tree.Root: %w", err)
	}
	e.OldRoot = "0x" + hex.EncodeToString(pad32(root))
	e.StarkEncKeyHex = pkHex
	e.StarkEncSkHex = skHex
	e.ResultsAddG5 = zeroEcgfp5Ballot()
	e.ResultsSubG5 = zeroEcgfp5Ballot()
	e.VotedBallotsG5 = map[int][8]davinci.Ecgfp5Ciphertext{}
	return nil
}

func (e *Election) BuildStarkReencBlock(results []*StarkBallotResult) (*davinci.Ecgfp5ReencryptionData, [][8]davinci.Ecgfp5Ciphertext, error) {
	if e.StarkEncKeyHex == "" {
		return nil, nil, fmt.Errorf("stark election key not configured")
	}
	entries := make([]davinci.Ecgfp5ReencryptionEntry, len(results))
	reencBallots := make([][8]davinci.Ecgfp5Ciphertext, len(results))
	for i, res := range results {
		seed := make([]byte, 40)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, fmt.Errorf("rand reenc seed[%d]: %w", i, err)
		}
		kHex := "0x" + hex.EncodeToString(seed)
		original := bundleCiphertexts(res.Bundle)
		reenc, err := ecgfp5ReencryptBallot(e.StarkEncKeyHex, kHex, original)
		if err != nil {
			return nil, nil, fmt.Errorf("reencrypt ballot[%d]: %w", i, err)
		}
		reencBallots[i] = reenc
		entries[i] = davinci.Ecgfp5ReencryptionEntry{
			K:           kHex,
			Original:    original,
			Reencrypted: reenc,
		}
	}
	return &davinci.Ecgfp5ReencryptionData{
		EncryptionKey: e.StarkEncKeyHex,
		Entries:       entries,
	}, reencBallots, nil
}

func bundleCiphertexts(bundle *davinci.StarkProofBundle) [8]davinci.Ecgfp5Ciphertext {
	return ballotJSONToCiphertexts(ciphertextsFromBundle(bundle))
}

func (e *Election) BuildStarkStateBlock(batchVoters []*Voter, ballotResults []*StarkBallotResult, reencBallots [][8]davinci.Ecgfp5Ciphertext) (*davinci.StateTransitionData, [][8]davinci.Ecgfp5Ciphertext, error) {
	n := len(batchVoters)
	if n != len(ballotResults) || n != len(reencBallots) {
		return nil, nil, fmt.Errorf("count mismatch in BuildStarkStateBlock")
	}

	bLen := arbo.HashFunctionSha256.Len()
	processSmtProofs, err := buildArboReadProofs(e.ProcTree, configKeys, bLen, procLevels)
	if err != nil {
		return nil, nil, fmt.Errorf("buildArboReadProofs: %w", err)
	}

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

	var ballotChain []davinci.SmtEntry
	overwrittenBallots := make([][8]davinci.Ecgfp5Ciphertext, 0)
	for i, v := range batchVoters {
		res := ballotResults[i]
		key := ballotMin + uint64(v.CensusIdx)<<16 + res.AddressLo16
		newLeafVal, err := ecgfp5LeafHash(reencBallots[i])
		if err != nil {
			return nil, nil, fmt.Errorf("leaf hash[%d]: %w", i, err)
		}
		if oldBallot, isOverwrite := e.VotedBallotsG5[v.CensusIdx]; isOverwrite {
			entry, err := buildArboUpdateEntry(e.ProcTree, new(big.Int).SetUint64(key), newLeafVal, procLevels)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot update[%d]: %w", i, err)
			}
			ballotChain = append(ballotChain, entry)
			overwrittenBallots = append(overwrittenBallots, oldBallot)
		} else {
			entry, err := buildArboInsertEntry(e.ProcTree, new(big.Int).SetUint64(key), newLeafVal, procLevels)
			if err != nil {
				return nil, nil, fmt.Errorf("ballot insert[%d]: %w", i, err)
			}
			ballotChain = append(ballotChain, entry)
		}
		e.VotedBallotsG5[v.CensusIdx] = reencBallots[i]
	}

	oldResultsAdd := e.ResultsAddG5
	oldResultsSub := e.ResultsSubG5
	newResultsAdd, err := ecgfp5AddBallots(append([][8]davinci.Ecgfp5Ciphertext{e.ResultsAddG5}, reencBallots...))
	if err != nil {
		return nil, nil, fmt.Errorf("results add: %w", err)
	}
	newResultsAddLeaf, err := ecgfp5LeafHash(newResultsAdd)
	if err != nil {
		return nil, nil, fmt.Errorf("results add leaf: %w", err)
	}
	resultsAddEntry, err := buildArboUpdateEntry(
		e.ProcTree,
		new(big.Int).SetUint64(keyResultsAdd),
		newResultsAddLeaf,
		procLevels,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ResultsAdd update: %w", err)
	}
	e.ResultsAddG5 = newResultsAdd

	var resultsSubEntry *davinci.SmtEntry
	if len(overwrittenBallots) > 0 {
		newResultsSub, err := ecgfp5AddBallots(append([][8]davinci.Ecgfp5Ciphertext{e.ResultsSubG5}, overwrittenBallots...))
		if err != nil {
			return nil, nil, fmt.Errorf("results sub: %w", err)
		}
		newResultsSubLeaf, err := ecgfp5LeafHash(newResultsSub)
		if err != nil {
			return nil, nil, fmt.Errorf("results sub leaf: %w", err)
		}
		entry, err := buildArboUpdateEntry(
			e.ProcTree,
			new(big.Int).SetUint64(keyResultsSub),
			newResultsSubLeaf,
			procLevels,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("ResultsSub update: %w", err)
		}
		e.ResultsSubG5 = newResultsSub
		resultsSubEntry = &entry
	}

	newRootBytes, err := e.ProcTree.Root()
	if err != nil {
		return nil, nil, fmt.Errorf("tree.Root (new): %w", err)
	}
	newRoot := "0x" + hex.EncodeToString(pad32(newRootBytes))
	oldRoot := e.OldRoot
	e.OldRoot = newRoot

	ballotProofs := &davinci.Ecgfp5BallotProofData{
		OldResultsAdd:      oldResultsAdd,
		OldResultsSub:      oldResultsSub,
		VoterBallots:       reencBallots,
		OverwrittenBallots: overwrittenBallots,
	}
	return &davinci.StateTransitionData{
		VotersCount:        uint64(n),
		OverwrittenCount:   uint64(len(overwrittenBallots)),
		ProcessID:          e.processIDArboHex(),
		OldStateRoot:       oldRoot,
		NewStateRoot:       newRoot,
		VoteIDSmt:          voteIDChain,
		BallotSmt:          ballotChain,
		ResultsAddSmt:      &resultsAddEntry,
		ResultsSubSmt:      resultsSubEntry,
		ProcessSmt:         processSmtProofs,
		Ecgfp5BallotProofs: ballotProofs,
	}, overwrittenBallots, nil
}

func (e *Election) StarkNetBallot() ([8]davinci.Ecgfp5Ciphertext, error) {
	return ecgfp5SubBallots(e.ResultsAddG5, [][8]davinci.Ecgfp5Ciphertext{e.ResultsSubG5})
}

func (e *Election) DecryptStarkTally(maxTotal uint64) ([8]uint64, error) {
	netBallot, err := e.StarkNetBallot()
	if err != nil {
		return [8]uint64{}, err
	}
	totals, err := ecgfp5DecryptTotals(e.StarkEncSkHex, netBallot, maxTotal)
	if err != nil {
		return [8]uint64{}, err
	}
	var out [8]uint64
	copy(out[:], totals)
	return out, nil
}
