// smt.go builds circuit-ready SMT transition proofs (insert, update,
// read) over an arbo SHA-256 tree.
package chain

import (
	"encoding/hex"
	"fmt"
	"math/big"

	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// pad32 right-aligns b into a 32-byte slice (zero-left-padded).
func pad32(b []byte) []byte {
	if len(b) == 32 {
		return b
	}
	if len(b) > 32 {
		return b[len(b)-32:]
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

// buildArboInsertEntry inserts newKey into the tree and returns the
// circuit insert proof (fnc = 1,0). The key must not exist yet.
func buildArboInsertEntry(tree *arbo.Tree, newKeyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	newKeyBytes := arbo.BigIntToBytes(bLen, newKeyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	// GenProof BEFORE insertion to detect the displaced leaf.
	oldLeafKey, oldLeafValue, _, exists, err := tree.GenProof(newKeyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof before: %w", err)
	}
	if exists {
		return davinci.SmtEntry{}, fmt.Errorf("key %s already exists in tree", newKeyBI)
	}

	isOld0 := len(oldLeafKey) == 0
	if isOld0 {
		oldLeafKey = make([]byte, bLen)
		oldLeafValue = make([]byte, bLen)
	}

	oldRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (old): %w", err)
	}
	if err := tree.Add(newKeyBytes, newValueBytes); err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Add: %w", err)
	}
	newRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (new): %w", err)
	}

	_, _, packedAfter, existsAfter, err := tree.GenProof(newKeyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof after: %w", err)
	}
	if !existsAfter {
		return davinci.SmtEntry{}, fmt.Errorf("new key not found after insertion")
	}
	sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedAfter)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("UnpackSiblings: %w", err)
	}
	// Remove last sibling when displacing an existing leaf (pure-insert mode).
	if !isOld0 && len(sibs) > 0 {
		sibs = sibs[:len(sibs)-1]
	}
	zero := make([]byte, bLen)
	for len(sibs) < levels {
		sibs = append(sibs, zero)
	}
	sibs = sibs[:levels]

	entry := davinci.SmtEntry{
		OldRoot:  "0x" + hex.EncodeToString(pad32(oldRootBytes)),
		NewRoot:  "0x" + hex.EncodeToString(pad32(newRootBytes)),
		OldKey:   "0x" + hex.EncodeToString(pad32(oldLeafKey)),
		OldValue: "0x" + hex.EncodeToString(pad32(oldLeafValue)),
		NewKey:   "0x" + hex.EncodeToString(pad32(newKeyBytes)),
		NewValue: "0x" + hex.EncodeToString(pad32(newValueBytes)),
		Fnc0:     1,
		Fnc1:     0,
		Siblings: make([]string, levels),
	}
	if isOld0 {
		entry.IsOld0 = 1
	}
	for i, sib := range sibs {
		entry.Siblings[i] = "0x" + hex.EncodeToString(pad32(sib))
	}
	return entry, nil
}

// buildArboUpdateEntry updates an existing key and returns the circuit
// update proof (fnc = 0,1).
func buildArboUpdateEntry(tree *arbo.Tree, keyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	keyBytes := arbo.BigIntToBytes(bLen, keyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	_, oldValueBytes, packedBefore, exists, err := tree.GenProof(keyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof before update: %w", err)
	}
	if !exists {
		return davinci.SmtEntry{}, fmt.Errorf("key %s not found for update", keyBI)
	}

	oldRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (old): %w", err)
	}
	if err := tree.Update(keyBytes, newValueBytes); err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Update: %w", err)
	}
	newRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (new): %w", err)
	}

	sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedBefore)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("UnpackSiblings: %w", err)
	}
	zero := make([]byte, bLen)
	for len(sibs) < levels {
		sibs = append(sibs, zero)
	}
	sibs = sibs[:levels]
	sibStrs := make([]string, levels)
	for i, sib := range sibs {
		sibStrs[i] = "0x" + hex.EncodeToString(pad32(sib))
	}

	return davinci.SmtEntry{
		OldRoot:  "0x" + hex.EncodeToString(pad32(oldRootBytes)),
		NewRoot:  "0x" + hex.EncodeToString(pad32(newRootBytes)),
		OldKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
		OldValue: "0x" + hex.EncodeToString(pad32(oldValueBytes)),
		NewKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
		NewValue: "0x" + hex.EncodeToString(pad32(newValueBytes)),
		IsOld0:   0,
		Fnc0:     0,
		Fnc1:     1,
		Siblings: sibStrs,
	}, nil
}

// buildArboReadProofs generates non-mutating read proofs (fnc = 0,0) for
// keys that must already exist in the tree.
func buildArboReadProofs(tree *arbo.Tree, keys []uint64, bLen, levels int) ([]davinci.SmtEntry, error) {
	rootBytes, err := tree.Root()
	if err != nil {
		return nil, err
	}
	rootHex := "0x" + hex.EncodeToString(pad32(rootBytes))

	entries := make([]davinci.SmtEntry, 0, len(keys))
	for _, k := range keys {
		keyBytes := arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k))
		_, valBytes, packed, exists, err := tree.GenProof(keyBytes)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("key 0x%x not found in tree", k)
		}
		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packed)
		if err != nil {
			return nil, err
		}
		zero := make([]byte, bLen)
		for len(sibs) < levels {
			sibs = append(sibs, zero)
		}
		sibs = sibs[:levels]
		sibStrs := make([]string, levels)
		for i, sib := range sibs {
			sibStrs[i] = "0x" + hex.EncodeToString(pad32(sib))
		}
		entries = append(entries, davinci.SmtEntry{
			OldRoot:  rootHex,
			NewRoot:  rootHex,
			OldKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
			OldValue: "0x" + hex.EncodeToString(pad32(valBytes)),
			IsOld0:   0,
			NewKey:   "0x" + hex.EncodeToString(pad32(keyBytes)),
			NewValue: "0x" + hex.EncodeToString(pad32(valBytes)),
			Fnc0:     0,
			Fnc1:     0,
			Siblings: sibStrs,
		})
	}
	return entries, nil
}
