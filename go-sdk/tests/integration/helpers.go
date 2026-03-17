// Package integration contains two kinds of tests:
// (1) API service tests (service_test.go, e2e_test.go, smt_service_test.go,
// integration_test.go) that submit jobs to a running davinci-zkvm service.
// These require: docker compose up -d --build (starts the davinci-zkvm service).
// The active integration suites generate real davinci-stark ballot proofs via
// the WASM package, chain multiple state-transitions, verify the accumulated
// vote tally by ecgfp5 ElGamal decryption.
package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	iden3poseidon "github.com/iden3/go-iden3-crypto/poseidon"
	arbo "github.com/vocdoni/arbo"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// API client helpers

// apiURL returns the base URL of the davinci-zkvm service.
// Override with DAVINCI_API_URL environment variable.
var apiURL = func() string {
	if u := os.Getenv("DAVINCI_API_URL"); u != "" {
		return u
	}
	return "http://localhost:8080"
}()

// proofTimeout returns the timeout for waiting on a single ZisK proof.
// Default: 5 minutes. Override with DAVINCI_PROOF_TIMEOUT (e.g. "10m").
func proofTimeout() time.Duration {
	if d := os.Getenv("DAVINCI_PROOF_TIMEOUT"); d != "" {
		if p, err := time.ParseDuration(d); err == nil {
			return p
		}
	}
	return 5 * time.Minute
}

// votesPerBatchFromEnv reads VOTES_PER_BATCH and returns the largest power of 2
// <= the specified value, capped at the configured batch limit. Default is 4.
func votesPerBatchFromEnv() int {
	maxBatchSize := davinci.ConfiguredMaxBatchSize()
	if s := os.Getenv("VOTES_PER_BATCH"); s != "" {
		n, err := strconv.Atoi(s)
		if err == nil && n >= 2 {
			p := 2
			for p*2 <= n && p*2 <= maxBatchSize {
				p *= 2
			}
			return p
		}
	}
	return 4
}

// newClient returns a new davinci SDK client.
func newClient() *davinci.Client {
	return davinci.NewClient(apiURL)
}

func requireCompatibleService(t testing.TB) *davinci.Client {
	t.Helper()
	client := newClient()
	_, err := client.Health()
	if err != nil {
		t.Skipf("davinci-zkvm service not available at %s: %v (start with 'docker compose up -d --build')", apiURL, err)
	}
	return client
}

// arboHexToBEHex converts an arbo LE hex string (as produced by hex.EncodeToString
// on arbo.Root() bytes) to standard big-endian hex. This is needed because the
// STATETX block encodes fields as arbo LE hex, while the KZG block requires
// big-endian hex => both must decode to the same FrRaw limbs in the circuit.
func arboHexToBEHex(leHex string) string {
	trimmed := strings.TrimPrefix(leHex, "0x")
	leBytes, _ := hex.DecodeString(trimmed)
	bi := arbo.BytesToBigInt(leBytes)
	return "0x" + hex.EncodeToString(pad32(bi.Bytes()))
}

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

// buildArboInsertEntry creates an SMT insert proof using arbo SHA-256.
// It records the OldRoot before insertion and NewRoot after, then returns
// a fully-populated SmtEntry ready for the circuit.
// Caller must NOT insert newKeyBI into the tree before calling this function.
// The function inserts it and updates the tree.
func buildArboInsertEntry(tree *arbo.Tree, newKeyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	newKeyBytes := arbo.BigIntToBytes(bLen, newKeyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	// GenProof BEFORE insertion => detect displaced leaf.
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

	// Record OldRoot.
	oldRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (old): %w", err)
	}

	// Insert.
	if err := tree.Add(newKeyBytes, newValueBytes); err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Add: %w", err)
	}

	// Record NewRoot.
	newRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (new): %w", err)
	}

	// GenProof AFTER insertion => get the updated siblings.
	_, _, packedSiblingsAfter, existsAfter, err := tree.GenProof(newKeyBytes)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("GenProof after: %w", err)
	}
	if !existsAfter {
		return davinci.SmtEntry{}, fmt.Errorf("new key not found after insertion")
	}

	siblingsUnpacked, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSiblingsAfter)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("UnpackSiblings: %w", err)
	}

	// Remove last sibling when displacing an existing leaf (pure-insert mode).
	if !isOld0 && len(siblingsUnpacked) > 0 {
		siblingsUnpacked = siblingsUnpacked[:len(siblingsUnpacked)-1]
	}

	// Pad siblings to `levels`.
	zero32 := make([]byte, bLen)
	for len(siblingsUnpacked) < levels {
		siblingsUnpacked = append(siblingsUnpacked, zero32)
	}
	siblingsUnpacked = siblingsUnpacked[:levels]

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
	for i, s := range siblingsUnpacked {
		entry.Siblings[i] = "0x" + hex.EncodeToString(pad32(s))
	}
	return entry, nil
}

// buildArboUpdateEntry creates an SMT update proof using arbo SHA-256.
// The key must already exist in the tree.
func buildArboUpdateEntry(tree *arbo.Tree, keyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	keyBytes := arbo.BigIntToBytes(bLen, keyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	// Get old value and siblings before update.
	_, oldValueBytes, packedSibsBefore, exists, err := tree.GenProof(keyBytes)
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

	// Update the value.
	if err := tree.Update(keyBytes, newValueBytes); err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Update: %w", err)
	}

	newRootBytes, err := tree.Root()
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("tree.Root (new): %w", err)
	}

	sibsBefore, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSibsBefore)
	if err != nil {
		return davinci.SmtEntry{}, fmt.Errorf("UnpackSiblings: %w", err)
	}

	zero32 := make([]byte, bLen)
	for len(sibsBefore) < levels {
		sibsBefore = append(sibsBefore, zero32)
	}
	sibsBefore = sibsBefore[:levels]

	sibStrs := make([]string, levels)
	for i, s := range sibsBefore {
		sibStrs[i] = "0x" + hex.EncodeToString(pad32(s))
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

// buildArboReadProofs generates read (non-mutating) proofs for a set of keys
// that must already exist in the tree.
func buildArboReadProofs(tree *arbo.Tree, keys []uint64, bLen, levels int) ([]davinci.SmtEntry, error) {
	rootBytes, err := tree.Root()
	if err != nil {
		return nil, err
	}
	rootHex := "0x" + hex.EncodeToString(pad32(rootBytes))

	var entries []davinci.SmtEntry
	for _, k := range keys {
		keyBI := new(big.Int).SetUint64(k)
		keyBytes := arbo.BigIntToBytes(bLen, keyBI)

		_, valBytes, packedSibs, exists, err := tree.GenProof(keyBytes)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, fmt.Errorf("key 0x%x not found in tree", k)
		}

		sibs, err := arbo.UnpackSiblings(arbo.HashFunctionSha256, packedSibs)
		if err != nil {
			return nil, err
		}
		zero := make([]byte, bLen)
		for len(sibs) < levels {
			sibs = append(sibs, zero)
		}
		sibs = sibs[:levels]

		sibStrs := make([]string, levels)
		for i, s := range sibs {
			sibStrs[i] = "0x" + hex.EncodeToString(pad32(s))
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

// Census (lean-IMT Poseidon) helpers

// poseidonHasher computes Poseidon(a, b) used by the lean-IMT census.
func poseidonHasher(a, b *big.Int) *big.Int {
	out, err := iden3poseidon.Hash([]*big.Int{a, b})
	if err != nil {
		panic(err)
	}
	return out
}

// bigIntEq compares two *big.Int values.
func bigIntEq(a, b *big.Int) bool { return a.Cmp(b) == 0 }

// packAddressWeight encodes address (160 bits) || weight (88 bits) into one big.Int.
// This is the leaf value format used in the census lean-IMT.
func packAddressWeight(address, weight *big.Int) *big.Int {
	// address occupies bits [88..247], weight occupies bits [0..87]
	packed := new(big.Int).Lsh(address, 88)
	return packed.Or(packed, weight)
}

// bigIntToFr32 converts a *big.Int to a 32-byte big-endian hex string (0x-prefixed).
func bigIntToFr32(v *big.Int) string {
	b := v.Bytes()
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return "0x" + hex.EncodeToString(padded)
}

// KZG helpers

// deriveKZGZ computes the evaluation point Z for KZG verification:
//
//	Z = SHA-256(processID_be32 ‖ rootHashBefore_be32 ‖ commitment_48)
//
// This matches the derivation in circuit/src/kzg.rs.
func deriveKZGZ(processIDHex, rootBeforeHex string, commitment [48]byte) *big.Int {
	processIDBytes, _ := hex.DecodeString(strings.TrimPrefix(processIDHex, "0x"))
	rootBytes, _ := hex.DecodeString(strings.TrimPrefix(rootBeforeHex, "0x"))

	var preimage [112]byte
	copy(preimage[32-len(processIDBytes):32], processIDBytes)
	copy(preimage[64-len(rootBytes):64], rootBytes)
	copy(preimage[64:], commitment[:])

	h := sha256.Sum256(preimage[:])
	return new(big.Int).SetBytes(h[:])
}

// ziskemu emulator helper

// runZiskEmu writes inputBytes to a temp file and executes ziskemu against the
// circuit ELF. Returns the parsed uint32 output registers or an error.
// The ELF path can be overridden with the CIRCUIT_ELF_PATH environment variable.
func runZiskEmu(inputBytes []byte) ([]uint32, error) {
	ziskemuBin, err := exec.LookPath("ziskemu")
	if err != nil {
		return nil, fmt.Errorf("ziskemu not in PATH: %w", err)
	}
	elfPath := os.Getenv("CIRCUIT_ELF_PATH")
	if elfPath == "" {
		elfPath = "/home/p4u/davinci-zkvm/circuit/elf/circuit.elf"
	}
	tmp, err := os.CreateTemp("", "davinci-integration-*.bin")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(inputBytes); err != nil {
		return nil, err
	}
	tmp.Close()

	cmd := exec.Command(ziskemuBin, "-e", elfPath, "-i", tmp.Name())
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ziskemu failed: %w\noutput: %s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var outputs []uint32
	for _, l := range lines {
		var v uint32
		fmt.Sscanf(strings.TrimSpace(l), "%x", &v)
		outputs = append(outputs, v)
	}
	return outputs, nil
}
