// Package integration contains two kinds of tests:
//
// (1) API service tests (service_test.go, e2e_test.go, smt_service_test.go,
// integration_test.go) that submit jobs to a running davinci-zkvm service.
// These require: docker compose up -d --build (starts the davinci-zkvm service).
//
// (2) Circuit constraint violation tests (cheat_test.go) that use ziskemu
// directly and do NOT require the API service. These require: ziskemu in PATH.
//
// The integration_test.go suite generates real BN254 Groth16 ballot proofs
// via go-rapidsnark, chains multiple state-transitions, verifies the accumulated
// vote tally by ElGamal decryption, and checks that deliberate protocol
// violations are rejected by the circuit.
package integration

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	iden3poseidon "github.com/iden3/go-iden3-crypto/poseidon"
	arbo "github.com/vocdoni/arbo"
	"github.com/vocdoni/davinci-node/crypto/ecc/format"
	"github.com/vocdoni/davinci-node/crypto/elgamal"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// ─── API client helpers ────────────────────────────────────────────────────

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

// newClient returns a new davinci SDK client.
func newClient() *davinci.Client {
	return davinci.NewClient(apiURL)
}

// arboHexToBEHex converts an arbo LE hex string (as produced by hex.EncodeToString
// on arbo.Root() bytes) to standard big-endian hex. This is needed because the
// STATETX block encodes fields as arbo LE hex, while the KZG block requires
// big-endian hex — both must decode to the same FrRaw limbs in the circuit.
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
//
// Caller must NOT insert newKeyBI into the tree before calling this function.
// The function inserts it and updates the tree.
func buildArboInsertEntry(tree *arbo.Tree, newKeyBI, newValueBI *big.Int, levels int) (davinci.SmtEntry, error) {
	bLen := arbo.HashFunctionSha256.Len()
	newKeyBytes := arbo.BigIntToBytes(bLen, newKeyBI)
	newValueBytes := arbo.BigIntToBytes(bLen, newValueBI)

	// GenProof BEFORE insertion — detect displaced leaf.
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

	// GenProof AFTER insertion — get the updated siblings.
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

// ─── Census (lean-IMT Poseidon) helpers ───────────────────────────────────

// ballotLeafHash computes a deterministic 32-byte SHA-256 leaf value for an
// ElGamal ballot stored in the arbo state tree (keys 0x04 / 0x05).
// Each of the 32 Twisted Edwards coordinates is encoded as a fixed-size 32-byte
// big-endian word so the hash is unambiguous.  The internal bjj_gnark library
// stores points in Reduced Twisted Edwards (RTE) form; we must convert to
// standard TE form before hashing so the digest matches the circuit.
func ballotLeafHash(b *elgamal.Ballot) *big.Int {
	h := sha256.New()
	buf := make([]byte, 32)
	for i := 0; i < 8; i++ {
		if b.Ciphertexts[i] == nil {
			// Identity point (0,1) in TE: 4 coordinates = 0, 1, 0, 1
			zeroCoord := make([]byte, 32)
			oneCoord := make([]byte, 32)
			oneCoord[31] = 1
			h.Write(zeroCoord)
			h.Write(oneCoord)
			h.Write(zeroCoord)
			h.Write(oneCoord)
			continue
		}
		c1rx, c1ry := b.Ciphertexts[i].C1.Point()
		c1tx, c1ty := format.FromRTEtoTE(c1rx, c1ry)
		c2rx, c2ry := b.Ciphertexts[i].C2.Point()
		c2tx, c2ty := format.FromRTEtoTE(c2rx, c2ry)
		for _, coord := range []*big.Int{c1tx, c1ty, c2tx, c2ty} {
			coord.FillBytes(buf)
			h.Write(buf)
		}
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// poseidonHasher computes Poseidon(a, b) used by lean-IMT.
func poseidonHasher(a, b *big.Int) *big.Int {
	out, err := iden3poseidon.Hash([]*big.Int{a, b})
	if err != nil {
		panic(err)
	}
	return out
}

// bigIntEq compares two *big.Int values.
func bigIntEq(a, b *big.Int) bool { return a.Cmp(b) == 0 }

// ─── Fr-wise ballot accumulator ──────────────────────────────────────────
//
// The circuit accumulates ResultsAdd / ResultsSub using coordinate-wise
// Fr addition (not EC point addition).  This type mirrors that behaviour
// so the Go-side leaf hashes match what the circuit computes.

// bn254ScalarField is the BN254 scalar field order (Fr).
var bn254ScalarField, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// frAccumBallot represents a ballot as 32 big.Int Fr elements (TE coordinates).
// This is used for the result accumulator, not for EC point operations.
type frAccumBallot [32]*big.Int

// newZeroFrAccum returns the zero accumulator (all fields = 0).
func newZeroFrAccum() frAccumBallot {
	var b frAccumBallot
	for i := range b {
		b[i] = new(big.Int)
	}
	return b
}

// frAccumFromBallot converts an elgamal.Ballot to frAccumBallot (TE coordinates).
func frAccumFromBallot(ballot *elgamal.Ballot) frAccumBallot {
	var acc frAccumBallot
	for i := 0; i < 8; i++ {
		rx, ry := ballot.Ciphertexts[i].C1.Point()
		c1tx, c1ty := format.FromRTEtoTE(rx, ry)
		rx2, ry2 := ballot.Ciphertexts[i].C2.Point()
		c2tx, c2ty := format.FromRTEtoTE(rx2, ry2)
		acc[i*4] = c1tx
		acc[i*4+1] = c1ty
		acc[i*4+2] = c2tx
		acc[i*4+3] = c2ty
	}
	return acc
}

// frAccumAdd performs coordinate-wise Fr addition: out[i] = (a[i] + b[i]) mod p.
func frAccumAdd(a, b frAccumBallot) frAccumBallot {
	var out frAccumBallot
	for i := 0; i < 32; i++ {
		out[i] = new(big.Int).Add(a[i], b[i])
		out[i].Mod(out[i], bn254ScalarField)
	}
	return out
}

// frAccumLeafHash computes SHA-256 of the 32 Fr elements (32-byte BE each).
func frAccumLeafHash(acc frAccumBallot) *big.Int {
	h := sha256.New()
	buf := make([]byte, 32)
	for _, v := range acc {
		v.FillBytes(buf)
		h.Write(buf)
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// frAccumToStrings converts frAccumBallot to 32 big-endian hex strings.
func frAccumToStrings(acc frAccumBallot) []string {
	out := make([]string, 32)
	for i, v := range acc {
		out[i] = bigIntToFr32(v)
	}
	return out
}

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

// ─── BabyJubJub point helper ─────────────────────────────────────────────

// bjjPointToFr32Hex converts a bjjgnark point from RTE (internal) coordinates
// to TE (Twisted Edwards) coordinates and returns them as 0x-prefixed 32-byte
// big-endian hex strings. The circuit expects TE coordinates.
func bjjPointToFr32Hex(p interface{ Point() (*big.Int, *big.Int) }) (xHex, yHex string) {
	rx, ry := p.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	return bigIntToFr32(tx), bigIntToFr32(ty)
}

// ─── KZG helpers ─────────────────────────────────────────────────────────

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

// ─── ziskemu emulator helper ──────────────────────────────────────────────

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

// ─── Fixture loading helpers ──────────────────────────────────────────────

// testDataDir returns the path to the ballot proof test fixtures.
// Override with TEST_DATA_DIR environment variable.
func testDataDir() string {
	if d := os.Getenv("TEST_DATA_DIR"); d != "" {
		return d
	}
	return filepath.Join("..", "..", "data", "ballot_proof_bn254")
}

// loadProveRequestFromDir builds a ProveRequest by reading proof, public, and sig
// files from dir. Only the first n proofs (sorted numerically) are loaded.
func loadProveRequestFromDir(dir string, n int) (*davinci.ProveRequest, error) {
	vkBytes, err := os.ReadFile(filepath.Join(dir, "verification_key.json"))
	if err != nil {
		return nil, fmt.Errorf("reading verification_key.json: %w", err)
	}

	proofPaths, err := collectPaths(dir, "proof_")
	if err != nil {
		return nil, err
	}
	publicPaths, err := collectPaths(dir, "public_")
	if err != nil {
		return nil, err
	}
	sigPaths, err := collectPaths(dir, "sig_")
	if err != nil {
		return nil, err
	}

	if len(proofPaths) < n {
		return nil, fmt.Errorf("need %d proofs, found %d in %s", n, len(proofPaths), dir)
	}
	if len(publicPaths) < n {
		return nil, fmt.Errorf("need %d public files, found %d in %s", n, len(publicPaths), dir)
	}
	if len(sigPaths) < n {
		return nil, fmt.Errorf("need %d sig files, found %d in %s (ECDSA signatures are mandatory)", n, len(sigPaths), dir)
	}

	proofPaths = proofPaths[:n]
	publicPaths = publicPaths[:n]
	sigPaths = sigPaths[:n]

	proofs := make([]json.RawMessage, n)
	publics := make([][]string, n)
	sigs := make([]json.RawMessage, n)

	for i := 0; i < n; i++ {
		raw, err := os.ReadFile(proofPaths[i])
		if err != nil {
			return nil, fmt.Errorf("reading proof %d: %w", i+1, err)
		}
		proofs[i] = raw

		pubRaw, err := os.ReadFile(publicPaths[i])
		if err != nil {
			return nil, fmt.Errorf("reading public %d: %w", i+1, err)
		}
		if err := json.Unmarshal(pubRaw, &publics[i]); err != nil {
			return nil, fmt.Errorf("parsing public %d: %w", i+1, err)
		}

		sigRaw, err := os.ReadFile(sigPaths[i])
		if err != nil {
			return nil, fmt.Errorf("reading sig %d: %w", i+1, err)
		}
		sigs[i] = sigRaw
	}

	return &davinci.ProveRequest{
		VK:           json.RawMessage(vkBytes),
		Proofs:       proofs,
		PublicInputs: publics,
		Sigs:         sigs,
	}, nil
}

// collectPaths returns all *.json files in dir whose base name starts with
// prefix, sorted numerically by the trailing integer.
func collectPaths(dir, prefix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	var paths []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), ".json") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Slice(paths, func(i, j int) bool {
		return numericSuffix(paths[i]) < numericSuffix(paths[j])
	})
	return paths, nil
}

// numericSuffix extracts the trailing integer from a filename like "proof_42.json".
func numericSuffix(path string) int {
	base := strings.TrimSuffix(filepath.Base(path), ".json")
	parts := strings.Split(base, "_")
	n, _ := strconv.Atoi(parts[len(parts)-1])
	return n
}

// ─── Binary input parsing helpers ────────────────────────────────────────

// parseVoteIDsFromBinary extracts voteID values (public input index 1, word 0)
// for the first n proofs from the davinci-zkvm binary input format.
func parseVoteIDsFromBinary(data []byte, n int) ([]uint64, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short for header")
	}
	off := 0
	off += 8 // magic
	off += 8 // logn
	nproofs := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	nPublic := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8

	if n > nproofs {
		return nil, fmt.Errorf("requested %d voteIDs but only %d proofs", n, nproofs)
	}
	if nPublic < 2 {
		return nil, fmt.Errorf("n_public=%d < 2, no voteID in public inputs", nPublic)
	}

	// Skip VK: alpha_g1(64) + beta_g2(128) + gamma_g2(128) + delta_g2(128)
	off += 64 + 128 + 128 + 128
	// gamma_abc count (u64) + (nPublic+1) G1 entries
	nAbc := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	if nAbc != nPublic+1 {
		return nil, fmt.Errorf("gamma_abc_len=%d != n_public+1=%d", nAbc, nPublic+1)
	}
	off += nAbc * 64

	// Proofs section: count (u64) + nproofs × proof
	off += 8 // nproofs_check
	proofSize := 64 + 128 + 64 + nPublic*32

	voteIDs := make([]uint64, n)
	for i := 0; i < n; i++ {
		proofOff := off + i*proofSize
		// Skip a(G1=64) + b(G2=128) + c(G1=64) + pubs[0](32) → pubs[1] at +288
		voteIDOff := proofOff + 64 + 128 + 64 + 32
		if voteIDOff+8 > len(data) {
			return nil, fmt.Errorf("data too short at proof %d voteID offset %d", i, voteIDOff)
		}
		voteIDs[i] = binary.LittleEndian.Uint64(data[voteIDOff : voteIDOff+8])
	}
	return voteIDs, nil
}

// parseAddrsLo16FromBinary extracts the lower 16 bits of address (public input[0], word[0])
// for the first n proofs from the davinci-zkvm binary input.
func parseAddrsLo16FromBinary(data []byte, n int) ([]uint64, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("data too short for header")
	}
	off := 0
	off += 8 // magic
	off += 8 // logn
	nproofs := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8
	nPublic := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8

	if n > nproofs {
		return nil, fmt.Errorf("requested %d addresses but only %d proofs", n, nproofs)
	}
	if nPublic < 1 {
		return nil, fmt.Errorf("n_public=%d < 1, no address in public inputs", nPublic)
	}

	off += 64 + 128 + 128 + 128
	nAbc := int(binary.LittleEndian.Uint64(data[off:]))
	off += 8 + nAbc*64
	off += 8 // nproofs_check

	proofSize := 64 + 128 + 64 + nPublic*32
	addrs := make([]uint64, n)
	for i := 0; i < n; i++ {
		proofOff := off + i*proofSize
		addrOff := proofOff + 64 + 128 + 64
		if addrOff+8 > len(data) {
			return nil, fmt.Errorf("data too short at proof %d addr offset %d", i, addrOff)
		}
		addrs[i] = binary.LittleEndian.Uint64(data[addrOff:addrOff+8]) & 0xFFFF
	}
	return addrs, nil
}

// ─── BabyJubJub point helpers ─────────────────────────────────────────────

// rtePointToFr32Hex converts a bjj_gnark (RTE) point to TE hex strings
// (32-byte BE, "0x" prefix). The circuit expects Twisted Edwards coordinates.
func rtePointToFr32Hex(p interface{ Point() (*big.Int, *big.Int) }) (xHex, yHex string) {
	rx, ry := p.Point()
	tx, ty := format.FromRTEtoTE(rx, ry)
	xHex = bigIntToFr32(tx)
	yHex = bigIntToFr32(ty)
	return
}
