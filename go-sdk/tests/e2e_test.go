package tests

// TestFullE2E is the full end-to-end integration test for the DAVINCI zkVM circuit.
//
// It combines all verifiable components in a single ziskemu run:
//  1. Groth16 batch proof verification (from pre-built zisk_full_verify_input.bin)
//  2. ECDSA signature verification (embedded in the same base input)
//  3. STATETX state transition: process config + voteID insertions + ballot insertions
//  4. CENSUS lean-IMT Poseidon membership proofs (one per voter)
//  5. REENCBLK BabyJubJub ElGamal re-encryption verification
//
// Expected: output[0] = 1 (overall_ok), output[1] = 0 (fail_mask).

import (
"crypto/rand"
"encoding/hex"
"math/big"
"os"
"path/filepath"
"testing"

arbo "github.com/vocdoni/arbo"
"github.com/vocdoni/arbo/memdb"
bjjgnark "github.com/vocdoni/davinci-node/crypto/ecc/bjj_gnark"
"github.com/vocdoni/davinci-node/crypto/elgamal"
davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
leanimt "github.com/vocdoni/lean-imt-go"
)

func TestFullE2E(t *testing.T) {
dataDir := testDataDir()
inputBin := filepath.Join(dataDir, "aggregated_bn254", "zisk_full_verify_input.bin")
if _, err := os.Stat(inputBin); err != nil {
t.Skipf("input.bin not found at %s — run 'make gen-input' first", inputBin)
}
baseInput, err := os.ReadFile(inputBin)
if err != nil {
t.Fatalf("read input.bin: %v", err)
}

const nVotes = 3
const nFields = 8
const procLevels = 256

// ─── 1. STATETX block ────────────────────────────────────────────────────
// Build process tree (SHA-256 Arbo) with config entries + voteID/ballot insertions.
procDB := memdb.New()
procTree, err := arbo.NewTree(arbo.Config{
Database:     procDB,
MaxLevels:    procLevels,
HashFunction: arbo.HashFunctionSha256,
})
if err != nil {
t.Fatalf("arbo.NewTree: %v", err)
}

// Insert config entries: processID(0), ballotMode(2), encKey(3), censusOrigin(6).
configKeys := []uint64{0x00, 0x02, 0x03, 0x06}
configVals := []uint64{0xABCDEF, 0x01, 0x1234, 0x01}
bLen := arbo.HashFunctionSha256.Len()
for i, k := range configKeys {
if err := procTree.Add(
arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(k)),
arbo.BigIntToBytes(bLen, new(big.Int).SetUint64(configVals[i])),
); err != nil {
t.Fatalf("procTree.Add config[%d]: %v", i, err)
}
}

oldRootBytes, _ := procTree.Root()
oldRootHex := "0x" + hex.EncodeToString(pad32(oldRootBytes))

processSmt, err := buildArboReadProofs(procTree, configKeys, bLen, procLevels)
if err != nil {
t.Fatalf("buildArboReadProofs: %v", err)
}

// Extract voteIDs and address lower-16 from the Groth16 base input.
voteIDs, err := parseVoteIDsFromBinary(baseInput, nVotes)
if err != nil {
t.Fatalf("parseVoteIDsFromBinary: %v", err)
}
addrsLo16, err := parseAddrsLo16FromBinary(baseInput, nVotes)
if err != nil {
t.Fatalf("parseAddrsLo16FromBinary: %v", err)
}

var voteIDChain []davinci.SmtEntry
for i := 0; i < nVotes; i++ {
entry, err := buildArboInsertEntry(procTree,
new(big.Int).SetUint64(voteIDs[i]),
new(big.Int).SetUint64(uint64(1000+i)),
procLevels)
if err != nil {
t.Fatalf("voteID insert[%d]: %v", i, err)
}
voteIDChain = append(voteIDChain, entry)
}

const ballotMin = uint64(0x10)
var ballotChain []davinci.SmtEntry
for i := 0; i < nVotes; i++ {
key := ballotMin + uint64(i)<<16 + addrsLo16[i]
entry, err := buildArboInsertEntry(procTree,
new(big.Int).SetUint64(key),
new(big.Int).SetUint64(uint64(2000+i)),
procLevels)
if err != nil {
t.Fatalf("ballot insert[%d]: %v", i, err)
}
ballotChain = append(ballotChain, entry)
}

newRootBytes, _ := procTree.Root()
newRootHex := "0x" + hex.EncodeToString(pad32(newRootBytes))

stateBlock, err := davinci.EncodeStateBlock(&davinci.StateTransitionData{
VotersCount:      nVotes,
OverwrittenCount: 0,
ProcessID:        oldRootHex,
OldStateRoot:     oldRootHex,
NewStateRoot:     newRootHex,
VoteIDSmt:        voteIDChain,
BallotSmt:        ballotChain,
ProcessSmt:       processSmt,
})
if err != nil {
t.Fatalf("EncodeStateBlock: %v", err)
}

// ─── 2. CENSUS block ─────────────────────────────────────────────────────
// Build a lean-IMT Poseidon tree and generate membership proofs.
imt, err := leanimt.New(poseidonHasher, bigIntEq, nil, nil, nil)
if err != nil {
t.Fatalf("leanimt.New: %v", err)
}
leaves := make([]*big.Int, nVotes)
for i := 0; i < nVotes; i++ {
addr := new(big.Int).SetBytes([]byte{byte(0x10 + i), byte(0x20 + i)})
leaves[i] = packAddressWeight(addr, big.NewInt(int64(100+i)))
imt.Insert(leaves[i])
}
root, ok := imt.Root()
if !ok {
t.Fatal("census tree root not available")
}

censusProofs := make([]davinci.CensusProof, nVotes)
for i := 0; i < nVotes; i++ {
proof, err := imt.GenerateProof(i)
if err != nil {
t.Fatalf("imt.GenerateProof[%d]: %v", i, err)
}
sibs := make([]string, len(proof.Siblings))
for j, s := range proof.Siblings {
sibs[j] = bigIntToFr32(s)
}
censusProofs[i] = davinci.CensusProof{
Root:     bigIntToFr32(root),
Leaf:     bigIntToFr32(proof.Leaf),
Index:    proof.Index,
Siblings: sibs,
}
}
censusBlock, err := davinci.EncodeCensusBlock(censusProofs)
if err != nil {
t.Fatalf("EncodeCensusBlock: %v", err)
}

// ─── 3. REENCBLK block ───────────────────────────────────────────────────
pubKey, _, err := elgamal.GenerateKey(bjjgnark.New())
if err != nil {
t.Fatalf("GenerateKey: %v", err)
}
pkX, pkY := rtePointToFr32Hex(pubKey)

entries := make([]davinci.ReencryptionEntry, nVotes)
for v := 0; v < nVotes; v++ {
ballot := elgamal.NewBallot(bjjgnark.New())
for i := 0; i < nFields; i++ {
c1, c2, _, err := elgamal.Encrypt(pubKey, big.NewInt(int64(v*100+i+1)))
if err != nil {
t.Fatalf("Encrypt v=%d i=%d: %v", v, i, err)
}
ballot.Ciphertexts[i] = &elgamal.Ciphertext{C1: c1, C2: c2}
}
rawK, err := rand.Int(rand.Reader, pubKey.Order())
if err != nil {
t.Fatalf("rand.Int: %v", err)
}
reencBallot, _, err := ballot.Reencrypt(pubKey, rawK)
if err != nil {
t.Fatalf("Reencrypt v=%d: %v", v, err)
}

entry := davinci.ReencryptionEntry{K: bigIntToFr32(rawK)}
for i := 0; i < nFields; i++ {
origC1x, origC1y := rtePointToFr32Hex(ballot.Ciphertexts[i].C1)
origC2x, origC2y := rtePointToFr32Hex(ballot.Ciphertexts[i].C2)
reencC1x, reencC1y := rtePointToFr32Hex(reencBallot.Ciphertexts[i].C1)
reencC2x, reencC2y := rtePointToFr32Hex(reencBallot.Ciphertexts[i].C2)
entry.Original[i] = davinci.BjjCiphertext{
C1: davinci.BjjPoint{X: origC1x, Y: origC1y},
C2: davinci.BjjPoint{X: origC2x, Y: origC2y},
}
entry.Reencrypted[i] = davinci.BjjCiphertext{
C1: davinci.BjjPoint{X: reencC1x, Y: reencC1y},
C2: davinci.BjjPoint{X: reencC2x, Y: reencC2y},
}
}
entries[v] = entry
}
reencBlock, err := davinci.EncodeReencBlock(&davinci.ReencryptionData{
EncryptionKeyX: pkX,
EncryptionKeyY: pkY,
Entries:        entries,
})
if err != nil {
t.Fatalf("EncodeReencBlock: %v", err)
}

// ─── 4. Combine and run ──────────────────────────────────────────────────
combined := append(baseInput, stateBlock...)
combined = append(combined, censusBlock...)
combined = append(combined, reencBlock...)
t.Logf("combined: %d bytes (base=%d state=%d census=%d reenc=%d)",
len(combined), len(baseInput), len(stateBlock), len(censusBlock), len(reencBlock))

outputs, err := runZiskEmu(combined)
if err != nil {
t.Fatalf("ziskemu: %v", err)
}
t.Logf("outputs: %v", outputsHex(outputs))

if outputs[0] != 1 {
t.Errorf("output[0] (overall_ok)=%d want 1  fail_mask=0x%08x", outputs[0], outputs[1])
}
if outputs[1] != 0 {
t.Errorf("output[1] (fail_mask)=0x%08x want 0", outputs[1])
}
if outputs[14] != uint32(nVotes) {
t.Errorf("output[14] (voters_count)=%d want %d", outputs[14], nVotes)
}
}
