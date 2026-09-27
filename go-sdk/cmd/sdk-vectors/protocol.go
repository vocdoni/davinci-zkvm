package main

import (
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/witness"
	leanimt "github.com/vocdoni/lean-imt-go"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"github.com/vocdoni/davinci-zkvm/go-sdk/chain"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/ballotproof"
	ballotprooftest "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/circuits/test/ballotproof"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto"
	bjj "github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/crypto/signatures/ethereum"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/spec"
	"github.com/vocdoni/davinci-zkvm/go-sdk/vocdoni/types"
)

func ballotVKLeaf(vk []byte) *big.Int {
	v, err := davinci.BallotVKLeaf(vk)
	must(err)
	return v
}

func circomV1VK() []byte { return ballotproof.CircomVerificationKey }

func le32hex(v *big.Int) string { return hex.EncodeToString(reverse(be32(v))) }

// Registry-style process id: creator(20) ‖ prefix(4) ‖ nonce(7).
func processID(creator []byte, prefix [4]byte, nonce uint64) types.ProcessID {
	return types.NewProcessID(common.BytesToAddress(creator), prefix, nonce)
}

type genesisVec struct {
	ProcessID    string            `json:"process_id"` // 31 bytes, BE hex
	ProcessIDDec string            `json:"process_id_dec"`
	BallotMode   modeJSON          `json:"ballot_mode"`
	EncKey       pointJSON         `json:"enc_key"`
	CensusOrigin uint64            `json:"census_origin"`
	BallotVKHash string            `json:"ballot_vk_hash"` // leaf integer, BE32 hex
	Leaves       map[string]string `json:"leaves"`         // key -> arbo LE32 value hex
	Root         string            `json:"root"`           // raw arbo root bytes, hex
}

func genesisVectors() []genesisVec {
	_, pk := fixedKey()
	pkx, pky := teOf(pk)
	vkRaw, err := os.ReadFile(*vkAsset)
	must(err)
	vkHash := ballotVKLeaf(vkRaw)
	var out []genesisVec
	creator := []byte{0x5f, 0x1b, 0xe5, 0x13, 0x0c, 0x4a, 0x4f, 0x2a, 0x9e, 0x31, 0x77, 0x02, 0x5d, 0x48, 0x61, 0x3c, 0xa2, 0x90, 0x3e, 0x11}
	for mi, bm := range []spec.BallotMode{ballotModes[1], ballotModes[2], ballotModes[3]} {
		for _, origin := range []uint64{1, 4} {
			pid := processID(creator, [4]byte{0xde, 0xad, 0xbe, byte(mi)}, uint64(1000+mi*10)+origin)
			packed, err := bm.Pack()
			must(err)
			st, err := chain.NewState(chain.Config{
				ProcessID:    pid.MathBigInt(),
				BallotMode:   packed,
				EncKey:       pk,
				CensusOrigin: origin,
				CensusRoot:   big.NewInt(1),
				BallotVKHash: vkHash,
			})
			must(err)
			root := st.Root()[2:]
			encKeyHash := new(big.Int).SetBytes(sha256Sum(append(be32(pkx), be32(pky)...)))
			idHash, _ := new(big.Int).SetString(ballotLeafHash(identityCoords()), 16)
			out = append(out, genesisVec{
				ProcessID:    hex.EncodeToString(pid[:]),
				ProcessIDDec: dec(pid.MathBigInt()),
				BallotMode:   modeOf(bm),
				EncKey:       pj(pkx, pky),
				CensusOrigin: origin,
				BallotVKHash: hex32(vkHash),
				Leaves: map[string]string{
					"0x00": le32hex(pid.MathBigInt()),
					"0x02": le32hex(packed),
					"0x03": le32hex(encKeyHash),
					"0x04": le32hex(idHash),
					"0x06": le32hex(new(big.Int).SetUint64(origin)),
					"0x07": le32hex(vkHash),
				},
				Root: root,
			})
		}
	}
	return out
}

// Deterministic census leaves: PackAddressWeight(addr_i, i+1).
func censusLeaf(i int) (*big.Int, []byte, *big.Int) {
	addr := ethcrypto.Keccak256([]byte(fmt.Sprintf("voter-%d", i)))[12:]
	w := big.NewInt(int64(i + 1))
	return davinci.PackAddressWeight(new(big.Int).SetBytes(addr), w), addr, w
}

type imtProof struct {
	Index    int      `json:"index"`
	Leaf     string   `json:"leaf"`
	PathBits uint64   `json:"path_bits"`
	Siblings []string `json:"siblings"`
	Slot     uint64   `json:"slot"`
}

type imtTree struct {
	Size   int        `json:"size"`
	Root   string     `json:"root"`
	Proofs []imtProof `json:"proofs,omitempty"`
}

func leanIMTVectors() map[string]any {
	withProofs := map[int]bool{1: true, 2: true, 3: true, 5: true, 8: true, 13: true, 33: true}
	var leaves []string
	for i := 0; i < 40; i++ {
		l, _, _ := censusLeaf(i)
		leaves = append(leaves, dec(l))
	}
	var trees []imtTree
	for size := 1; size <= 40; size++ {
		t, err := leanimt.New(leanimt.PoseidonHasher, leanimt.BigIntEqual, nil, nil, nil)
		must(err)
		for i := 0; i < size; i++ {
			l, _, _ := censusLeaf(i)
			t.Insert(l)
		}
		root, _ := t.Root()
		tv := imtTree{Size: size, Root: dec(root)}
		if withProofs[size] {
			for i := 0; i < size; i++ {
				p, err := t.GenerateProof(i)
				must(err)
				if !t.VerifyProof(p) {
					panic("lean-imt proof does not verify")
				}
				tv.Proofs = append(tv.Proofs, imtProof{
					Index: i, Leaf: dec(p.Leaf), PathBits: p.PathBits,
					Siblings: decs(p.Siblings), Slot: davinci.SlotKey(p.PathBits, len(p.Siblings)),
				})
			}
		}
		trees = append(trees, tv)
	}
	return map[string]any{"leaves": leaves, "trees": trees}
}

// Fixed secp256k1 keys (never used anywhere else).
func fixedECDSA(tag string) *ecdsa.PrivateKey {
	k, err := ethcrypto.ToECDSA(ethcrypto.Keccak256([]byte(tag)))
	must(err)
	return k
}

type cspVec struct {
	ProcessID string `json:"process_id"` // decimal
	Address   string `json:"address"`    // 20 bytes hex
	Weight    string `json:"weight"`     // decimal
	Index     uint64 `json:"index"`
	Hash      string `json:"hash"`
	R         string `json:"r"`
	S         string `json:"s"`
	Recid     uint8  `json:"recid"`
	Slot      uint64 `json:"slot"`
}

// cspSign mirrors tests/integration/election.go BuildCspData.
func cspSign(key *ecdsa.PrivateKey, pid *big.Int, addr []byte, weight *big.Int, index uint64) cspVec {
	var payload [92]byte
	copy(payload[:32], be32(pid))
	copy(payload[32:52], addr)
	weight.FillBytes(payload[52:84])
	binary.BigEndian.PutUint64(payload[84:92], index)
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(payload))
	hash := ethcrypto.Keccak256(append([]byte(prefix), payload[:]...))
	sig, err := ethcrypto.Sign(hash, key)
	must(err)
	return cspVec{
		ProcessID: dec(pid), Address: hex.EncodeToString(addr), Weight: dec(weight), Index: index,
		Hash: hex.EncodeToString(hash), R: hex.EncodeToString(sig[:32]), S: hex.EncodeToString(sig[32:64]),
		Recid: sig[64], Slot: davinci.CSPSlotKey(index),
	}
}

func censusVectors() map[string]any {
	type leafVec struct {
		Address string `json:"address"`
		Weight  string `json:"weight"`
		Leaf    string `json:"leaf"`
	}
	var leaves []leafVec
	for i := 0; i < 6; i++ {
		addr := randBytes(20)
		w := new(big.Int).Rand(rng, new(big.Int).Lsh(big.NewInt(1), 88))
		if i == 0 {
			w = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 88), big.NewInt(1))
			for j := range addr {
				addr[j] = 0xff
			}
		}
		leaves = append(leaves, leafVec{hex.EncodeToString(addr), dec(w), dec(davinci.PackAddressWeight(new(big.Int).SetBytes(addr), w))})
	}
	type slotVec struct {
		PathBits uint64 `json:"path_bits"`
		Depth    int    `json:"depth"`
		Slot     uint64 `json:"slot"`
	}
	var slots []slotVec
	for _, s := range [][2]uint64{{0, 0}, {1, 1}, {5, 3}, {0, 10}, {1<<61 - 1, 61}} {
		slots = append(slots, slotVec{s[0], int(s[1]), davinci.SlotKey(s[0], int(s[1]))})
	}
	key := fixedECDSA("davinci-sdk-vectors-csp")
	pid := processID(randBytes(20), [4]byte{1, 2, 3, 4}, 77).MathBigInt()
	var csps []cspVec
	for i := 0; i < 5; i++ {
		w := big.NewInt(int64(rng.Intn(1000) + 1))
		if i == 4 {
			w = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 88), big.NewInt(1))
		}
		csps = append(csps, cspSign(key, pid, randBytes(20), w, uint64(i*7)))
	}
	return map[string]any{
		"leaves":      leaves,
		"slots":       slots,
		"csp_key":     hex.EncodeToString(ethcrypto.FromECDSA(key)),
		"csp_address": hex.EncodeToString(ethcrypto.PubkeyToAddress(key.PublicKey).Bytes()),
		"csp":         csps,
	}
}

func voteIDSigVectors() map[string]any {
	key := fixedECDSA("davinci-sdk-vectors-voter")
	type sigVec struct {
		VoteID uint64 `json:"vote_id"`
		R      string `json:"r"`
		S      string `json:"s"`
		V      uint8  `json:"v"`
	}
	var out []sigVec
	for _, vid := range []uint64{1 << 63, 1<<63 + 12345, 1<<64 - 1, 1<<63 | rng.Uint64()} {
		sig, err := ethereum.Sign(crypto.PadToSign(types.VoteID(vid).Bytes()), key)
		must(err)
		b := sig.Bytes()
		out = append(out, sigVec{VoteID: vid, R: hex.EncodeToString(b[:32]), S: hex.EncodeToString(b[32:64]), V: b[64]})
	}
	return map[string]any{
		"key":     hex.EncodeToString(ethcrypto.FromECDSA(key)),
		"address": hex.EncodeToString(ethcrypto.PubkeyToAddress(key.PublicKey).Bytes()),
		"sigs":    out,
	}
}

type ballotVec struct {
	ProcessID  string    `json:"process_id"` // decimal
	Address    string    `json:"address"`    // 20 bytes hex
	K          string    `json:"k"`
	Weight     string    `json:"weight"`
	Mode       modeJSON  `json:"mode"`
	Fields     []uint64  `json:"fields"`
	Pk         pointJSON `json:"pk"`
	VoteID     uint64    `json:"vote_id"`
	Ballot     []string  `json:"ballot"` // 64 TE coords
	InputsHash string    `json:"inputs_hash"`
	Inputs     []string  `json:"inputs"` // the 71 hashed inputs
}

func buildBallot(pk *bjj.BJJ, mode spec.BallotMode, fields []uint64, weight int64) (*ballotproof.BallotProofInputsResult, ballotVec) {
	pid := processID(randBytes(20), [4]byte{9, 8, 7, 6}, uint64(rng.Intn(1<<20)))
	addr := randBytes(20)
	k := randField()
	var fv []*types.BigInt
	for _, f := range fields {
		fv = append(fv, new(types.BigInt).SetUint64(f))
	}
	in := &ballotproof.BallotProofInputs{
		ProcessID:     pid,
		Address:       addr,
		EncryptionKey: types.SliceOf(pk.BigInts(), types.BigIntConverter),
		K:             new(types.BigInt).SetBigInt(k),
		BallotMode:    mode,
		Weight:        new(types.BigInt).SetInt(int(weight)),
		FieldValues:   fv,
	}
	res, err := ballotproof.GenerateBallotProofInputs(in)
	must(err)
	x, y := teOf(pk)
	coords := res.Ballot.BigInts()
	packed, err := mode.Pack()
	must(err)
	inputs := []*big.Int{pid.MathBigInt(), packed, x, y, new(big.Int).SetBytes(addr), new(big.Int).SetUint64(res.VoteID.Uint64())}
	inputs = append(inputs, coords...)
	inputs = append(inputs, big.NewInt(weight))
	return res, ballotVec{
		ProcessID: dec(pid.MathBigInt()), Address: hex.EncodeToString(addr), K: dec(k),
		Weight: fmt.Sprint(weight), Mode: modeOf(mode), Fields: fields, Pk: pj(x, y),
		VoteID: res.VoteID.Uint64(), Ballot: decs(coords), InputsHash: dec(res.BallotInputsHash.MathBigInt()),
		Inputs: decs(inputs),
	}
}

func ballotVectors() []ballotVec {
	_, pk := fixedKey()
	var out []ballotVec
	for i, mode := range []spec.BallotMode{ballotModes[1], ballotModes[2], ballotModes[3]} {
		fields := randFields(int(mode.NumFields), int(min(mode.MaxValue, 1000))+1)
		_, v := buildBallot(pk, mode, fields, int64(1+i*41))
		out = append(out, v)
	}
	return out
}

type realProof struct {
	Vk            json.RawMessage `json:"vk"`
	Proof         json.RawMessage `json:"proof"`
	PublicSignals []string        `json:"public_signals"`
	Ballot        *ballotVec      `json:"ballot,omitempty"`
}

// realProofVector proves one ballot with the davinci-circom artifacts that
// match the SDK's embedded VK.
func realProofVector() realProof {
	_, pk := fixedKey()
	mode := ballotModes[2]
	res, v := buildBallot(pk, mode, []uint64{1, 2, 3, 4, 5, 6}, 42)
	inputs, err := json.Marshal(res.CircomInputs)
	must(err)
	wasm, err := os.ReadFile(filepath.Join(*circomDir, "ballot_proof.wasm"))
	must(err)
	zkey, err := os.ReadFile(filepath.Join(*circomDir, "ballot_proof_pkey.zkey"))
	must(err)
	vk, err := os.ReadFile(*vkAsset)
	must(err)
	parsed, err := witness.ParseInputs(inputs)
	must(err)
	calc, err := witness.NewCircom2WitnessCalculator(wasm, true)
	must(err)
	wtns, err := calc.CalculateWTNSBin(parsed, true)
	must(err)
	proof, pubs, err := prover.Groth16ProverRaw(zkey, wtns)
	must(err)
	var signals []string
	must(json.Unmarshal([]byte(pubs), &signals))
	return realProof{Vk: vk, Proof: json.RawMessage(proof), PublicSignals: signals, Ballot: &v}
}

// realProofV1Vector is the go-sdk's own DeterministicBallotProof (davinci-circom
// v1.0.0 artifacts, the VK the zkVM integration tests pin).
func realProofV1Vector() realProof {
	_, pk := fixedKey()
	res, err := ballotprooftest.DeterministicBallotProof(randBytes(20), processID(randBytes(20), [4]byte{0, 0, 0, 1}, 5), pk, 7)
	must(err)
	var signals []string
	must(json.Unmarshal([]byte(res.PubInputs), &signals))
	return realProof{Vk: circomV1VK(), Proof: json.RawMessage(res.Proof), PublicSignals: signals}
}

func sha256Sum(b []byte) []byte {
	h := sha256Hex(b)
	out, _ := hex.DecodeString(h)
	return out
}
