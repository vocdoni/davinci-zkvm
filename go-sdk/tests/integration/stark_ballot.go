package integration

import (
	ecdsapkg "crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vocdoni/davinci-node/crypto"
	"github.com/vocdoni/davinci-node/types"
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

const starkBallotMaxFields = 8

// StarkBallotResult holds the output of one davinci-stark ballot proof generation.
type StarkBallotResult struct {
	VoteID      uint64
	AddressLo16 uint64
	Fields      [8]uint64
	ProofData   []byte
	Bundle      *davinci.StarkProofBundle
	SigJSON     json.RawMessage
}

// StarkBatchProveComponents holds the STARK-native ballot data for one batch.
type StarkBatchProveComponents struct {
	StarkProofs []davinci.StarkProofBundleJson
	Sigs        []json.RawMessage
	Results     []*StarkBallotResult
}

func (b *StarkBatchProveComponents) ToProveRequest() *davinci.ProveRequest {
	return &davinci.ProveRequest{
		StarkProofs: b.StarkProofs,
		Sigs:        b.Sigs,
	}
}

var starkNodeRunner = runStarkNode

// deterministicBallotFields mirrors the existing integration expected-tally formula.
func deterministicBallotFields(seed int64) [8]uint64 {
	var fields [8]uint64
	used := map[uint64]bool{}
	for f := int64(0); f < 6; f++ {
		for attempt := int64(0); ; attempt++ {
			val := uint64((seed + f*1000 + attempt) % 16)
			if !used[val] {
				fields[f] = val
				used[val] = true
				break
			}
		}
	}
	return fields
}

type starkBallotMode struct {
	NumFields      uint64 `json:"numFields"`
	GroupSize      uint64 `json:"groupSize"`
	UniqueValues   uint64 `json:"uniqueValues"`
	CostFromWeight uint64 `json:"costFromWeight"`
	CostExponent   uint64 `json:"costExponent"`
	MaxValue       uint64 `json:"maxValue"`
	MinValue       uint64 `json:"minValue"`
	MaxValueSum    uint64 `json:"maxValueSum"`
	MinValueSum    uint64 `json:"minValueSum"`
}

func defaultStarkBallotMode() starkBallotMode {
	return starkBallotMode{
		NumFields:      6,
		GroupSize:      1,
		UniqueValues:   0,
		CostFromWeight: 0,
		CostExponent:   2,
		MaxValue:       16,
		MinValue:       0,
		MaxValueSum:    1125,
		MinValueSum:    5,
	}
}

func packStarkBallotMode(cfg starkBallotMode) [4]uint64 {
	bits := big.NewInt(0)
	orShift := func(v uint64, shift uint) {
		tmp := new(big.Int).SetUint64(v)
		tmp.Lsh(tmp, shift)
		bits.Or(bits, tmp)
	}
	orShift(cfg.NumFields&0xff, 0)
	orShift(cfg.GroupSize&0xff, 8)
	orShift(cfg.UniqueValues&0x1, 16)
	orShift(cfg.CostFromWeight&0x1, 17)
	orShift(cfg.CostExponent&0xff, 18)
	orShift(cfg.MaxValue&0xffffffffffff, 26)
	orShift(cfg.MinValue&0xffffffffffff, 74)
	orShift(cfg.MaxValueSum&0x7fffffffffffffff, 122)
	orShift(cfg.MinValueSum&0x7fffffffffffffff, 185)
	mask62 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 62), big.NewInt(1))
	var out [4]uint64
	for i := 0; i < 4; i++ {
		chunk := new(big.Int).Rsh(new(big.Int).Set(bits), uint(i*62))
		chunk.And(chunk, mask62)
		out[i] = chunk.Uint64()
	}
	return out
}

func u64ArrayToLEHex(values []uint64) string {
	buf := make([]byte, len(values)*8)
	for i, v := range values {
		binary.LittleEndian.PutUint64(buf[i*8:], v)
	}
	return hex.EncodeToString(buf)
}

func processIDToLEHex(processID types.ProcessID) string {
	buf := make([]byte, 32)
	copy(buf[:len(processID)], processID[:])
	return hex.EncodeToString(buf)
}

func addressToLEHex(address []byte) string {
	buf := make([]byte, 32)
	copy(buf[:len(address)], address)
	return hex.EncodeToString(buf)
}

func weightToLEHex(weight *big.Int) string {
	buf := make([]byte, 8)
	if weight != nil {
		binary.LittleEndian.PutUint64(buf, weight.Uint64())
	}
	return hex.EncodeToString(buf)
}

func deterministicKHex(seed int64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("davinci-stark-k:%d", seed)))
	return hex.EncodeToString(sum[:])
}

func findDavinciStarkRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../"))
}

func nodeStarkScriptPath() string {
	return filepath.Join(filepath.Dir(currentFile()), "davinciStarkWasm.mjs")
}

func currentFile() string {
	_, file, _, _ := runtime.Caller(0)
	return file
}

func generateStarkKeypair(skSeed []byte) (string, error) {
	root := findDavinciStarkRoot()
	payload := map[string]any{
		"command":   "generate-keypair",
		"sk_hex":    hex.EncodeToString(skSeed),
		"repo_root": root,
	}
	out, err := runStarkNode(payload)
	if err != nil {
		return "", err
	}
	return out["pk_hex"].(string), nil
}

func runStarkNode(payload map[string]any) (map[string]any, error) {
	input, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("node", nodeStarkScriptPath())
	cmd.Stdin = strings.NewReader(string(input))
	cmd.Dir = filepath.Dir(nodeStarkScriptPath())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("node helper failed: %w\n%s", err, output)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output, &decoded); err != nil {
		return nil, fmt.Errorf("decode node output: %w\n%s", err, output)
	}
	return decoded, nil
}

func starkMaxConcurrencyFromEnv() int {
	if s := os.Getenv("DAVINCI_STARK_MAX_CONCURRENCY"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 1 {
			return n
		}
	}
	return 8
}

// GenerateStarkBallotBatch generates one davinci-stark ballot proof per voter.
// Proof generation is bounded by DAVINCI_STARK_MAX_CONCURRENCY and preserves
// the input voter order in the returned slices.
func GenerateStarkBallotBatch(processID types.ProcessID, pkHex string, voters []*Voter, seedBase int64) (*StarkBatchProveComponents, error) {
	results := make([]*StarkBallotResult, len(voters))
	starkProofs := make([]davinci.StarkProofBundleJson, len(voters))
	sigs := make([]json.RawMessage, len(voters))
	mode := packStarkBallotMode(defaultStarkBallotMode())
	root := findDavinciStarkRoot()
	maxConcurrency := starkMaxConcurrencyFromEnv()
	fmt.Println(starkBatchStartLog(len(voters), maxConcurrency, seedBase))
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	var done atomic.Int64
	errCh := make(chan error, len(voters))

	for i, v := range voters {
		wg.Add(1)
		go func(i int, v *Voter) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			seed := seedBase + int64(i)
			fields := deterministicBallotFields(seed)
			payload := map[string]any{
				"command":         "prove-full",
				"repo_root":       root,
				"k_hex":           deterministicKHex(seed),
				"fields_le_hex":   u64ArrayToLEHex(fields[:]),
				"pk_hex":          pkHex,
				"process_id_hex":  processIDToLEHex(processID),
				"address_hex":     addressToLEHex(v.AddressBytes),
				"weight_hex":      weightToLEHex(v.Weight),
				"ballot_mode_hex": u64ArrayToLEHex(mode[:]),
			}
			out, err := starkNodeRunner(payload)
			if err != nil {
				errCh <- fmt.Errorf("voter %d stark proof: %w", i, err)
				return
			}
			proofHex, ok := out["proof_data_hex"].(string)
			if !ok {
				errCh <- fmt.Errorf("voter %d missing proof_data_hex", i)
				return
			}
			proofData, err := hex.DecodeString(proofHex)
			if err != nil {
				errCh <- fmt.Errorf("voter %d decode proof: %w", i, err)
				return
			}
			bundle, err := davinci.DecodeStarkProofBundle(proofData)
			if err != nil {
				errCh <- fmt.Errorf("voter %d decode bundle: %w", i, err)
				return
			}
			voteID := bundle.PublicValues.VoteID
			addrBig := new(big.Int).SetBytes(v.AddressBytes)
			addrLo16 := addrBig.Uint64() & 0xFFFF
			sig, err := v.Signer.Sign(crypto.PadToSign(new(big.Int).SetUint64(voteID).Bytes()))
			if err != nil {
				errCh <- fmt.Errorf("voter %d ecdsa sign: %w", i, err)
				return
			}
			ecdsaKey := (*ecdsapkg.PrivateKey)(v.Signer)
			sigData := sigJSON{
				PublicKeyX: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.X),
				PublicKeyY: fmt.Sprintf("0x%064x", ecdsaKey.PublicKey.Y),
				SignatureR: fmt.Sprintf("0x%064x", sig.R),
				SignatureS: fmt.Sprintf("0x%064x", sig.S),
				SignatureV: 0,
				VoteID:     voteID,
				Address:    addrBig.String(),
			}
			sigBytes, err := json.Marshal(sigData)
			if err != nil {
				errCh <- fmt.Errorf("marshal sig %d: %w", i, err)
				return
			}
			starkProofs[i] = davinci.StarkProofBundleJson{
				Proof:        "0x" + hex.EncodeToString(bundle.ProofBytes),
				PublicValues: "0x" + hex.EncodeToString(bundle.PublicValues.Encode()),
			}
			sigs[i] = sigBytes
			results[i] = &StarkBallotResult{
				VoteID:      voteID,
				AddressLo16: addrLo16,
				Fields:      fields,
				ProofData:   proofData,
				Bundle:      bundle,
				SigJSON:     sigBytes,
			}
			completed := int(done.Add(1))
			fmt.Println(starkVoteCreatedLog(completed, len(voters), i, voteID))
		}(i, v)
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return nil, err
		}
	}
	return &StarkBatchProveComponents{StarkProofs: starkProofs, Sigs: sigs, Results: results}, nil
}
