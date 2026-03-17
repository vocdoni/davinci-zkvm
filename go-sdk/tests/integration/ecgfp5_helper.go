package integration

import (
	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type ecgfp5CipherJSON struct {
	C1 string `json:"c1"`
	C2 string `json:"c2"`
}

type ecgfp5BallotJSON struct {
	Fields []ecgfp5CipherJSON `json:"fields"`
}

type ecgfp5HashResponse struct {
	HashHex string `json:"hash_hex"`
}

type ecgfp5BallotResponse struct {
	Ballot ecgfp5BallotJSON `json:"ballot"`
}

type ecgfp5PubKeyResponse struct {
	PkHex string `json:"pk_hex"`
}

type ecgfp5TotalsResponse struct {
	Totals []uint64 `json:"totals"`
}

func ecgfp5HelperPath() string {
	root := findDavinciStarkRoot()
	return filepath.Join(root, "target", "debug", "ecgfp5_helper")
}

func ensureEcgfp5Helper() (string, error) {
	path := ecgfp5HelperPath()
	root := findDavinciStarkRoot()
	cmd := exec.Command("cargo", "build", "--bin", "ecgfp5_helper")
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build ecgfp5_helper: %w\n%s", err, out)
	}
	return path, nil
}

func runEcgfp5Helper(payload any, out any) error {
	path, err := ensureEcgfp5Helper()
	if err != nil {
		return err
	}
	input, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	cmd := exec.Command(path)
	cmd.Dir = findDavinciStarkRoot()
	cmd.Stdin = strings.NewReader(string(input))
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ecgfp5_helper failed: %w\n%s", err, raw)
	}
	return json.Unmarshal(raw, out)
}

func ciphertextsFromBundle(bundle *davinci.StarkProofBundle) ecgfp5BallotJSON {
	encs := bundle.PublicValues.CiphertextEncodings()
	fields := make([]ecgfp5CipherJSON, 8)
	for i := 0; i < 8; i++ {
		c1 := make([]byte, 40)
		c2 := make([]byte, 40)
		for j := 0; j < 5; j++ {
			copy(c1[j*8:(j+1)*8], u64le(encs[i*2][j]))
			copy(c2[j*8:(j+1)*8], u64le(encs[i*2+1][j]))
		}
		fields[i] = ecgfp5CipherJSON{C1: hex.EncodeToString(c1), C2: hex.EncodeToString(c2)}
	}
	return ecgfp5BallotJSON{Fields: fields}
}

func ballotJSONToCiphertexts(ballot ecgfp5BallotJSON) [8]davinci.Ecgfp5Ciphertext {
	var out [8]davinci.Ecgfp5Ciphertext
	for i := 0; i < 8; i++ {
		out[i] = davinci.Ecgfp5Ciphertext{C1: "0x" + ballot.Fields[i].C1, C2: "0x" + ballot.Fields[i].C2}
	}
	return out
}

func ciphertextsToBallotJSON(ballot [8]davinci.Ecgfp5Ciphertext) ecgfp5BallotJSON {
	fields := make([]ecgfp5CipherJSON, 8)
	for i, ct := range ballot {
		fields[i] = ecgfp5CipherJSON{
			C1: strings.TrimPrefix(ct.C1, "0x"),
			C2: strings.TrimPrefix(ct.C2, "0x"),
		}
	}
	return ecgfp5BallotJSON{Fields: fields}
}

func ecgfp5HashEncKey(pkHex string) (*big.Int, error) {
	var out ecgfp5HashResponse
	if err := runEcgfp5Helper(map[string]any{"command": "hash_enc_key", "pk_hex": pkHex}, &out); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(out.HashHex, "0x"))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func ecgfp5DerivePubkey(skHex string) (string, error) {
	var out ecgfp5PubKeyResponse
	if err := runEcgfp5Helper(map[string]any{"command": "derive_pubkey", "sk_hex": strings.TrimPrefix(skHex, "0x")}, &out); err != nil {
		return "", err
	}
	return "0x" + out.PkHex, nil
}

func ecgfp5LeafHash(ballot [8]davinci.Ecgfp5Ciphertext) (*big.Int, error) {
	var out ecgfp5HashResponse
	if err := runEcgfp5Helper(map[string]any{"command": "leaf_hash", "ballot": ciphertextsToBallotJSON(ballot)}, &out); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(out.HashHex, "0x"))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

func ecgfp5ReencryptBallot(pkHex, kHex string, ballot [8]davinci.Ecgfp5Ciphertext) ([8]davinci.Ecgfp5Ciphertext, error) {
	var out ecgfp5BallotResponse
	if err := runEcgfp5Helper(map[string]any{
		"command": "reencrypt_ballot",
		"pk_hex":  pkHex,
		"k_hex":   strings.TrimPrefix(kHex, "0x"),
		"ballot":  ciphertextsToBallotJSON(ballot),
	}, &out); err != nil {
		return [8]davinci.Ecgfp5Ciphertext{}, err
	}
	return ballotJSONToCiphertexts(out.Ballot), nil
}

func ecgfp5AddBallots(ballots [][8]davinci.Ecgfp5Ciphertext) ([8]davinci.Ecgfp5Ciphertext, error) {
	payloadBallots := make([]ecgfp5BallotJSON, len(ballots))
	for i, ballot := range ballots {
		payloadBallots[i] = ciphertextsToBallotJSON(ballot)
	}
	var out ecgfp5BallotResponse
	if err := runEcgfp5Helper(map[string]any{"command": "add_ballots", "ballots": payloadBallots}, &out); err != nil {
		return [8]davinci.Ecgfp5Ciphertext{}, err
	}
	return ballotJSONToCiphertexts(out.Ballot), nil
}

func ecgfp5SubBallots(base [8]davinci.Ecgfp5Ciphertext, subtract [][8]davinci.Ecgfp5Ciphertext) ([8]davinci.Ecgfp5Ciphertext, error) {
	payloadSubtract := make([]ecgfp5BallotJSON, len(subtract))
	for i, ballot := range subtract {
		payloadSubtract[i] = ciphertextsToBallotJSON(ballot)
	}
	var out ecgfp5BallotResponse
	if err := runEcgfp5Helper(map[string]any{
		"command":  "sub_ballots",
		"base":     ciphertextsToBallotJSON(base),
		"subtract": payloadSubtract,
	}, &out); err != nil {
		return [8]davinci.Ecgfp5Ciphertext{}, err
	}
	return ballotJSONToCiphertexts(out.Ballot), nil
}

func ecgfp5DecryptTotals(skHex string, ballot [8]davinci.Ecgfp5Ciphertext, maxTotal uint64) ([]uint64, error) {
	var out ecgfp5TotalsResponse
	if err := runEcgfp5Helper(map[string]any{
		"command":   "decrypt_totals",
		"sk_hex":    strings.TrimPrefix(skHex, "0x"),
		"ballot":    ciphertextsToBallotJSON(ballot),
		"max_total": maxTotal,
	}, &out); err != nil {
		return nil, err
	}
	return out.Totals, nil
}

func u64le(v uint64) []byte {
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return b
}

func currentFilePath() string {
	_, file, _, _ := runtime.Caller(0)
	return file
}
