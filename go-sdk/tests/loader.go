package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// loadProveRequestFromDir builds a ProveRequest by reading proof, public, and sig
// files from dir. It expects:
//   - verification_key.json
//   - proof_1.json .. proof_N.json
//   - public_1.json .. public_N.json
//   - sig_1.json .. sig_N.json  (mandatory)
//
// Only the first n proofs (sorted numerically) are loaded.
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

// collectPaths returns all *.json files in dir whose base name starts with prefix,
// sorted numerically by the trailing integer.
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
