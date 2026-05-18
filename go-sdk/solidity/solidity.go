// Package solidity wraps the on-chain PLONK verifier shipped with the ZisK
// proving-key bundle.
//
// It exposes a single high-level helper, [VerifyOnSimulated], which compiles
// `ZiskVerifier.sol` + `PlonkVerifier.sol` + `IZiskVerifier.sol` (located in
// the davinci-zkvm repo at `solidity/`), deploys the verifier on a
// `go-ethereum/ethclient/simulated.NewBackend`, and invokes
// `verifySnarkProof(programVK, rootCVadcopFinal, publicValues, proofBytes)`.
//
// The simulated backend brings up an in-process Ethereum execution layer with
// the EVM precompiles ECDSA / BN254 add+mul+pairing pre-funded, so no Anvil,
// ganache, or external RPC is required: tests run anywhere `solc` (or
// `docker run ethereum/solc:stable`) is available.
package solidity

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// verifyABI is the minimal interface fragment needed to pack the verifier
// call. The on-chain contract is `ZiskVerifier` from the davinci-zkvm
// `solidity/` directory.
const verifyABI = `[{
    "inputs":[
        {"internalType":"bytes32","name":"programVK","type":"bytes32"},
        {"internalType":"bytes32","name":"rootCVadcopFinal","type":"bytes32"},
        {"internalType":"bytes","name":"publicValues","type":"bytes"},
        {"internalType":"bytes","name":"proofBytes","type":"bytes"}
    ],
    "name":"verifySnarkProof",
    "outputs":[],
    "stateMutability":"view",
    "type":"function"
}]`

// VerifyOnSimulated compiles the verifier sources at solidityDir (which must
// contain `ZiskVerifier.sol`, `PlonkVerifier.sol`, and `IZiskVerifier.sol`),
// deploys the contract on a fresh simulated backend, and invokes
// `verifySnarkProof` with the four fields of the provided [davinci.PlonkSnark].
//
// Returns nil on successful verification. The view function reverts on failure
// (with `InvalidProof()`), which surfaces as a non-nil error from the
// underlying [bind.BoundContract.Call].
//
// `solidityDir` is typically the davinci-zkvm repo's top-level `solidity/`
// directory. `solc` is preferred when on PATH; otherwise the function falls
// back to `docker run --rm ethereum/solc:stable`. Both produce identical
// artifacts.
func VerifyOnSimulated(solidityDir string, snark *davinci.PlonkSnark) error {
	buildDir, err := os.MkdirTemp("", "davinci-solidity-build-*")
	if err != nil {
		return fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	if err := compileVerifier(solidityDir, buildDir); err != nil {
		return fmt.Errorf("compile verifier: %w", err)
	}

	abiBytes, err := os.ReadFile(filepath.Join(buildDir, "ZiskVerifier.abi"))
	if err != nil {
		return fmt.Errorf("read ZiskVerifier.abi: %w", err)
	}
	binHex, err := os.ReadFile(filepath.Join(buildDir, "ZiskVerifier.bin"))
	if err != nil {
		return fmt.Errorf("read ZiskVerifier.bin: %w", err)
	}

	parsedABI, err := abi.JSON(strings.NewReader(string(abiBytes)))
	if err != nil {
		return fmt.Errorf("parse ABI: %w", err)
	}

	priv, err := crypto.GenerateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	chainID := big.NewInt(1337)
	deployer, err := bind.NewKeyedTransactorWithChainID(priv, chainID)
	if err != nil {
		return fmt.Errorf("new transactor: %w", err)
	}

	alloc := gethtypes.GenesisAlloc{
		deployer.From:               {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(10))},
		common.HexToAddress("0x05"): {Balance: big.NewInt(1)}, // MODEXP
		common.HexToAddress("0x06"): {Balance: big.NewInt(1)}, // BN256ADD
		common.HexToAddress("0x07"): {Balance: big.NewInt(1)}, // BN256MUL
		common.HexToAddress("0x08"): {Balance: big.NewInt(1)}, // BN256PAIRING
	}
	sim := simulated.NewBackend(alloc, simulated.WithBlockGasLimit(30_000_000))
	defer sim.Close()

	addr, _, _, err := bind.DeployContract(
		deployer, parsedABI, common.FromHex(strings.TrimSpace(string(binHex))), sim.Client(),
	)
	if err != nil {
		return fmt.Errorf("deploy verifier: %w", err)
	}
	sim.Commit()

	verifyAbi, err := abi.JSON(strings.NewReader(verifyABI))
	if err != nil {
		return fmt.Errorf("parse verify ABI: %w", err)
	}
	callData, err := verifyAbi.Pack(
		"verifySnarkProof",
		snark.ProgramVK,
		snark.RootCVadcopFinal,
		snark.PublicValues,
		snark.ProofBytes,
	)
	if err != nil {
		return fmt.Errorf("pack verifySnarkProof: %w", err)
	}

	if _, err := sim.Client().CallContract(context.Background(),
		ethereum.CallMsg{From: deployer.From, To: &addr, Data: callData}, nil); err != nil {
		return fmt.Errorf("verifySnarkProof reverted: %w", err)
	}
	return nil
}

// compileVerifier writes `ZiskVerifier.abi` and `ZiskVerifier.bin` into
// outDir. Uses local solc when available, otherwise falls back to a
// Docker-pinned solc image.
//
// The verifier sources shipped with the ZisK PLONK proving key declare some
// `bytes32` parameters with a redundant `calldata` / `memory` data location,
// which the current Solidity compiler rejects. To keep the vendored .sol
// files byte-identical to what ZisK distributes (so a fresh `cp` works
// without manual edits), the patch is applied on a copy in a temp dir
// before invoking solc. The original `srcDir` is never modified.
func compileVerifier(srcDir, outDir string) error {
	patchedDir, err := stageAndPatchSources(srcDir)
	if err != nil {
		return err
	}
	defer os.RemoveAll(patchedDir)

	src := filepath.Join(patchedDir, "ZiskVerifier.sol")

	if _, err := exec.LookPath("solc"); err == nil {
		cmd := exec.Command("solc",
			"--abi", "--bin", "--optimize",
			"--base-path", patchedDir,
			"-o", outDir,
			"--overwrite",
			src,
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("solc: %w\n%s", err, out)
		}
		return nil
	}

	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("neither solc nor docker found on PATH; install one to run Solidity verification")
	}
	cmd := exec.Command("docker", "run", "--rm",
		"-v", patchedDir+":/src",
		"-v", outDir+":/out",
		"ethereum/solc:stable",
		"--abi", "--bin", "--optimize",
		"--base-path", "/src",
		"-o", "/out",
		"--overwrite",
		"/src/ZiskVerifier.sol",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker solc: %w\n%s", err, out)
	}
	return nil
}

// stageAndPatchSources copies the vendored verifier .sol files into a fresh
// temp directory and applies the data-location patches needed for modern
// solc to accept them. The vendored files are left untouched. Returns the
// patched directory path; caller is responsible for removing it.
func stageAndPatchSources(srcDir string) (string, error) {
	dst, err := os.MkdirTemp("", "davinci-solidity-src-*")
	if err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	for _, name := range []string{"ZiskVerifier.sol", "PlonkVerifier.sol", "IZiskVerifier.sol"} {
		in, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			os.RemoveAll(dst)
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		patched := patchBytes32DataLocation(string(in))
		if err := os.WriteFile(filepath.Join(dst, name), []byte(patched), 0o644); err != nil {
			os.RemoveAll(dst)
			return "", fmt.Errorf("write patched %s: %w", name, err)
		}
	}
	return dst, nil
}

// patchBytes32DataLocation strips the redundant `calldata` / `memory`
// markers from `bytes32` parameters and return values in the vendored
// verifier sources. Idempotent and safe to re-apply.
func patchBytes32DataLocation(src string) string {
	r := strings.NewReplacer(
		"bytes32 calldata ", "bytes32 ",
		"bytes32 memory ", "bytes32 ",
		"bytes32 memory)", "bytes32)",
	)
	return r.Replace(src)
}
