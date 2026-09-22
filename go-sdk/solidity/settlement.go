package solidity

// Settlement helper: compiles and deploys `DavinciSettlement.sol` next to
// the vendored ZisK PLONK verifier, wires them together on a fresh
// `simulated.NewBackend`, and exposes typed helpers for `createProcess` /
// `submitTransition`. The submit path sends a real EIP-4844 blob
// transaction so the contract's `blobhash(i)` reads and its KZG
// point-evaluation precompile calls exercise the same code the on-chain
// path would.

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	"github.com/ethereum/go-ethereum/crypto/kzg4844"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/holiman/uint256"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// Settlement is a deployed DavinciSettlement contract on top of an
// ethclient/simulated backend. Zero value is not usable — construct via
// [DeploySettlement] or [DeploySettlementWithMockVerifier].
type Settlement struct {
	Backend  *simulated.Backend
	Auth     *bind.TransactOpts
	Key      *ecdsa.PrivateKey
	Verifier common.Address
	Contract common.Address
	ABI      abi.ABI
	ChainID  *big.Int
}

// settlementABI is a minimal ABI fragment covering the calls the Go helper
// makes. It intentionally mirrors DavinciSettlement.sol so the compile
// pipeline stays independent of the returned ABI JSON.
const settlementABI = `[
{"inputs":[
    {"internalType":"contract IZiskVerifier","name":"_zisk","type":"address"},
    {"internalType":"bytes32","name":"_programVK","type":"bytes32"},
    {"internalType":"bytes32","name":"_rootCVadcopFinal","type":"bytes32"}
 ],"stateMutability":"nonpayable","type":"constructor"},
{"inputs":[
    {"internalType":"bytes32","name":"processId","type":"bytes32"},
    {"internalType":"bytes32","name":"genesisRoot","type":"bytes32"},
    {"internalType":"bytes32","name":"censusRoot","type":"bytes32"}
 ],"name":"createProcess","outputs":[],"stateMutability":"nonpayable","type":"function"},
{"inputs":[
    {"internalType":"bytes32","name":"processId","type":"bytes32"},
    {"internalType":"bytes","name":"publicValues","type":"bytes"},
    {"internalType":"bytes","name":"proofBytes","type":"bytes"},
    {"internalType":"bytes[]","name":"commitments","type":"bytes[]"},
    {"internalType":"bytes32[]","name":"ys","type":"bytes32[]"},
    {"internalType":"bytes[]","name":"kzgProofs","type":"bytes[]"}
 ],"name":"submitTransition","outputs":[],"stateMutability":"nonpayable","type":"function"},
{"inputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],
 "name":"processes","outputs":[
    {"internalType":"bytes32","name":"stateRoot","type":"bytes32"},
    {"internalType":"bytes32","name":"censusRoot","type":"bytes32"},
    {"internalType":"uint64","name":"voteCount","type":"uint64"},
    {"internalType":"uint64","name":"overwrittenCount","type":"uint64"},
    {"internalType":"bool","name":"exists","type":"bool"}],
 "stateMutability":"view","type":"function"}
]`

// DeploySettlement compiles the vendored PLONK verifier and
// DavinciSettlement.sol at `solidityDir`, spins up a fresh simulated
// backend, deploys the ZisK verifier followed by the settlement contract
// wired against it, and returns a ready-to-use handle.
func DeploySettlement(solidityDir string, programVK, rootC [32]byte) (*Settlement, error) {
	return deploySettlement(solidityDir, "ZiskVerifier", nil, programVK, rootC)
}

// DeploySettlementWithMockVerifier is the test entry point. It writes each
// entry of `mockSources` into the staging directory alongside the settlement
// sources (`mockSources` maps file name -> Solidity source), skips the real
// PlonkVerifier/ZiskVerifier sources, then deploys the contract named by
// `mockVerifierContract` (e.g. `"MockZiskVerifier"`) as the IZiskVerifier
// backing for DavinciSettlement.
func DeploySettlementWithMockVerifier(
	solidityDir string,
	mockVerifierContract string,
	mockSources map[string]string,
	programVK, rootC [32]byte,
) (*Settlement, error) {
	if mockVerifierContract == "" {
		return nil, errors.New("mock verifier contract name is required")
	}
	if len(mockSources) == 0 {
		return nil, errors.New("mock verifier sources are required")
	}
	return deploySettlement(solidityDir, mockVerifierContract, mockSources, programVK, rootC)
}

// CreateProcess registers a new voting process on the settlement contract.
func (s *Settlement) CreateProcess(pid, genesisRoot, censusRoot [32]byte) error {
	ctx := context.Background()
	data, err := s.ABI.Pack("createProcess", pid, genesisRoot, censusRoot)
	if err != nil {
		return fmt.Errorf("pack createProcess: %w", err)
	}
	nonce, err := s.Backend.Client().PendingNonceAt(ctx, s.Auth.From)
	if err != nil {
		return fmt.Errorf("nonce: %w", err)
	}
	head, err := s.Backend.Client().HeaderByNumber(ctx, nil)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1_000_000_000)) // +1 gwei
	tx := gethtypes.NewTx(&gethtypes.DynamicFeeTx{
		ChainID:   s.ChainID,
		Nonce:     nonce,
		GasTipCap: big.NewInt(1_000_000_000),
		GasFeeCap: gasPrice,
		Gas:       500_000,
		To:        &s.Contract,
		Data:      data,
	})
	signed, err := gethtypes.SignTx(tx, gethtypes.LatestSignerForChainID(s.ChainID), s.Key)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := s.Backend.Client().SendTransaction(ctx, signed); err != nil {
		return fmt.Errorf("send createProcess: %w", err)
	}
	s.Backend.Commit()
	receipt, err := s.Backend.Client().TransactionReceipt(ctx, signed.Hash())
	if err != nil {
		return fmt.Errorf("receipt: %w", err)
	}
	if receipt.Status != 1 {
		return fmt.Errorf("createProcess reverted (tx %s)", signed.Hash().Hex())
	}
	return nil
}

// SubmitTransition sends the batch-settlement blob transaction. The
// simulated backend runs on the Osaka fork, which requires v1 sidecars
// (cell proofs); those are derived from `blobs.Blobs` on the fly. The
// 48-byte KZG opening proofs in `blobs.Proofs` are what the contract feeds
// to the point-evaluation precompile.
//
// The function first replays the call statically via `eth_call` with the
// blob hashes set, so a revert surfaces with the Solidity revert reason
// rather than a bare receipt.Status == 0.
func (s *Settlement) SubmitTransition(
	pid [32]byte,
	snark *davinci.PlonkSnark,
	blobs *davinci.TransitionBlobs,
) (uint64, error) {
	if blobs == nil {
		return 0, errors.New("nil blobs")
	}
	n := len(blobs.Blobs)
	if n == 0 {
		return 0, errors.New("no blobs")
	}
	if len(blobs.Commitments) != n || len(blobs.Ys) != n || len(blobs.Proofs) != n {
		return 0, fmt.Errorf("blob field length mismatch: blobs=%d commits=%d ys=%d proofs=%d",
			n, len(blobs.Commitments), len(blobs.Ys), len(blobs.Proofs))
	}

	ctx := context.Background()

	// Versioned hashes (v1) derived from the commitments, matching what the
	// contract sees via `BLOBHASH`.
	hashes := make([]common.Hash, n)
	hasher := sha256.New()
	for i, c := range blobs.Commitments {
		vh := kzg4844.CalcBlobHashV1(hasher, &c)
		hashes[i] = common.BytesToHash(vh[:])
	}

	// Contract-side arguments — bytes[] and bytes32[] copies of the fixed
	// arrays so we don't hand out references to the caller's memory.
	commitments := make([][]byte, n)
	kzgProofs := make([][]byte, n)
	ys := make([][32]byte, n)
	for i := 0; i < n; i++ {
		commitments[i] = append([]byte(nil), blobs.Commitments[i][:]...)
		kzgProofs[i] = append([]byte(nil), blobs.Proofs[i][:]...)
		ys[i] = blobs.Ys[i]
	}

	data, err := s.ABI.Pack(
		"submitTransition",
		pid,
		snark.PublicValues,
		snark.ProofBytes,
		commitments,
		ys,
		kzgProofs,
	)
	if err != nil {
		return 0, fmt.Errorf("pack submitTransition: %w", err)
	}

	// Static pre-flight: the same call, with BLOBHASH resolving via
	// CallMsg.BlobHashes, gives us the Solidity revert reason.
	if _, err := s.Backend.Client().CallContract(ctx, ethereum.CallMsg{
		From:       s.Auth.From,
		To:         &s.Contract,
		Data:       data,
		BlobHashes: hashes,
	}, nil); err != nil {
		return 0, fmt.Errorf("submitTransition reverted: %s", s.revertReason(err))
	}

	client := s.Backend.Client()
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("head: %w", err)
	}
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1_000_000_000))
	gasPriceU256, _ := uint256.FromBig(gasPrice)
	tipU256, _ := uint256.FromBig(big.NewInt(1_000_000_000))
	chainIDU256, _ := uint256.FromBig(s.ChainID)

	// Osaka wants v1 sidecars: derive the cell proofs from the raw blobs.
	cellProofs := make([]kzg4844.Proof, 0, n*kzg4844.CellProofsPerBlob)
	for i := 0; i < n; i++ {
		cp, err := kzg4844.ComputeCellProofs(&blobs.Blobs[i])
		if err != nil {
			return 0, fmt.Errorf("cell proofs [%d]: %w", i, err)
		}
		cellProofs = append(cellProofs, cp...)
	}
	sidecar := gethtypes.NewBlobTxSidecar(
		gethtypes.BlobSidecarVersion1,
		append([]kzg4844.Blob(nil), blobs.Blobs...),
		append([]kzg4844.Commitment(nil), blobs.Commitments...),
		cellProofs,
	)

	nonce, err := client.PendingNonceAt(ctx, s.Auth.From)
	if err != nil {
		return 0, fmt.Errorf("nonce: %w", err)
	}

	tx := gethtypes.NewTx(&gethtypes.BlobTx{
		ChainID:    chainIDU256,
		Nonce:      nonce,
		GasTipCap:  tipU256,
		GasFeeCap:  gasPriceU256,
		BlobFeeCap: uint256.NewInt(1),
		Gas:        8_000_000,
		To:         s.Contract,
		Data:       data,
		BlobHashes: hashes,
		Sidecar:    sidecar,
	})
	signed, err := gethtypes.SignTx(tx, gethtypes.LatestSignerForChainID(s.ChainID), s.Key)
	if err != nil {
		return 0, fmt.Errorf("sign blob tx: %w", err)
	}
	if err := client.SendTransaction(ctx, signed); err != nil {
		return 0, fmt.Errorf("send blob tx: %w", err)
	}
	s.Backend.Commit()

	receipt, err := client.TransactionReceipt(ctx, signed.Hash())
	if err != nil {
		return 0, fmt.Errorf("receipt: %w", err)
	}
	if receipt.Status != 1 {
		return receipt.GasUsed, fmt.Errorf("blob tx failed: hash=%s status=%d", signed.Hash().Hex(), receipt.Status)
	}
	return receipt.GasUsed, nil
}

// Process reads the current on-chain state for `pid`.
func (s *Settlement) Process(pid [32]byte) (
	stateRoot, censusRoot [32]byte, voteCount, overwrittenCount uint64, err error,
) {
	ctx := context.Background()
	data, err := s.ABI.Pack("processes", pid)
	if err != nil {
		return stateRoot, censusRoot, 0, 0, fmt.Errorf("pack processes: %w", err)
	}
	raw, err := s.Backend.Client().CallContract(ctx, ethereum.CallMsg{
		From: s.Auth.From,
		To:   &s.Contract,
		Data: data,
	}, nil)
	if err != nil {
		return stateRoot, censusRoot, 0, 0, fmt.Errorf("call processes: %w", err)
	}
	out, err := s.ABI.Unpack("processes", raw)
	if err != nil {
		return stateRoot, censusRoot, 0, 0, fmt.Errorf("unpack processes: %w", err)
	}
	if len(out) != 5 {
		return stateRoot, censusRoot, 0, 0, fmt.Errorf("processes: expected 5 fields, got %d", len(out))
	}
	stateRoot = out[0].([32]byte)
	censusRoot = out[1].([32]byte)
	voteCount = out[2].(uint64)
	overwrittenCount = out[3].(uint64)
	return stateRoot, censusRoot, voteCount, overwrittenCount, nil
}

// deploySettlement stages sources, compiles the two contracts, and deploys
// them on a fresh simulated backend.
func deploySettlement(
	solidityDir string,
	verifierContract string,
	extraSources map[string]string,
	programVK, rootC [32]byte,
) (*Settlement, error) {
	buildDir, err := os.MkdirTemp("", "davinci-settlement-build-*")
	if err != nil {
		return nil, fmt.Errorf("create build dir: %w", err)
	}
	defer os.RemoveAll(buildDir)

	patchedDir, err := stageSettlementSources(solidityDir, verifierContract, extraSources)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(patchedDir)

	// Compile whichever verifier source contains the requested contract, plus
	// the settlement source (which imports only IZiskVerifier.sol).
	verifierSource := verifierContract + ".sol"
	if err := compileSettlementSolc(patchedDir, buildDir, verifierSource, "DavinciSettlement.sol"); err != nil {
		return nil, err
	}

	verABIBytes, err := os.ReadFile(filepath.Join(buildDir, verifierContract+".abi"))
	if err != nil {
		return nil, fmt.Errorf("read %s.abi: %w", verifierContract, err)
	}
	verBinHex, err := os.ReadFile(filepath.Join(buildDir, verifierContract+".bin"))
	if err != nil {
		return nil, fmt.Errorf("read %s.bin: %w", verifierContract, err)
	}
	setBinHex, err := os.ReadFile(filepath.Join(buildDir, "DavinciSettlement.bin"))
	if err != nil {
		return nil, fmt.Errorf("read DavinciSettlement.bin: %w", err)
	}

	verABI, err := abi.JSON(strings.NewReader(string(verABIBytes)))
	if err != nil {
		return nil, fmt.Errorf("parse verifier ABI: %w", err)
	}
	packABI, err := abi.JSON(strings.NewReader(settlementABI))
	if err != nil {
		return nil, fmt.Errorf("parse packing ABI: %w", err)
	}

	priv, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	chainID := big.NewInt(1337)
	auth, err := bind.NewKeyedTransactorWithChainID(priv, chainID)
	if err != nil {
		return nil, fmt.Errorf("new transactor: %w", err)
	}

	alloc := gethtypes.GenesisAlloc{
		auth.From:                   {Balance: new(big.Int).Mul(big.NewInt(1e18), big.NewInt(1000))},
		common.HexToAddress("0x05"): {Balance: big.NewInt(1)}, // MODEXP
		common.HexToAddress("0x06"): {Balance: big.NewInt(1)}, // BN256ADD
		common.HexToAddress("0x07"): {Balance: big.NewInt(1)}, // BN256MUL
		common.HexToAddress("0x08"): {Balance: big.NewInt(1)}, // BN256PAIRING
		common.HexToAddress("0x0A"): {Balance: big.NewInt(1)}, // KZG point-evaluation
	}
	sim := simulated.NewBackend(alloc, simulated.WithBlockGasLimit(30_000_000))

	// Deploy verifier.
	verifierAddr, _, _, err := bind.DeployContract(
		auth, verABI, common.FromHex(strings.TrimSpace(string(verBinHex))), sim.Client(),
	)
	if err != nil {
		sim.Close()
		return nil, fmt.Errorf("deploy verifier: %w", err)
	}
	sim.Commit()

	// Deploy settlement.
	contractAddr, _, _, err := bind.DeployContract(
		auth, packABI, common.FromHex(strings.TrimSpace(string(setBinHex))), sim.Client(),
		verifierAddr, programVK, rootC,
	)
	if err != nil {
		sim.Close()
		return nil, fmt.Errorf("deploy settlement: %w", err)
	}
	sim.Commit()

	return &Settlement{
		Backend:  sim,
		Auth:     auth,
		Key:      priv,
		Verifier: verifierAddr,
		Contract: contractAddr,
		ABI:      packABI,
		ChainID:  chainID,
	}, nil
}

// stageSettlementSources writes IZiskVerifier.sol and DavinciSettlement.sol
// (patched) into a fresh temp dir, plus either the vendored ZisK verifier
// pair or the supplied mock sources. Callers own the returned directory.
func stageSettlementSources(
	srcDir, verifierContract string,
	extraSources map[string]string,
) (string, error) {
	dst, err := os.MkdirTemp("", "davinci-settlement-src-*")
	if err != nil {
		return "", fmt.Errorf("create staging dir: %w", err)
	}
	base := []string{"IZiskVerifier.sol", "DavinciSettlement.sol"}
	if verifierContract == "ZiskVerifier" {
		base = append(base, "PlonkVerifier.sol", "ZiskVerifier.sol")
	}
	for _, name := range base {
		in, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			os.RemoveAll(dst)
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		patched := patchBytes32DataLocation(string(in))
		if err := os.WriteFile(filepath.Join(dst, name), []byte(patched), 0o644); err != nil {
			os.RemoveAll(dst)
			return "", fmt.Errorf("write %s: %w", name, err)
		}
	}
	for name, content := range extraSources {
		if err := os.WriteFile(filepath.Join(dst, name), []byte(content), 0o644); err != nil {
			os.RemoveAll(dst)
			return "", fmt.Errorf("write extra %s: %w", name, err)
		}
	}
	return dst, nil
}

// compileSettlementSolc invokes solc (locally or via docker) on the given
// source files, writing .abi/.bin artifacts into outDir.
func compileSettlementSolc(patchedDir, outDir string, sources ...string) error {
	if len(sources) == 0 {
		return errors.New("no sources to compile")
	}
	if _, err := exec.LookPath("solc"); err == nil {
		args := []string{
			"--abi", "--bin", "--optimize", "--via-ir",
			"--base-path", patchedDir,
			"-o", outDir,
			"--overwrite",
		}
		for _, s := range sources {
			args = append(args, filepath.Join(patchedDir, s))
		}
		cmd := exec.Command("solc", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("solc: %w\n%s", err, out)
		}
		return nil
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return errors.New("neither solc nor docker found on PATH; install one to run Solidity tests")
	}
	args := []string{"run", "--rm",
		"-v", patchedDir + ":/src",
		"-v", outDir + ":/out",
		"ethereum/solc:0.8.28",
		"--abi", "--bin", "--optimize", "--via-ir",
		"--base-path", "/src",
		"-o", "/out",
		"--overwrite",
	}
	for _, s := range sources {
		args = append(args, "/src/"+s)
	}
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker solc: %w\n%s", err, out)
	}
	return nil
}

// revertReason names the custom error behind a reverted call when the
// backend attached the revert data, else returns the error text.
func (s *Settlement) revertReason(err error) string {
	var dataErr interface{ ErrorData() interface{} }
	if !errors.As(err, &dataErr) {
		return err.Error()
	}
	hexData, ok := dataErr.ErrorData().(string)
	if !ok {
		return err.Error()
	}
	data, decErr := hex.DecodeString(strings.TrimPrefix(hexData, "0x"))
	if decErr != nil || len(data) < 4 {
		return fmt.Sprintf("%s (data %s)", err.Error(), hexData)
	}
	var sel [4]byte
	copy(sel[:], data[:4])
	if abiErr, lookupErr := s.ABI.ErrorByID(sel); lookupErr == nil {
		return fmt.Sprintf("%s (%s)", abiErr.Name, err.Error())
	}
	return fmt.Sprintf("%s (data %s)", err.Error(), hexData)
}
