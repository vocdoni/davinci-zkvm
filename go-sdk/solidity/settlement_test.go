package solidity

// Tests for the DavinciSettlement contract. We do not have a real prover
// available here, so the tests deploy the settlement against a mock
// IZiskVerifier whose `verifySnarkProof` is a no-op. All other logic —
// publicValues layout, root/counter checks, blob digest, KZG opening
// verification via the point-evaluation precompile — is exercised end to
// end on go-ethereum's simulated backend, including a real EIP-4844 blob
// transaction so the contract's `blobhash(i)` returns real values.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/crypto/kzg4844"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

// blsModulus matches BLS_MODULUS in DavinciSettlement.sol / EIP-4844.
var blsModulus, _ = new(big.Int).SetString(
	"52435875175126190479447740508185965837690552500527637822603658699938581184513", 10,
)

const mockVerifierSource = `// SPDX-License-Identifier: AGPL-3.0
pragma solidity ^0.8.24;

import {IZiskVerifier} from "./IZiskVerifier.sol";

/// Test-only IZiskVerifier that accepts every proof. Used to isolate the
/// settlement contract's own checks from PLONK verification.
contract MockZiskVerifier is IZiskVerifier {
    function verifySnarkProof(
        bytes32,
        bytes32,
        bytes calldata,
        bytes calldata
    ) external view {}
}
`

// solidityDir resolves the repo's `solidity/` directory from this test's
// on-disk location, so `go test` works from any wd.
func solidityDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "solidity")
}

func mustDeploy(t *testing.T, programVK, rootC [32]byte) *Settlement {
	t.Helper()
	s, err := DeploySettlementWithMockVerifier(
		solidityDir(t),
		"MockZiskVerifier",
		map[string]string{"MockZiskVerifier.sol": mockVerifierSource},
		programVK, rootC,
	)
	if err != nil {
		t.Fatalf("DeploySettlementWithMockVerifier: %v", err)
	}
	t.Cleanup(func() { s.Backend.Close() })
	return s
}

// publics builds the 512-byte publicValues buffer from a 64-register view.
func publics(regs [64]uint32) []byte {
	buf := make([]byte, 512)
	for i, w := range regs {
		binary.LittleEndian.PutUint64(buf[i*8:], uint64(w))
	}
	return buf
}

// setReg32 writes `val` into 8 consecutive registers such that the
// contract's `reg32(k)` reads it back byte-identically.
func setReg32(regs *[64]uint32, k int, val [32]byte) {
	for j := 0; j < 8; j++ {
		regs[k+j] = binary.LittleEndian.Uint32(val[4*j : 4*(j+1)])
	}
}

// reverseBytes32 returns the byte-reversed copy (LE ↔ BE integer encoding).
func reverseBytes32(b [32]byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out
}

// makeBlob returns a deterministic 4844 blob whose 4096 field elements are
// all < BLS_MODULUS (top byte held to 0, bottom byte cycles from `seed`).
func makeBlob(seed byte) kzg4844.Blob {
	var b kzg4844.Blob
	for i := 0; i < 4096; i++ {
		b[i*32+31] = seed + byte(i%251)
	}
	return b
}

// computeZ returns z = sha256(pid || rootBeforeBE || commitment) mod BLS_MODULUS.
func computeZ(pid, rootBeforeBE [32]byte, com kzg4844.Commitment) kzg4844.Point {
	h := sha256.New()
	h.Write(pid[:])
	h.Write(rootBeforeBE[:])
	h.Write(com[:])
	sum := h.Sum(nil)
	z := new(big.Int).SetBytes(sum)
	z.Mod(z, blsModulus)
	var pt kzg4844.Point
	z.FillBytes(pt[:])
	return pt
}

// buildBlobs returns a TransitionBlobs with commitments and opening proofs
// bound to (pid, rootBefore). rootBefore is the LE-form root (as it lives
// in the publics); we hash the reversed (BE) form, matching the guest.
func buildBlobs(pid, rootBefore [32]byte, seeds []byte) (*davinci.TransitionBlobs, error) {
	rootBE := reverseBytes32(rootBefore)
	out := &davinci.TransitionBlobs{
		Blobs:       make([]kzg4844.Blob, len(seeds)),
		Commitments: make([]kzg4844.Commitment, len(seeds)),
		Ys:          make([][32]byte, len(seeds)),
		Proofs:      make([]kzg4844.Proof, len(seeds)),
	}
	digest := sha256.New()
	for i, s := range seeds {
		out.Blobs[i] = makeBlob(s)
		com, err := kzg4844.BlobToCommitment(&out.Blobs[i])
		if err != nil {
			return nil, fmt.Errorf("commit blob %d: %w", i, err)
		}
		out.Commitments[i] = com
		z := computeZ(pid, rootBE, com)
		proof, claim, err := kzg4844.ComputeProof(&out.Blobs[i], z)
		if err != nil {
			return nil, fmt.Errorf("open blob %d: %w", i, err)
		}
		out.Proofs[i] = proof
		var y [32]byte
		copy(y[:], claim[:])
		out.Ys[i] = y
		digest.Write(com[:])
		digest.Write(y[:])
	}
	copy(out.Digest[:], digest.Sum(nil))
	return out, nil
}

// makePublicValues assembles a well-formed 512-byte publicValues buffer.
// Fields left zero if not provided.
type publicsSpec struct {
	ok             uint32
	failMask       uint32
	rootBefore     [32]byte
	rootAfter      [32]byte
	voters         uint32
	overwrites     uint32
	censusRoot     [32]byte
	blobsDigest    [32]byte
	nBlobs         uint32
	occupiedBefore uint32
}

func makePublicValues(spec publicsSpec) []byte {
	var regs [64]uint32
	regs[0] = spec.ok
	regs[1] = spec.failMask
	setReg32(&regs, 2, spec.rootBefore)
	setReg32(&regs, 10, spec.rootAfter)
	regs[18] = spec.voters
	regs[19] = spec.overwrites
	setReg32(&regs, 20, spec.censusRoot)
	setReg32(&regs, 28, spec.blobsDigest)
	regs[36] = spec.nBlobs
	regs[42] = spec.occupiedBefore
	return publics(regs)
}

// snarkFrom bundles the four PlonkSnark fields the settlement expects. The
// verifier is mocked, so proofBytes may be any byte string.
func snarkFrom(programVK, rootC [32]byte, pv []byte) *davinci.PlonkSnark {
	return &davinci.PlonkSnark{
		ProgramVK:        programVK,
		RootCVadcopFinal: rootC,
		PublicValues:     pv,
		ProofBytes:       make([]byte, 24*32),
	}
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func TestSettlement(t *testing.T) {
	programVK := [32]byte{0x11}
	rootC := [32]byte{0x22}
	s := mustDeploy(t, programVK, rootC)

	// One process per subtest for isolation.
	newProcess := func(t *testing.T, tag byte) (pid, root, census [32]byte) {
		t.Helper()
		pid[0] = tag
		pid[31] = tag ^ 0xFF
		root[0] = 0xA0 + tag
		root[31] = 0xB0 + tag
		census[0] = 0xC0 + tag
		census[31] = 0xD0 + tag
		if err := s.CreateProcess(pid, root, census); err != nil {
			t.Fatalf("CreateProcess: %v", err)
		}
		return
	}

	t.Run("OneBlobHappyPath", func(t *testing.T) {
		pid, rootBefore, census := newProcess(t, 0x01)
		var rootAfter [32]byte
		rootAfter[0] = 0xAA

		blobs, err := buildBlobs(pid, rootBefore, []byte{0x10})
		if err != nil {
			t.Fatalf("buildBlobs: %v", err)
		}

		pv := makePublicValues(publicsSpec{
			ok:             1,
			rootBefore:     rootBefore,
			rootAfter:      rootAfter,
			voters:         7,
			overwrites:     2,
			censusRoot:     census,
			blobsDigest:    blobs.Digest,
			nBlobs:         1,
			occupiedBefore: 0,
		})
		gas, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, pv), blobs)
		if err != nil {
			t.Fatalf("SubmitTransition: %v", err)
		}
		t.Logf("1-blob settlement gas: %d", gas)

		sr, cr, vc, oc, err := s.Process(pid)
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		if sr != rootAfter {
			t.Errorf("stateRoot: got %x want %x", sr, rootAfter)
		}
		if cr != census {
			t.Errorf("censusRoot changed: got %x want %x", cr, census)
		}
		if vc != 7 {
			t.Errorf("voteCount: got %d want 7", vc)
		}
		if oc != 2 {
			t.Errorf("overwrittenCount: got %d want 2", oc)
		}
	})

	t.Run("TwoBlobsHappyPath", func(t *testing.T) {
		pid, rootBefore, census := newProcess(t, 0x02)
		var rootAfter [32]byte
		rootAfter[7] = 0x55

		blobs, err := buildBlobs(pid, rootBefore, []byte{0x20, 0x21})
		if err != nil {
			t.Fatalf("buildBlobs: %v", err)
		}

		pv := makePublicValues(publicsSpec{
			ok:             1,
			rootBefore:     rootBefore,
			rootAfter:      rootAfter,
			voters:         64,
			overwrites:     0,
			censusRoot:     census,
			blobsDigest:    blobs.Digest,
			nBlobs:         2,
			occupiedBefore: 0,
		})
		gas, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, pv), blobs)
		if err != nil {
			t.Fatalf("SubmitTransition (2 blobs): %v", err)
		}
		t.Logf("2-blob settlement gas: %d", gas)

		sr, _, vc, oc, err := s.Process(pid)
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		if sr != rootAfter {
			t.Errorf("stateRoot: got %x want %x", sr, rootAfter)
		}
		if vc != 64 || oc != 0 {
			t.Errorf("counters: vc=%d oc=%d want 64/0", vc, oc)
		}
	})

	t.Run("Rejections", func(t *testing.T) {
		pid, rootBefore, census := newProcess(t, 0x03)
		var rootAfter [32]byte
		rootAfter[0] = 0x77

		blobs, err := buildBlobs(pid, rootBefore, []byte{0x30})
		if err != nil {
			t.Fatalf("buildBlobs: %v", err)
		}

		goodSpec := publicsSpec{
			ok:             1,
			rootBefore:     rootBefore,
			rootAfter:      rootAfter,
			voters:         3,
			overwrites:     1,
			censusRoot:     census,
			blobsDigest:    blobs.Digest,
			nBlobs:         1,
			occupiedBefore: 0,
		}

		// wrong rootBefore
		spec := goodSpec
		spec.rootBefore = [32]byte{0xDE, 0xAD}
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), blobs); err == nil {
			t.Error("wrong rootBefore: expected revert")
		} else if !strings.Contains(err.Error(), "reverted") {
			t.Errorf("wrong rootBefore: unexpected error %v", err)
		}

		// wrong census
		spec = goodSpec
		spec.censusRoot = [32]byte{0xCA, 0xFE}
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), blobs); err == nil {
			t.Error("wrong census: expected revert")
		}

		// occupiedBefore mismatch (state has vc-oc=0 but we claim 5)
		spec = goodSpec
		spec.occupiedBefore = 5
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), blobs); err == nil {
			t.Error("bad occupiedBefore: expected revert")
		}

		// digest mismatch
		spec = goodSpec
		spec.blobsDigest = [32]byte{0xAB, 0xCD}
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), blobs); err == nil {
			t.Error("bad digest: expected revert")
		}

		// tampered y (breaks KZG opening; digest also breaks, but the digest
		// check runs first — recompute the digest so KZG failure is the
		// surface reason).
		tampered := *blobs
		tampered.Ys = append([][32]byte(nil), blobs.Ys...)
		tampered.Ys[0][0] ^= 0x01
		newDigest := sha256.New()
		newDigest.Write(tampered.Commitments[0][:])
		newDigest.Write(tampered.Ys[0][:])
		var tamperedDigest [32]byte
		copy(tamperedDigest[:], newDigest.Sum(nil))
		spec = goodSpec
		spec.blobsDigest = tamperedDigest
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), &tampered); err == nil {
			t.Error("tampered y: expected revert")
		}

		// wrong commitment count (claim 2 blobs, only provide 1)
		spec = goodSpec
		spec.nBlobs = 2
		if _, err := s.SubmitTransition(pid, snarkFrom(programVK, rootC, makePublicValues(spec)), blobs); err == nil {
			t.Error("bad nBlobs vs commitments.length: expected revert")
		}

		// missing blob: BLOBHASH returns zero when the transaction carries no
		// blob hashes. submitWithoutBlobHashes runs the pre-flight call with
		// an empty BlobHashes list to hit MissingBlob.
		emptyBlobs := &davinci.TransitionBlobs{
			Blobs:       []kzg4844.Blob{blobs.Blobs[0]},
			Commitments: []kzg4844.Commitment{blobs.Commitments[0]},
			Ys:          [][32]byte{blobs.Ys[0]},
			Proofs:      []kzg4844.Proof{blobs.Proofs[0]},
			Digest:      blobs.Digest,
		}
		spec = goodSpec
		if err := submitWithoutBlobHashes(s, pid, snarkFrom(programVK, rootC, makePublicValues(spec)), emptyBlobs); err == nil {
			t.Error("missing blob: expected revert")
		}

		// Final state should still be genesis (no accepted transitions).
		sr, _, vc, oc, err := s.Process(pid)
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
		if sr != rootBefore || vc != 0 || oc != 0 {
			t.Errorf("state was mutated by a rejected tx: sr=%x vc=%d oc=%d", sr, vc, oc)
		}
	})
}

// submitWithoutBlobHashes runs the same pre-flight the settlement uses but
// with an empty BlobHashes list, so `blobhash(i)` returns zero and the
// contract reverts with MissingBlob. Test-only shortcut that skips the tx
// send (which would refuse a blob tx without matching sidecar hashes).
func submitWithoutBlobHashes(s *Settlement, pid [32]byte, snark *davinci.PlonkSnark, blobs *davinci.TransitionBlobs) error {
	n := len(blobs.Blobs)
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
		return err
	}
	// No BlobHashes: blobhash(i) yields zero and the contract must revert.
	_, err = s.Backend.Client().CallContract(context.Background(), ethereum.CallMsg{
		From: s.Auth.From,
		To:   &s.Contract,
		Data: data,
	}, nil)
	if err == nil {
		return errors.New("expected revert with empty BlobHashes but call succeeded")
	}
	return err
}
