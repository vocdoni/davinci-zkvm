package davinci

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// PlonkSnark is the on-chain-ready payload produced by the davinci-zkvm
// service after a successful PLONK proving run.
//
// It maps one-to-one onto the inputs of the Solidity verifier shipped with
// the ZisK proving key, `ZiskVerifier.verifySnarkProof`:
//
//	function verifySnarkProof(
//	    bytes32 programVK,
//	    bytes32 rootCVadcopFinal,
//	    bytes   publicValues,
//	    bytes   proofBytes
//	) external view;
//
// The verifier hashes `programVK || publicValues || rootCVadcopFinal` with
// SHA-256, reduces the digest modulo the BN254 scalar field, and feeds the
// resulting scalar to the bare PLONK verifier together with
// `abi.decode(proofBytes, (uint256[24]))`.
//
// Callers must not need to know anything about STARKs, VADCOP, or
// recursivef wrapping; everything underneath those layers has been folded
// into these four byte strings.
type PlonkSnark struct {
	// ProgramVK is the program (RISC-V ROM) verification key. Constant for
	// a given davinci circuit ELF version; 32 bytes.
	ProgramVK [32]byte
	// RootCVadcopFinal is the VADCOP-final commitment root, constant for a
	// given ZisK setup version. The Solidity verifier also exposes this as
	// a hardcoded `getRootCVadcopFinal()`; this field lets callers verify
	// off-chain without reading the contract; 32 bytes.
	RootCVadcopFinal [32]byte
	// PublicValues is the program's `commit_slice` output (256 bytes for
	// the current `ZISK_PUBLICS=64` setup).
	PublicValues []byte
	// ProofBytes is the PLONK proof already ABI-encoded as `uint256[24]`
	// (768 bytes). Pass it straight as the `bytes proofBytes` argument to
	// `verifySnarkProof`.
	ProofBytes []byte
}

// plonkSnarkJSON is the wire-format the service returns at /jobs/:id/snark:
// all four fields are `0x`-prefixed hex strings.
type plonkSnarkJSON struct {
	ProgramVK        string `json:"program_vk"`
	RootCVadcopFinal string `json:"root_c_vadcop_final"`
	PublicValues     string `json:"public_values"`
	ProofBytes       string `json:"proof_bytes"`
}

func (p *plonkSnarkJSON) toPlonkSnark() (*PlonkSnark, error) {
	pvk, err := decodeHex32(p.ProgramVK, "program_vk")
	if err != nil {
		return nil, err
	}
	rcvf, err := decodeHex32(p.RootCVadcopFinal, "root_c_vadcop_final")
	if err != nil {
		return nil, err
	}
	pv, err := decodeHexBytes(p.PublicValues, "public_values")
	if err != nil {
		return nil, err
	}
	pb, err := decodeHexBytes(p.ProofBytes, "proof_bytes")
	if err != nil {
		return nil, err
	}
	if len(pb) != 24*32 {
		return nil, fmt.Errorf(
			"proof_bytes: expected %d bytes (uint256[24]), got %d",
			24*32, len(pb),
		)
	}
	return &PlonkSnark{
		ProgramVK:        pvk,
		RootCVadcopFinal: rcvf,
		PublicValues:     pv,
		ProofBytes:       pb,
	}, nil
}

func decodeHex32(s, name string) ([32]byte, error) {
	b, err := decodeHexBytes(s, name)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%s: expected 32 bytes, got %d", name, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

func decodeHexBytes(s, name string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return b, nil
}
