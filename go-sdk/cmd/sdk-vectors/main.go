// Command sdk-vectors writes the golden vectors the Rust SDK
// (rust-sdk, crate davinci-zkvm-sdk) replays in its compatibility tests.
// Every value comes from the Go reference code (go-sdk, go-iden3-crypto,
// lean-imt-go, go-ethereum), so a byte mismatch in Rust is a Rust bug.
//
//	cd go-sdk && go run ./cmd/sdk-vectors -out ../rust-sdk/testdata
//
// It also writes the iden3 Poseidon constants for widths 1..16 to
// ../rust-sdk/assets/poseidon_constants.bin (see -constants).
//
// The Groth16 fixtures (real_proof.json, real_proof_v1.json) are not
// reproducible: rapidsnark randomizes every proof. A default run keeps them
// and reads real_proof.json back for wire_prove.json; pass -proofs to
// regenerate them, which also changes wire_prove.json. Every other file is
// byte-identical across runs.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	mrand "math/rand"
	"os"
	"path/filepath"
)

var (
	outDir       = flag.String("out", "../rust-sdk/testdata", "directory for the JSON vectors")
	constantsOut = flag.String("constants", "../rust-sdk/assets/poseidon_constants.bin", "poseidon constants output (empty = skip)")
	circomDir    = flag.String("circom", "../davinci-circom/artifacts", "davinci-circom artifacts matching rust-sdk/assets/ballot_proof_vkey.json")
	vkAsset      = flag.String("vk", "../rust-sdk/assets/ballot_proof_vkey.json", "ballot VK embedded in the Rust SDK")
	cpVectors    = flag.String("cp", "../circuit-primitives/testdata/cp_vectors.json", "guest Chaum-Pedersen vectors to copy")
	proofs       = flag.Bool("proofs", false, "regenerate the rapidsnark proof fixtures (non-deterministic)")
)

// Fixed seed: reruns reproduce every file except the Groth16 proofs.
var rng = mrand.New(mrand.NewSource(20260926))

func main() {
	flag.Parse()
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}
	if *constantsOut != "" {
		must(writePoseidonConstants(*constantsOut))
	}
	must(copyFile(*cpVectors, filepath.Join(*outDir, "cp_vectors.json")))
	write("poseidon.json", poseidonVectors())
	write("babyjubjub.json", bjjVectors())
	write("elgamal.json", elgamalVectors())
	write("chaum_pedersen.json", cpVectorsGen())
	write("reenc.json", reencVectors())
	write("ballot_mode.json", ballotModeVectors())
	write("hashes.json", hashVectors())
	write("genesis.json", genesisVectors())
	write("leanimt.json", leanIMTVectors())
	write("census.json", censusVectors())
	write("voteid_sig.json", voteIDSigVectors())
	write("ballots.json", ballotVectors())
	if *proofs {
		// Own stream, so the files after this do not depend on -proofs.
		saved := rng
		rng = mrand.New(mrand.NewSource(20260927))
		write("real_proof.json", realProofVector())
		write("real_proof_v1.json", realProofV1Vector())
		rng = saved
	}
	blobMain()
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func write(name string, v any) {
	b, err := json.MarshalIndent(v, "", " ")
	must(err)
	must(os.WriteFile(filepath.Join(*outDir, name), append(b, '\n'), 0o644))
	fmt.Println("wrote", name)
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// bn254 scalar field (BabyJubJub base field).
var fieldP, _ = new(big.Int).SetString(
	"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

func dec(v *big.Int) string { return v.String() }

func decs(vs []*big.Int) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = v.String()
	}
	return out
}

func be32(v *big.Int) []byte {
	var b [32]byte
	v.FillBytes(b[:])
	return b[:]
}

func hex32(v *big.Int) string { return hex.EncodeToString(be32(v)) }

func randField() *big.Int { return new(big.Int).Rand(rng, fieldP) }

func randBelow(n *big.Int) *big.Int { return new(big.Int).Rand(rng, n) }

func randBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func sha256Hex(b []byte) string {
	d := sha256.Sum256(b)
	return hex.EncodeToString(d[:])
}

func u64le(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}
