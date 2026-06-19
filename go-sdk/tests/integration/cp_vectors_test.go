// cp_vectors_test.go extracts Chaum-Pedersen decryption-proof test vectors
// from davinci-node so the Rust guest implementation can be checked
// bit-exactly. Gated by CP_VECTORS=1; writes JSON to
// ../../../circuit-primitives/testdata/cp_vectors.json (override with
// CP_VECTORS_OUT).
//
// All points are emitted in both coordinate forms:
//   - rte: Reduced Twisted Edwards, the gnark in-memory form returned by
//     Point() and the form fed to the Poseidon Fiat-Shamir hash.
//   - te:  standard Twisted Edwards (iden3, a=168700), the form the guest
//     computes in and the form stored in the state tree.
package integration

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/ecc"
	bjjgnark "github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/ecc/format"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/crypto/elgamal"
)

type cpPoint struct {
	RteX string `json:"rte_x"`
	RteY string `json:"rte_y"`
	TeX  string `json:"te_x"`
	TeY  string `json:"te_y"`
}

type cpVector struct {
	Msg            string   `json:"msg"`
	K              string   `json:"k"`
	C1             cpPoint  `json:"c1"`
	C2             cpPoint  `json:"c2"`
	D              cpPoint  `json:"d_point"`
	A1             cpPoint  `json:"a1"`
	A2             cpPoint  `json:"a2"`
	Z              string   `json:"z"`
	E              string   `json:"e"`
	PoseidonInputs []string `json:"poseidon_inputs"`
}

type cpVectors struct {
	Order         string     `json:"order"`
	ScalingFactor string     `json:"scaling_factor"`
	Generator     cpPoint    `json:"generator"`
	PubKey        cpPoint    `json:"pub_key"`
	PrivKey       string     `json:"priv_key"`
	Vectors       []cpVector `json:"vectors"`
	Poseidon12In  []string   `json:"poseidon12_in"`
	Poseidon12Out string     `json:"poseidon12_out"`
}

func toCpPoint(p ecc.Point) cpPoint {
	x, y := p.Point()
	tx, ty := format.FromRTEtoTE(x, y)
	return cpPoint{
		RteX: x.String(), RteY: y.String(),
		TeX: tx.String(), TeY: ty.String(),
	}
}

func TestCPVectors(t *testing.T) {
	if os.Getenv("CP_VECTORS") == "" {
		t.Skip("set CP_VECTORS=1 to run")
	}

	pubKey, privKey, err := elgamal.GenerateKey(bjjgnark.New())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	order := pubKey.Order()

	gen := bjjgnark.New()
	gen.SetGenerator()

	out := cpVectors{
		Order:         order.String(),
		ScalingFactor: "6360561867910373094066688120553762416144456282423235903351243436111059670888",
		Generator:     toCpPoint(gen),
		PubKey:        toCpPoint(pubKey),
		PrivKey:       privKey.String(),
	}

	msgs := []int64{0, 1, 42, 123456789}
	for i, m := range msgs {
		msg := big.NewInt(m)
		k := big.NewInt(int64(1000 + i*7)) // fixed encryption randomness
		c1, c2 := elgamal.EncryptWithK(pubKey, msg, k)

		proof, err := elgamal.BuildDecryptionProof(privKey, pubKey, c1, c2, msg)
		if err != nil {
			t.Fatalf("BuildDecryptionProof: %v", err)
		}
		if err := elgamal.VerifyDecryptionProof(pubKey, c1, c2, msg, proof); err != nil {
			t.Fatalf("VerifyDecryptionProof: %v", err)
		}

		// Recompute D = C2 - (msg mod order)*G and the challenge e,
		// exactly as VerifyDecryptionProof does.
		mm := new(big.Int).Mod(msg, order)
		M := pubKey.New()
		M.ScalarBaseMult(mm)
		D := pubKey.New()
		D.Set(c2)
		negM := pubKey.New()
		negM.Neg(M)
		D.Add(D, negM)

		e, err := elgamal.HashPointsToScalar(pubKey, pubKey, c1, D, proof.A1, proof.A2)
		if err != nil {
			t.Fatalf("HashPointsToScalar: %v", err)
		}

		var inputs []string
		for _, p := range []ecc.Point{pubKey, pubKey, c1, D, proof.A1, proof.A2} {
			x, y := p.Point()
			inputs = append(inputs, x.String(), y.String())
		}

		out.Vectors = append(out.Vectors, cpVector{
			Msg:            msg.String(),
			K:              k.String(),
			C1:             toCpPoint(c1),
			C2:             toCpPoint(c2),
			D:              toCpPoint(D),
			A1:             toCpPoint(proof.A1),
			A2:             toCpPoint(proof.A2),
			Z:              proof.Z.String(),
			E:              e.String(),
			PoseidonInputs: inputs,
		})
	}

	// Standalone Poseidon arity-12 vector (single iden3 hash, t=13).
	var pin []*big.Int
	for i := int64(1); i <= 12; i++ {
		pin = append(pin, big.NewInt(i))
		out.Poseidon12In = append(out.Poseidon12In, big.NewInt(i).String())
	}
	ph, err := poseidon.Hash(pin)
	if err != nil {
		t.Fatalf("poseidon.Hash: %v", err)
	}
	out.Poseidon12Out = ph.String()

	dst := os.Getenv("CP_VECTORS_OUT")
	if dst == "" {
		dst = filepath.Join("..", "..", "..", "circuit-primitives", "testdata", "cp_vectors.json")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	buf, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d CP vectors to %s", len(out.Vectors), dst)
}
