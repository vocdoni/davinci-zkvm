package davinci

import (
	"math/big"
	"testing"

	leanimt "github.com/vocdoni/lean-imt-go"
)

func hexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		t.Fatalf("bad hex %q", s)
	}
	return v
}

func TestKeccakHasherMatchesSolidity(t *testing.T) {
	// cast keccak $(cast abi-encode "f(uint256,uint256)" 1 2), and of 64 zero bytes.
	for _, c := range []struct {
		a, b int64
		want string
	}{
		{1, 2, "0xe90b7bceb6e7df5418fb78d8ee546e97c83a08bbccc01a0644d599ccd2a7c2e0"},
		{0, 0, "0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5"},
	} {
		if got := KeccakHasher(big.NewInt(c.a), big.NewInt(c.b)); got.Cmp(hexInt(t, c.want)) != 0 {
			t.Errorf("KeccakHasher(%d, %d) = %#x, want %s", c.a, c.b, got, c.want)
		}
	}
	// Inputs are padded to 32 bytes: (1, 2) and (0x0102, 0) must differ.
	if KeccakHasher(big.NewInt(1), big.NewInt(2)).Cmp(KeccakHasher(big.NewInt(0x0102), big.NewInt(0))) == 0 {
		t.Error("unpadded concatenation")
	}
	for _, bad := range []*big.Int{big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 256)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("KeccakHasher(%v): want panic", bad)
				}
			}()
			KeccakHasher(bad, big.NewInt(0))
		}()
	}
}

func TestKeccakLeanIMTShape(t *testing.T) {
	eq := func(a, b *big.Int) bool { return a.Cmp(b) == 0 }
	tree, err := leanimt.New(KeccakHasher, eq, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tree.Root(); ok {
		t.Fatal("empty tree has a root")
	}
	l := []*big.Int{big.NewInt(11), big.NewInt(22), big.NewInt(33)}
	tree.Insert(l[0])
	if r, _ := tree.Root(); r.Cmp(l[0]) != 0 {
		t.Errorf("single-member root %v, want the leaf", r)
	}
	tree.Insert(l[1])
	tree.Insert(l[2])
	// The lone right-most node moves up unhashed.
	want := KeccakHasher(KeccakHasher(l[0], l[1]), l[2])
	if r, _ := tree.Root(); r.Cmp(want) != 0 {
		t.Errorf("root %#x, want %#x", r, want)
	}
	if want.Cmp(fieldModulus) < 0 {
		t.Logf("root below the BN254 modulus (expected 19%% of the time)")
	}
	p, err := tree.GenerateProof(2)
	if err != nil || !tree.VerifyProof(p) {
		t.Fatalf("proof for the lone leaf: %v", err)
	}
}

var fieldModulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
