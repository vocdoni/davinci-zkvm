package poseidon2

import "math/big"

const (
	GoldilocksModulus   uint64 = 0xffffffff00000001
	ballotWidth                = 8
	ballotRate                 = 4
	ziskWidth                  = 16
	fullRounds                 = 8
	halfFullRounds             = fullRounds / 2
	partialRoundsBallot        = 22
	partialRoundsZisk          = 22
)

var goldilocksModulusBig = new(big.Int).SetUint64(GoldilocksModulus)

func add(a, b uint64) uint64 {
	z := new(big.Int).SetUint64(a)
	z.Add(z, new(big.Int).SetUint64(b))
	z.Mod(z, goldilocksModulusBig)
	return z.Uint64()
}

func sub(a, b uint64) uint64 {
	z := new(big.Int).SetUint64(a)
	z.Sub(z, new(big.Int).SetUint64(b))
	z.Mod(z, goldilocksModulusBig)
	if z.Sign() < 0 {
		z.Add(z, goldilocksModulusBig)
	}
	return z.Uint64()
}

func mul(a, b uint64) uint64 {
	z := new(big.Int).SetUint64(a)
	z.Mul(z, new(big.Int).SetUint64(b))
	z.Mod(z, goldilocksModulusBig)
	return z.Uint64()
}

func pow7(x uint64) uint64 {
	x2 := mul(x, x)
	x3 := mul(x, x2)
	x4 := mul(x2, x2)
	return mul(x3, x4)
}

func matmulM4(x []uint64) {
	t0 := add(x[0], x[1])
	t1 := add(x[2], x[3])
	t2 := add(add(x[1], x[1]), t1)
	t3 := add(add(x[3], x[3]), t0)
	t1x2 := add(t1, t1)
	t0x2 := add(t0, t0)
	t4 := add(add(t1x2, t1x2), t3)
	t5 := add(add(t0x2, t0x2), t2)
	t6 := add(t3, t5)
	t7 := add(t2, t4)
	x[0], x[1], x[2], x[3] = t6, t5, t7, t4
}

func matmulExternal(state []uint64) {
	for i := 0; i < len(state); i += 4 {
		matmulM4(state[i : i+4])
	}
	stored := [4]uint64{}
	for i := 0; i < 4; i++ {
		for j := 0; j < len(state)/4; j++ {
			stored[i] = add(stored[i], state[j*4+i])
		}
	}
	for i := range state {
		state[i] = add(state[i], stored[i%4])
	}
}

func matmulInternal(state []uint64, diag []uint64) {
	sum := uint64(0)
	for _, v := range state {
		sum = add(sum, v)
	}
	for i := range state {
		state[i] = add(mul(state[i], diag[i]), sum)
	}
}

func permuteBallot(state *[ballotWidth]uint64) {
	matmulExternal(state[:])
	for r := 0; r < halfFullRounds; r++ {
		for i := 0; i < ballotWidth; i++ {
			state[i] = pow7(add(state[i], hlExternalRoundConstants8[r][i]))
		}
		matmulExternal(state[:])
	}
	for r := 0; r < partialRoundsBallot; r++ {
		state[0] = pow7(add(state[0], hlInternalRoundConstants8[r]))
		matmulInternal(state[:], matrixDiag8[:])
	}
	for r := 0; r < halfFullRounds; r++ {
		for i := 0; i < ballotWidth; i++ {
			state[i] = pow7(add(state[i], hlExternalRoundConstants8[halfFullRounds+r][i]))
		}
		matmulExternal(state[:])
	}
}

func permuteZisk(state *[ziskWidth]uint64) {
	matmulExternal(state[:])
	for r := 0; r < halfFullRounds; r++ {
		base := r * ziskWidth
		for i := 0; i < ziskWidth; i++ {
			state[i] = pow7(add(state[i], ziskRoundConstants16[base+i]))
		}
		matmulExternal(state[:])
	}
	for r := 0; r < partialRoundsZisk; r++ {
		state[0] = pow7(add(state[0], ziskRoundConstants16[halfFullRounds*ziskWidth+r]))
		matmulInternal(state[:], ziskMatrixDiag16[:])
	}
	for r := 0; r < halfFullRounds; r++ {
		base := halfFullRounds*ziskWidth + partialRoundsZisk + r*ziskWidth
		for i := 0; i < ziskWidth; i++ {
			state[i] = pow7(add(state[i], ziskRoundConstants16[base+i]))
		}
		matmulExternal(state[:])
	}
}

// PermuteWidth8 runs the davinci-stark ballot permutation used for vote-id and inputs hashing.
func PermuteWidth8(input [ballotWidth]uint64) [ballotWidth]uint64 {
	state := input
	permuteBallot(&state)
	return state
}

// HashWidth8 runs the davinci-stark width-8 sponge with rate 4.
func HashWidth8(input []uint64, outputLen int) []uint64 {
	state := [ballotWidth]uint64{}
	for start := 0; start < len(input); start += ballotRate {
		end := start + ballotRate
		if end > len(input) {
			end = len(input)
		}
		for i := start; i < end; i++ {
			state[i-start] = add(state[i-start], input[i])
		}
		permuteBallot(&state)
	}
	if outputLen > ballotWidth {
		outputLen = ballotWidth
	}
	out := make([]uint64, outputLen)
	copy(out, state[:outputLen])
	return out
}

// PermuteWidth16 runs the ZisK-compatible width-16 Goldilocks Poseidon2 permutation.
func PermuteWidth16(input [ziskWidth]uint64) [ziskWidth]uint64 {
	state := input
	permuteZisk(&state)
	return state
}
