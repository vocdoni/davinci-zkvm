package testutil

import (
	"math/big"

	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/spec"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/spec/params"
	spectestutil "github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/spec/testutil"
	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/types"
)

// Trimmed from davinci-node internal/testutil: only the deterministic ballot
// helpers the vendored circom harness needs. The Process/Census/EncryptionKey
// generators were dropped to avoid pulling in the heavy types.Process tree.

const Weight = 42

func BallotMode() spec.BallotMode {
	return spectestutil.FixedBallotMode()
}

// GenDeterministicBallotFields generates a list of deterministic fields
// based on the provided seed for reproducible testing.
func GenDeterministicBallotFields(seed int64) [params.FieldsPerBallot]*types.BigInt {
	bm := spectestutil.FixedBallotMode()
	fields := [params.FieldsPerBallot]*types.BigInt{}
	for i := range len(fields) {
		fields[i] = types.NewInt(0)
	}

	// Use seed-based deterministic generation
	stored := map[string]bool{}
	for i := range bm.NumFields {
		for attempt := 0; ; attempt++ {
			// Generate deterministic field based on seed, index, and attempt
			fieldSeed := seed + int64(i)*1000 + int64(attempt)
			fieldValue := int64(bm.MinValue) + (fieldSeed % int64(bm.MaxValue-bm.MinValue))
			field := big.NewInt(fieldValue)

			// if it should be unique and it's already stored, try next attempt
			if bm.UniqueValues || !stored[field.String()] {
				fields[i] = fields[i].SetBigInt(field)
				stored[field.String()] = true
				break
			}
		}
	}
	return fields
}
