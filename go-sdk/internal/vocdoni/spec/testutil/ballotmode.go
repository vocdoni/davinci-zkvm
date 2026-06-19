package testutil

import (
	"os"
	"strconv"

	"github.com/vocdoni/davinci-zkvm/go-sdk/internal/vocdoni/spec"
)

const (
	BallotNumFields    = 6
	BallotGroupSize    = 2
	BallotUniqueValues = 0
	BallotMaxValue     = 16
	BallotMinValue     = 0
	BallotMaxValueSum  = 1280 // (maxValue ^ costExponent) * numFields
	BallotMinValueSum  = BallotNumFields
	BallotCostExponent = 2
)

// ballotNumFields returns the active field count for fixtures. It defaults to
// BallotNumFields but can be overridden with BALLOT_NUM_FIELDS to sweep
// different configurations in tests (clamped to [1, FieldsPerBallot]).
func ballotNumFields() int {
	nf := BallotNumFields
	if v := os.Getenv("BALLOT_NUM_FIELDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			nf = n
		}
	}
	return nf
}

// FixedBallotMode returns a fixed ballot mode fixture used in tests. The active
// field count honors BALLOT_NUM_FIELDS; the sum bounds scale with it so the
// circom constraints hold for any field count (MinValueSum=0 never under-runs,
// MaxValueSum=MaxValue^CostExponent*numFields never over-runs).
func FixedBallotMode() spec.BallotMode {
	nf := ballotNumFields()
	maxValueSum := uint64(BallotMaxValue) * uint64(BallotMaxValue) * uint64(nf) // MaxValue^CostExponent * numFields
	return spec.BallotMode{
		NumFields:    uint8(nf),
		GroupSize:    BallotGroupSize,
		UniqueValues: BallotUniqueValues == 1,
		MaxValue:     BallotMaxValue,
		MinValue:     BallotMinValue,
		MaxValueSum:  maxValueSum,
		MinValueSum:  0,
		CostExponent: BallotCostExponent,
	}
}
