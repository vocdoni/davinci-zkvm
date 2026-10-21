package spec

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

// TestBallotModeValidateCostRule pins the registry's creation rule at its
// boundaries (davinci-contracts ProcessRegistry, rust-sdk BallotMode::validate).
func TestBallotModeValidateCostRule(t *testing.T) {
	c := qt.New(t)
	mode := func(nf uint8, maxValue uint64, exp uint8) BallotMode {
		return BallotMode{NumFields: nf, GroupSize: nf, CostExponent: exp, MaxValue: maxValue}
	}
	for _, tc := range []struct {
		name string
		mode BallotMode
		ok   bool
	}{
		{"16 * (2^48-1)^1", mode(16, 1<<48-1, 1), true},
		{"16 * (2^15)^4 = 2^64", mode(16, 1<<15, 4), false},
		{"1 * (2^63-1)^1 = 2^63-1", mode(1, 1<<63-1, 1), true},
		{"1 * (2^63)^1 = 2^63", mode(1, 1<<63, 1), false},
		{"2 * (2^31)^2 = 2^63", mode(2, 1<<31, 2), false},
		{"1 * 3037000499^2 < 2^63", mode(1, 3037000499, 2), true},
		{"16 * (2^48-1)^255 overflows", mode(16, 1<<48-1, 255), false},
		{"16 * 1^255", mode(16, 1, 255), true},
		{"costExponent 0", mode(16, 1, 0), false},
	} {
		err := tc.mode.Validate()
		c.Assert(err == nil, qt.Equals, tc.ok, qt.Commentf("%s: %v", tc.name, err))
	}
}
