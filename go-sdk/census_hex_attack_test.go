package davinci

import (
	"strings"
	"testing"
)

// BUG: census values reach the CENSUS block without the 0x + 64 hex digit form input-gen, rust-sdk and TS require: "", "0x", short or decimal strings are left-padded and read as another root, leaf or sibling.
func TestCensusValuesRequireStrictHex(t *testing.T) {
	good := "0x" + strings.Repeat("0a", 32)
	bad := []string{
		"",
		"0x",
		"12345",
		strings.Repeat("0a", 32),               // no 0x
		"0x" + strings.Repeat("a", 63),         // short
		"0x" + strings.Repeat("a", 65),         // long
		"0X" + strings.Repeat("0a", 32),        // input-gen strips "0x" only
		" 0x" + strings.Repeat("0a", 32),       // whitespace
		"0x" + strings.Repeat("0a", 31) + "g0", // non-hex
		"0x+" + strings.Repeat("a", 63),
	}
	for _, b := range bad {
		for pos, p := range map[string]CensusProof{
			"root":    {Root: b, Leaf: good},
			"leaf":    {Root: good, Leaf: b},
			"sibling": {Root: good, Leaf: good, Siblings: []string{good, b}},
		} {
			if _, err := EncodeCensusBlock([]CensusProof{p}); err == nil {
				t.Errorf("EncodeCensusBlock accepted %s %q", pos, b)
			}
		}
		if _, err := (CensusProof{Leaf: b}).SlotKey(); err == nil {
			t.Errorf("SlotKey accepted leaf %q", b)
		}
	}
	// The spec form, either case, still encodes.
	for _, v := range []string{good, "0x" + strings.Repeat("0A", 32), "0x" + strings.Repeat("f", 64)} {
		if _, err := EncodeCensusBlock([]CensusProof{{Root: v, Leaf: v, Siblings: []string{v}}}); err != nil {
			t.Errorf("EncodeCensusBlock refused %q: %v", v, err)
		}
	}
}
