package chain

import "testing"

// TestCircuitReleasePinned checks the committed release carries all three vks
// as 32-byte hex.
func TestCircuitReleasePinned(t *testing.T) {
	if !CircuitRelease.IsSet() || !CircuitRelease.ResultsSet() {
		t.Fatalf("CircuitRelease not fully pinned: %+v", CircuitRelease)
	}
	for name, vk := range map[string]string{
		"AggVK":     CircuitRelease.AggVK,
		"BatchVK":   CircuitRelease.BatchVK,
		"ResultsVK": CircuitRelease.ResultsVK,
	} {
		if _, err := VKWords(vk); err != nil {
			t.Errorf("%s %q: %v", name, vk, err)
		}
	}
	if (Release{}).IsSet() || (Release{}).ResultsSet() {
		t.Fatal("empty release reported as set")
	}
	if (Release{AggVK: "0x1", BatchVK: "0x2"}).ResultsSet() {
		t.Fatal("ResultsSet ignores ResultsVK")
	}
}
