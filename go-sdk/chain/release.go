// release.go pins the canonical verification keys of one circuit ELF release.
// Pinning these grounds the recursion: an independent verifier anchors the
// final proof's program_vk to CircuitRelease.AggVK (so the fold_vk==program_vk
// knot binds to a known circuit, not a self-chosen one) and folds both vks into
// the election-identity commitment. Rebuilding either guest changes the release.
package chain

import (
	"fmt"
	"strings"
)

// Release is the canonical (aggregator, vote-batch) program_vk pair for one ELF
// release. Both are 0x-prefixed big-endian hex, the form digest.FoldVK /
// digest.BatchVK and PlonkSnark.ProgramVK use.
type Release struct {
	AggVK   string
	BatchVK string
}

// CircuitRelease is the canonical release for the ELFs committed in this repo
// (circuit/elf/circuit.elf + circuit-aggregator/elf/aggregator.elf). Regenerate
// after rebuilding either guest: run a fold + finalize and read the digest's
// fold_vk (== aggregator program_vk) and batch_vk.
var CircuitRelease = Release{
	AggVK:   "0xf0ae0dc3a3e1c4df4c5c4a356db8f1f2a675ba393682170fc9ac6b1497f47790",
	BatchVK: "0x6ae4f9e9ff8cf2866223435f8354d25b7894d28d64c83ec9eeb0dd1c1b0c4b85",
}

// IsSet reports whether the release has been pinned (both vks present).
func (r Release) IsSet() bool { return r.AggVK != "" && r.BatchVK != "" }

// AggWords / BatchWords return the vks as the guest's native u64 words for the
// config-commitment computation.
func (r Release) AggWords() ([4]uint64, error)   { return VKWords(r.AggVK) }
func (r Release) BatchWords() ([4]uint64, error) { return VKWords(r.BatchVK) }

// Verify asserts learned vks (from FetchStarkInfo or a fold digest) match this
// release, catching a worker running a stale or wrong ELF.
func (r Release) Verify(aggVK, batchVK string) error {
	if !vkEqual(r.AggVK, aggVK) {
		return fmt.Errorf("aggregator vk mismatch: release %s, got %s", r.AggVK, aggVK)
	}
	if !vkEqual(r.BatchVK, batchVK) {
		return fmt.Errorf("batch vk mismatch: release %s, got %s", r.BatchVK, batchVK)
	}
	return nil
}

// vkEqual compares two vk hex strings ignoring 0x prefix and case.
func vkEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimPrefix(a, "0x"), strings.TrimPrefix(b, "0x"))
}
