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
	AggVK:   "0xc3fce781c27ef9f1e7b1091a8e2d1fde1f90b0488279d0fee065271205db3643",
	BatchVK: "0xcb4a14ecbd01bc7a304b7c36f172ac398daf418112d406bb16a557a4fb16b19e",
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
