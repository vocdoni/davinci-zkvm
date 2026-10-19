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
	// ResultsVK is the circuit-results program_vk: the per-batch settlement
	// verifies the tally PLONK under it. Not part of Verify or IsSet; check it
	// with ResultsSet.
	ResultsVK string
}

// CircuitRelease is the canonical release for the ELFs committed in this repo
// (circuit/elf/circuit.elf + circuit-aggregator/elf/aggregator.elf +
// circuit-results/elf/results.elf). Regenerate after rebuilding the guests with
// scripts/build-guests.sh: `cargo-zisk setup -e <elf> -k <proving-key>` prints
// `Root hash`, whose words rendered big-endian and concatenated are the vk.
var CircuitRelease = Release{
	AggVK:     "0xb0dd8f234ae6dcb168b444b30d00addc5e780e136a012dd9058b182aeb8f0410",
	BatchVK:   "0x1e4a74a1c6fb1cd1874d80895e1e075930837955efb4a135539016f7cdead2a8",
	ResultsVK: "0xde55d751582e510bf378d4eec0d98ee3fa5817a50b77bc0e5ce560035e29e4e9",
}

// IsSet reports whether the release has been pinned (both vks present).
func (r Release) IsSet() bool { return r.AggVK != "" && r.BatchVK != "" }

// ResultsSet reports whether the results vk has been pinned. IsSet leaves it
// out because chained-mode verification never uses it.
func (r Release) ResultsSet() bool { return r.ResultsVK != "" }

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
