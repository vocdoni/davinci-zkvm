package integration

import "testing"

func TestMaxProofsPerJobFromEnvDefaultsToSixteen(t *testing.T) {
	t.Setenv("DAVINCI_MAX_PROOFS_PER_JOB", "")
	if got := maxProofsPerJobFromEnv(); got != 16 {
		t.Fatalf("maxProofsPerJobFromEnv() = %d, want 16", got)
	}
}

func TestChunkBatchSizeSplitsLargeLogicalBatch(t *testing.T) {
	t.Setenv("DAVINCI_MAX_PROOFS_PER_JOB", "64")
	got := chunkBatchSize(128)
	want := []int{64, 64}
	if len(got) != len(want) {
		t.Fatalf("chunkBatchSize len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chunkBatchSize[%d] = %d, want %d (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestChunkBatchSizeKeepsSmallBatchWhole(t *testing.T) {
	t.Setenv("DAVINCI_MAX_PROOFS_PER_JOB", "64")
	got := chunkBatchSize(32)
	if len(got) != 1 || got[0] != 32 {
		t.Fatalf("chunkBatchSize(32) = %v, want [32]", got)
	}
}
