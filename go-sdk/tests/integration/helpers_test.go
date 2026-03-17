package integration

import "testing"

func TestVotesPerBatchFromEnvUsesConfiguredMaxBatchSize(t *testing.T) {
	t.Setenv("DAVINCI_MAX_BATCH_SIZE", "256")
	t.Setenv("VOTES_PER_BATCH", "300")
	if got := votesPerBatchFromEnv(); got != 256 {
		t.Fatalf("votesPerBatchFromEnv() = %d, want 256", got)
	}
}

func TestVotesPerBatchFromEnvDefaultsToFour(t *testing.T) {
	t.Setenv("DAVINCI_MAX_BATCH_SIZE", "")
	t.Setenv("VOTES_PER_BATCH", "")
	if got := votesPerBatchFromEnv(); got != 4 {
		t.Fatalf("votesPerBatchFromEnv() = %d, want 4", got)
	}
}

func TestStarkMaxConcurrencyFromEnv(t *testing.T) {
	t.Setenv("DAVINCI_STARK_MAX_CONCURRENCY", "3")
	if got := starkMaxConcurrencyFromEnv(); got != 3 {
		t.Fatalf("starkMaxConcurrencyFromEnv() = %d, want 3", got)
	}
}

func TestStarkMaxConcurrencyDefaultsToEight(t *testing.T) {
	t.Setenv("DAVINCI_STARK_MAX_CONCURRENCY", "")
	if got := starkMaxConcurrencyFromEnv(); got != 8 {
		t.Fatalf("starkMaxConcurrencyFromEnv() = %d, want 8", got)
	}
}
