package integration

import "testing"

func TestStarkBatchStartLog(t *testing.T) {
	got := starkBatchStartLog(128, 8, 42)
	want := "[stark-wasm] starting batch: votes=128 concurrency=8 seedBase=42"
	if got != want {
		t.Fatalf("start log = %q, want %q", got, want)
	}
}

func TestStarkVoteCreatedLog(t *testing.T) {
	got := starkVoteCreatedLog(5, 64, 17, 12345)
	want := "[stark-wasm] created vote 5/64 remaining=59 voterIndex=17 voteId=12345"
	if got != want {
		t.Fatalf("created log = %q, want %q", got, want)
	}
}
