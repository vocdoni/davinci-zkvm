package integration

import "fmt"

func starkBatchStartLog(total, concurrency int, seedBase int64) string {
	return fmt.Sprintf("[stark-wasm] starting batch: votes=%d concurrency=%d seedBase=%d", total, concurrency, seedBase)
}

func starkVoteCreatedLog(done, total int, voterIndex int, voteID uint64) string {
	return fmt.Sprintf("[stark-wasm] created vote %d/%d remaining=%d voterIndex=%d voteId=%d", done, total, total-done, voterIndex, voteID)
}
