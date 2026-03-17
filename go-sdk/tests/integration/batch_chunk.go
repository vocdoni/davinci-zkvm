package integration

import (
	"os"
	"strconv"

	davinci "github.com/vocdoni/davinci-zkvm/go-sdk"
)

func maxProofsPerJobFromEnv() int {
	limit := 32
	if s := os.Getenv("DAVINCI_MAX_PROOFS_PER_JOB"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 2 {
			limit = n
		}
	}
	maxBatchSize := davinci.ConfiguredMaxBatchSize()
	if limit > maxBatchSize {
		limit = maxBatchSize
	}
	power := 1
	for power*2 <= limit {
		power *= 2
	}
	if power < 2 {
		return 2
	}
	return power
}

func chunkBatchSize(total int) []int {
	if total <= 0 {
		return nil
	}
	limit := maxProofsPerJobFromEnv()
	var chunks []int
	remaining := total
	for remaining > 0 {
		size := limit
		for size > remaining {
			size /= 2
		}
		if size < 2 {
			size = remaining
		}
		chunks = append(chunks, size)
		remaining -= size
	}
	return chunks
}
