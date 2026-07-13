package integration

// The child (worker) side of subprocess-based ballot proof generation lives in
// ballot_worker.go (RunBallotWorkerIfRequested) so that external test binaries
// embedding this package can intercept BALLOT_WORKER_MODE too. TestMain must
// intercept before any test framework setup.

import (
	"os"
	"testing"
)

// TestMain intercepts the worker mode before any test framework setup.
func TestMain(m *testing.M) {
	RunBallotWorkerIfRequested()
	os.Exit(m.Run())
}
