package integration

import "testing"

func TestBatchProgressSummaryFresh(t *testing.T) {
	spec := batchSpec{Size: 8, VoterStart: -1, SeedOffset: 0}
	got := batchProgressSummary(spec, 12, 32, 12, 0)

	if got.Created != 8 {
		t.Fatalf("Created = %d, want 8", got.Created)
	}
	if got.Overwrites != 0 {
		t.Fatalf("Overwrites = %d, want 0", got.Overwrites)
	}
	if got.FreshAssigned != 12 {
		t.Fatalf("FreshAssigned = %d, want 12", got.FreshAssigned)
	}
	if got.FreshRemaining != 20 {
		t.Fatalf("FreshRemaining = %d, want 20", got.FreshRemaining)
	}
	if got.NetBallots != 12 {
		t.Fatalf("NetBallots = %d, want 12", got.NetBallots)
	}
	if got.OverwritesSeen != 0 {
		t.Fatalf("OverwritesSeen = %d, want 0", got.OverwritesSeen)
	}
}

func TestBatchProgressSummaryOverwrite(t *testing.T) {
	spec := batchSpec{Size: 4, VoterStart: 2, SeedOffset: 7}
	got := batchProgressSummary(spec, 12, 32, 12, 6)

	if got.Created != 0 {
		t.Fatalf("Created = %d, want 0", got.Created)
	}
	if got.Overwrites != 4 {
		t.Fatalf("Overwrites = %d, want 4", got.Overwrites)
	}
	if got.FreshAssigned != 12 {
		t.Fatalf("FreshAssigned = %d, want 12", got.FreshAssigned)
	}
	if got.FreshRemaining != 20 {
		t.Fatalf("FreshRemaining = %d, want 20", got.FreshRemaining)
	}
	if got.NetBallots != 12 {
		t.Fatalf("NetBallots = %d, want 12", got.NetBallots)
	}
	if got.OverwritesSeen != 6 {
		t.Fatalf("OverwritesSeen = %d, want 6", got.OverwritesSeen)
	}
}
