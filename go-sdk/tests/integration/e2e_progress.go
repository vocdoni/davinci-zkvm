package integration

type batchProgress struct {
	Created        int
	Overwrites     int
	FreshAssigned  int
	FreshRemaining int
	NetBallots     int
	OverwritesSeen int
}

func batchProgressSummary(spec batchSpec, freshAssigned, totalFresh, netBallots, overwritesSeen int) batchProgress {
	created := 0
	overwrites := 0
	if spec.VoterStart >= 0 {
		overwrites = spec.Size
	} else {
		created = spec.Size
	}
	return batchProgress{
		Created:        created,
		Overwrites:     overwrites,
		FreshAssigned:  freshAssigned,
		FreshRemaining: totalFresh - freshAssigned,
		NetBallots:     netBallots,
		OverwritesSeen: overwritesSeen,
	}
}
