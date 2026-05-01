package jobs

import (
	"slices"
	"testing"

	"github.com/riverqueue/river/rivertype"
)

func TestEmailOutboxArgsInsertOptsPreventsOverlappingJobs(t *testing.T) {
	opts := (EmailOutboxArgs{}).InsertOpts()

	if opts.Queue != "" {
		t.Fatalf("InsertOpts.Queue = %q, want River default queue", opts.Queue)
	}

	wantStates := []rivertype.JobState{
		rivertype.JobStateAvailable,
		rivertype.JobStatePending,
		rivertype.JobStateRunning,
		rivertype.JobStateRetryable,
		rivertype.JobStateScheduled,
	}
	if !slices.Equal(opts.UniqueOpts.ByState, wantStates) {
		t.Fatalf("InsertOpts.UniqueOpts.ByState = %v, want %v", opts.UniqueOpts.ByState, wantStates)
	}
	if slices.Contains(opts.UniqueOpts.ByState, rivertype.JobStateCompleted) {
		t.Fatal("InsertOpts.UniqueOpts.ByState contains completed, want next run to be insertable after success")
	}
}
