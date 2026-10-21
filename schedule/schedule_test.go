package schedule

import (
	"testing"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
)

func TestNewAlwaysBoundsTheRun(t *testing.T) {
	s, err := New("nightly", "0 4 * * *", "Refresh", "geo")
	if err != nil {
		t.Fatal(err)
	}
	if s.ExecutionTimeout != DefaultExecutionTimeout || s.Overlap != enumspb.SCHEDULE_OVERLAP_POLICY_SKIP || s.WorkflowID != "nightly" {
		t.Errorf("defaults: %+v", s)
	}
	if _, err := New("nightly", "0 4 * * *", "Refresh", "geo", WithExecutionTimeout(0)); err == nil {
		t.Error("a zero timeout must be refused: it is how one wedged run ends a schedule")
	}
	if _, err := New("", "0 4 * * *", "Refresh", "geo"); err == nil {
		t.Error("accepted an empty id")
	}
	s, _ = New("five", "*/5 * * * *", "Segment", "flights",
		WithExecutionTimeout(10*time.Minute), WithTimeZone("America/Los_Angeles"), WithArgs(1, "x"), WithWorkflowID("five/scheduled"))
	if s.ExecutionTimeout != 10*time.Minute || s.TimeZone != "America/Los_Angeles" || len(s.Args) != 2 || s.WorkflowID != "five/scheduled" {
		t.Errorf("options not applied: %+v", s)
	}
}
