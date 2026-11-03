package trigger

import (
	"testing"
)

// A crash mid-job must not re-run steps that already completed inside that job: the
// checkpoint records each terminal step as it happens, and CompletedSteps exposes
// exactly those (and only for jobs that are themselves still unfinished).
func TestUpdateStepAndCompletedSteps(t *testing.T) {
	c, _, _ := newTestCheckpoint(t)
	c.SaveRunning("wf", "run1", "manual", "me", nil, []string{"report", "notify"})

	c.UpdateStep("wf", "run1", "report", "kb-stats", StepState{Stdout: "kb docs: 3", Status: "success"})
	c.UpdateStep("wf", "run1", "report", "gate", StepState{Status: "skipped"})
	// a failed step is recorded too but is never treated as completed (it re-runs)
	c.UpdateStep("wf", "run1", "report", "flaky", StepState{ExitCode: 1, Status: "failure"})

	got := c.CompletedSteps("wf", "run1")
	if len(got) != 1 || len(got["report"]) != 2 || !got["report"]["kb-stats"] || !got["report"]["gate"] {
		t.Fatalf("CompletedSteps = %v, want report:{kb-stats,gate}", got)
	}
	if got["report"]["flaky"] {
		t.Fatalf("a failed step must not count as completed")
	}

	// The step data round-trips through GetJobSteps for expression recovery.
	steps := c.GetJobSteps("wf", "run1", "report")
	if steps["kb-stats"].Stdout != "kb docs: 3" {
		t.Fatalf("saved stdout lost: %+v", steps["kb-stats"])
	}
	// The job's own status is untouched by step updates.
	if rec := c.GetRunRecord("wf", "run1"); rec.Jobs["report"].Status != "pending" {
		t.Fatalf("job status changed to %q by a step update", rec.Jobs["report"].Status)
	}

	// Once the job finishes, it is recovered whole (CompletedJobs) and drops out of
	// CompletedSteps so the two recovery paths never overlap.
	c.UpdateJob("wf", "run1", "report", "success", "", steps)
	if got := c.CompletedSteps("wf", "run1"); len(got) != 0 {
		t.Fatalf("finished job still reported in CompletedSteps: %v", got)
	}
	if cj := c.CompletedJobs("wf", "run1"); cj["report"] != "success" {
		t.Fatalf("CompletedJobs = %v", cj)
	}
}

func TestUpdateStepOnUnknownRunIsNoop(t *testing.T) {
	c, _, _ := newTestCheckpoint(t)
	c.UpdateStep("wf", "ghost", "j", "s", StepState{Status: "success"}) // must not create a record
	if c.GetRunRecord("wf", "ghost") != nil {
		t.Fatalf("UpdateStep created a checkpoint for an unknown run")
	}
}

// MarkCompleteError must surface why a run died before any step ran, and the
// reason survives the later MarkComplete that finalizes the status.
func TestMarkCompleteErrorSurvivesMarkComplete(t *testing.T) {
	c, _, _ := newTestCheckpoint(t)
	c.SaveRunning("wf", "run1", "manual", "me", nil, []string{"a"})

	c.MarkCompleteError("wf", "run1", "issue workflow run capability: 403")
	c.MarkComplete("wf", "run1", "failure")

	rec := c.GetRunRecord("wf", "run1")
	if rec == nil || rec.Error != "issue workflow run capability: 403" {
		t.Fatalf("expected capability reason preserved, got %+v", rec)
	}
}
