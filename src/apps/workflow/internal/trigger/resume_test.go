package trigger

import (
	"context"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/engine"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/workdir"
)

// resumeHarness wires a real Checkpoint and workdir into a real Service, so the
// resume tests run the production recovery path — recoverState plus the engine
// options from engineOptions — rather than a copy of it. Only the daemon-dependent
// parts (capability issuance, TCP client) are absent.
type resumeHarness struct {
	svc *Service
	cp  *Checkpoint
}

func newResumeHarness(t *testing.T) *resumeHarness {
	t.Helper()
	w := workdir.NewManager(t.TempDir(), 10)
	s := &Service{checkpoint: NewCheckpoint(w), wdir: w}
	return &resumeHarness{svc: s, cp: s.checkpoint}
}

// crashedRun persists the state a SIGKILL leaves behind: a run whose first main step
// and whose finally step both completed (OnStepPersist), with the job still unfinished.
func (h *resumeHarness) crashedRun(wf *models.Workflow, runID string) {
	jobNames := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		jobNames = append(jobNames, name)
	}
	h.cp.SaveRunning(wf.Name, runID, "manual", "actor", nil, jobNames)
	h.cp.UpdateStep(wf.Name, runID, "j", "work", StepState{
		Stdout: "did-work", ExitCode: 0, Status: "success",
	})
	h.cp.UpdateStep(wf.Name, runID, "j", "cleanup", StepState{
		Stdout: "did-cleanup", ExitCode: 0, Status: "success",
	})
}

func resumeWorkflow() *models.Workflow {
	return &models.Workflow{
		Name: "resume-e2e",
		Jobs: map[string]*models.Job{
			"j": {
				Name: "j",
				Steps: []models.Step{
					{Name: "work", Type: models.StepCommand, Command: "echo did-work"},
					// Condition-skipped, so the resume reaches a terminal outcome for the
					// remaining step without a daemon (a real execution needs a client).
					{Name: "tail", Type: models.StepCommand, Command: "echo did-tail", Condition: "1 == 2"},
				},
				Finally: []models.Step{
					{Name: "cleanup", Type: models.StepCommand, Command: "echo did-cleanup"},
				},
			},
		},
	}
}

// resumeOptions rebuilds the run after a crash exactly as resumeRun does: one atomic
// checkpoint with completed and pending jobs, then the production engine options.
func (h *resumeHarness) resumeOptions(wf *models.Workflow, runID string) engine.Options {
	completedJobs, completedSteps, savedSteps, recovered := h.svc.recoverState(wf.Name, runID)
	h.cp.SaveRunningWithCompleted(wf.Name, runID, "manual", "actor", nil, wf.Jobs, completedJobs, savedSteps)
	return h.svc.engineOptions(wf, runID, "", nil, nil, completedJobs, completedSteps, recovered)
}

// The full resume path a crash exercises: CompletedSteps come back out of the
// checkpoint, the engine skips both the completed main step AND the completed finally
// step (nil client: any execution panics → failure), and the final checkpoint carries
// every step's saved data — including the finally step's.
func TestResumePathSkipsCompletedMainAndFinallySteps(t *testing.T) {
	h := newResumeHarness(t)
	wf := resumeWorkflow()
	runID := "run-resume-1"
	h.crashedRun(wf, runID)

	opts := h.resumeOptions(wf, runID)
	inner := opts.OnStepPersist // observe persists through the production callback
	var persisted []string
	opts.OnStepPersist = func(jobName, stepName string, data map[string]any) {
		persisted = append(persisted, stepName)
		inner(jobName, stepName, data)
	}

	code, _ := engine.RunWithContext(context.Background(), wf, nil, nil, runID, 0, opts)
	if code != 0 {
		t.Fatalf("exit %d, want 0 (no recovered step may re-execute against the nil client)", code)
	}
	if len(persisted) != 1 || persisted[0] != "tail" {
		t.Fatalf("persisted steps = %v, want exactly the not-yet-completed 'tail'", persisted)
	}

	// The final checkpoint keeps every step's result, including the recovered ones.
	rec := h.cp.GetRunRecord(wf.Name, runID)
	job := rec.Jobs["j"]
	if job.Status != "success" {
		t.Fatalf("resumed job status = %q, want success", job.Status)
	}
	for name, want := range map[string]string{"work": "success", "tail": "skipped", "cleanup": "success"} {
		if job.Steps[name].Status != want {
			t.Fatalf("step %q status = %q, want %q, in final checkpoint: %+v", name, job.Steps[name].Status, want,
				job.Steps)
		}
	}
	if job.Steps["work"].Stdout != "did-work" || job.Steps["cleanup"].Stdout != "did-cleanup" {
		t.Fatalf("recovered step data lost in final checkpoint: %+v", job.Steps)
	}
}

// A job that was already terminal (success) in the crashed run resumes whole: its
// steps are restored for downstream expressions and OnJobDone is not re-invoked.
func TestResumePathSkipsTerminalJobAndKeepsItsSteps(t *testing.T) {
	h := newResumeHarness(t)
	wf := resumeWorkflow()
	runID := "run-resume-2"
	h.cp.SaveRunning(wf.Name, runID, "manual", "actor", nil, []string{"j"})
	h.cp.UpdateJob(wf.Name, runID, "j", "success", "", map[string]StepState{
		"work":    {Stdout: "did-work", ExitCode: 0, Status: "success"},
		"tail":    {Stdout: "did-tail", ExitCode: 0, Status: "success"},
		"cleanup": {Stdout: "did-cleanup", ExitCode: 0, Status: "success"},
	})

	opts := h.resumeOptions(wf, runID)
	jobDone := false // observe through the production callback
	inner := opts.OnJobDone
	opts.OnJobDone = func(jobName, status, host string, steps map[string]map[string]any) {
		jobDone = true
		inner(jobName, status, host, steps)
	}

	code, ectx := engine.RunWithContext(context.Background(), wf, nil, nil, runID, 0, opts)
	if code != 0 {
		t.Fatalf("exit %d, want 0 (a terminal job must not execute anything)", code)
	}
	if jobDone {
		t.Fatalf("OnJobDone re-invoked for an already-terminal job")
	}
	if got := ectx.Steps["j.work"]; got["stdout"] != "did-work" {
		t.Fatalf("terminal job step data not restored into expressions: %v", got)
	}
}
