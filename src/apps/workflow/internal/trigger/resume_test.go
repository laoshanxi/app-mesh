package trigger

import (
	"context"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/engine"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/workdir"
)

// resumeHarness wires the checkpoint, the recoverState assembly and the engine exactly
// the way Service.launchRun does (minus the run capability, which needs a daemon), so a
// test can prove the whole crash→resume data path — not just one layer of it.
type resumeHarness struct {
	cp   *Checkpoint
	wdir *workdir.Manager
}

func newResumeHarness(t *testing.T) (*resumeHarness, string) {
	t.Helper()
	base := t.TempDir()
	w := workdir.NewManager(base, 10)
	return &resumeHarness{cp: NewCheckpoint(w), wdir: w}, base
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

// The full resume path a crash exercises: CompletedSteps come back out of the
// checkpoint, the engine skips both the completed main step AND the completed finally
// step (nil client: any execution panics → failure), and the final checkpoint carries
// every step's saved data — including the finally step's.
func TestResumePathSkipsCompletedMainAndFinallySteps(t *testing.T) {
	h, _ := newResumeHarness(t)
	wf := resumeWorkflow()
	runID := "run-resume-1"
	h.crashedRun(wf, runID)

	// resumeRun's assembly: completed jobs/steps + saved data in one atomic checkpoint.
	completedJobs, completedSteps, savedSteps, recovered := h.recoverAssembly(wf, runID)
	h.cp.SaveRunningWithCompleted(wf.Name, runID, "manual", "actor", nil, wf.Jobs, completedJobs, savedSteps)

	executed := map[string]string{}
	code, _ := engine.RunWithContext(context.Background(), wf, nil, nil, runID, 0, engine.Options{
		CompletedJobs:  completedJobs,
		CompletedSteps: completedSteps,
		RecoveredSteps: recovered,
		OnJobDone: func(jobName, status, _ string, steps map[string]map[string]any) {
			cpSteps := make(map[string]StepState, len(steps))
			for name, data := range steps {
				cpSteps[name] = stepDataToState(data)
			}
			h.cp.UpdateJob(wf.Name, runID, jobName, status, "", cpSteps)
		},
		OnStepPersist: func(_, stepName string, data map[string]any) {
			executed[stepName], _ = data["status"].(string)
		},
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0 (no recovered step may re-execute against the nil client)", code)
	}
	for _, name := range []string{"work", "cleanup"} {
		if _, ran := executed[name]; ran {
			t.Fatalf("recovered step %q re-executed and re-persisted on resume", name)
		}
	}
	if executed["tail"] != models.StatusSkipped {
		t.Fatalf("the not-yet-completed step 'tail' must still reach a terminal outcome, got %q", executed["tail"])
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
	h, _ := newResumeHarness(t)
	wf := resumeWorkflow()
	runID := "run-resume-2"
	jobNames := []string{"j"}
	h.cp.SaveRunning(wf.Name, runID, "manual", "actor", nil, jobNames)
	h.cp.UpdateStep(wf.Name, runID, "j", "work", StepState{Stdout: "did-work", ExitCode: 0, Status: "success"})
	h.cp.UpdateStep(wf.Name, runID, "j", "tail", StepState{Stdout: "did-tail", ExitCode: 0, Status: "success"})
	h.cp.UpdateStep(wf.Name, runID, "j", "cleanup", StepState{Stdout: "did-cleanup", ExitCode: 0, Status: "success"})
	h.cp.UpdateJob(wf.Name, runID, "j", "success", "", map[string]StepState{
		"work":    {Stdout: "did-work", ExitCode: 0, Status: "success"},
		"tail":    {Stdout: "did-tail", ExitCode: 0, Status: "success"},
		"cleanup": {Stdout: "did-cleanup", ExitCode: 0, Status: "success"},
	})

	completedJobs, completedSteps, savedSteps, recovered := h.recoverAssembly(wf, runID)
	h.cp.SaveRunningWithCompleted(wf.Name, runID, "manual", "actor", nil, wf.Jobs, completedJobs, savedSteps)

	if len(completedJobs) != 1 || completedJobs["j"] != "success" {
		t.Fatalf("terminal job not recovered as completed: %v", completedJobs)
	}
	if len(completedSteps) != 0 {
		t.Fatalf("a terminal job must not surface per-step completions: %v", completedSteps)
	}

	jobDone := false
	code, ectx := engine.RunWithContext(context.Background(), wf, nil, nil, runID, 0, engine.Options{
		CompletedJobs:  completedJobs,
		CompletedSteps: completedSteps,
		RecoveredSteps: recovered,
		OnJobDone:      func(_, _, _ string, _ map[string]map[string]any) { jobDone = true },
	})
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

// recoverAssembly mirrors Service.recoverState for tests (same code path, exposed via
// the harness so the assertions exercise the production assembly).
func (h *resumeHarness) recoverAssembly(wf *models.Workflow, runID string) (map[string]string,
	map[string]map[string]bool, map[string]map[string]StepState, map[string]map[string]map[string]any) {
	s := &Service{checkpoint: h.cp}
	return s.recoverState(wf.Name, runID)
}
