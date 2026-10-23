package engine

import (
	"context"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
)

// Recovery fixtures run with a nil daemon client: a command step that actually
// executes dereferences it synchronously and panics (recovered per job → failure), so
// "exit 0" proves every step was skipped and "failure" proves one was attempted.

func recoveryWorkflow() *models.Workflow {
	return &models.Workflow{
		Name: "digest",
		Jobs: map[string]*models.Job{
			"report": {
				Name: "report",
				Steps: []models.Step{
					{Name: "kb-stats", Type: models.StepCommand, Command: "echo 3"},
					{Name: "ask", Type: models.StepCommand, Command: "ask-the-agent"},
				},
			},
		},
	}
}

func recovered(steps ...string) map[string]map[string]map[string]any {
	out := map[string]map[string]map[string]any{"report": {}}
	for _, s := range steps {
		out["report"][s] = map[string]any{"stdout": "saved:" + s, "exit_code": 0, "status": "success",
			"response": "", "outputs": nil}
	}
	return out
}

// Every step of the unfinished job already completed before the crash: the job must
// finish successfully with NO step executed and its saved results restored.
func TestRecoverySkipsCompletedStepsWithoutExecuting(t *testing.T) {
	var jobDone string
	var snap map[string]map[string]any
	code, ectx := RunWithContext(context.Background(), recoveryWorkflow(), nil, nil, "run1", 0, Options{
		CompletedSteps: map[string]map[string]bool{"report": {"kb-stats": true, "ask": true}},
		RecoveredSteps: recovered("kb-stats", "ask"),
		OnJobDone: func(jobName, status, _ string, steps map[string]map[string]any) {
			jobDone = jobName + ":" + status
			snap = steps
		},
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0 (nothing should have executed against the nil client)", code)
	}
	if jobDone != "report:success" {
		t.Fatalf("job outcome = %q", jobDone)
	}
	if snap["ask"] == nil || snap["ask"]["stdout"] != "saved:ask" {
		t.Fatalf("saved step result not restored into the job snapshot: %v", snap)
	}
	if ectx == nil {
		t.Fatalf("expression context missing")
	}
}

// Only the first step completed before the crash: the engine must skip it and
// attempt the second (which, with a nil client, panics → job failure). The failed
// attempt must not be persisted as completed.
func TestRecoveryExecutesOnlyRemainingSteps(t *testing.T) {
	persisted := map[string]bool{}
	code, _ := RunWithContext(context.Background(), recoveryWorkflow(), nil, nil, "run2", 0, Options{
		CompletedSteps: map[string]map[string]bool{"report": {"kb-stats": true}},
		RecoveredSteps: recovered("kb-stats"),
		OnStepPersist:  func(_, stepName string, _ map[string]any) { persisted[stepName] = true },
	})
	if code == 0 {
		t.Fatalf("exit 0: the remaining 'ask' step was not attempted")
	}
	if persisted["kb-stats"] {
		t.Fatalf("a recovered step must not be re-persisted")
	}
	if persisted["ask"] {
		t.Fatalf("a step that failed to run must not be persisted as completed")
	}
}

// A finally step that already completed before the crash is persisted like any other
// step (runStep → OnStepPersist), so a resume must not re-run it — a cleanup or LLM
// message step in `finally` would otherwise side-effect (and charge) twice.
func TestRecoverySkipsCompletedFinallySteps(t *testing.T) {
	wf := &models.Workflow{
		Name: "cleanup",
		Jobs: map[string]*models.Job{
			"j": {
				Name: "j",
				Steps: []models.Step{
					{Name: "work", Type: models.StepCommand, Command: "echo done"},
				},
				Finally: []models.Step{
					{Name: "notify", Type: models.StepCommand, Command: "notify-the-agent"},
				},
			},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run4", 0, Options{
		CompletedSteps: map[string]map[string]bool{"j": {"work": true, "notify": true}},
		RecoveredSteps: map[string]map[string]map[string]any{
			"j": {
				"work":   {"stdout": "saved:work", "exit_code": 0, "status": "success", "response": "", "outputs": nil},
				"notify": {"stdout": "saved:notify", "exit_code": 0, "status": "success", "response": "", "outputs": nil},
			},
		},
		OnJobDone: func(_, _ string, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0 (neither the recovered step nor the recovered finally step may execute)", code)
	}
	if snap["notify"] == nil || snap["notify"]["stdout"] != "saved:notify" {
		t.Fatalf("recovered finally step result not restored into the job snapshot: %v", snap)
	}
}

// Steps skipped by their own `if:` are terminal too and must be persisted, so a resume
// never re-evaluates them against a changed context.
func TestConditionSkippedStepIsPersisted(t *testing.T) {
	wf := &models.Workflow{
		Name: "gated",
		Jobs: map[string]*models.Job{
			"j": {Name: "j", Steps: []models.Step{
				{Name: "never", Type: models.StepCommand, Command: "true", Condition: "1 == 2"},
			}},
		},
	}
	var got map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run3", 0, Options{
		OnStepPersist: func(_, stepName string, data map[string]any) {
			if stepName == "never" {
				got = data
			}
		},
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0 (the only step is condition-skipped)", code)
	}
	if got == nil || got["status"] != models.StatusSkipped {
		t.Fatalf("skipped step not persisted as skipped: %v", got)
	}
}
