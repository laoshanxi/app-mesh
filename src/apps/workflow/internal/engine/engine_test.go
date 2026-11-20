package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
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

func TestKillAllSparesFinallySteps(t *testing.T) {
	a := NewActiveSteps(nil, "")
	a.Set("j", "main", "app-main", "", false)
	a.Set("j", "cleanup", "app-finally", "", true)
	a.KillAll() // nil client: kill calls are skipped, partitioning still applies
	a.mu.Lock()
	_, mainKilled := a.apps["j.main"]
	_, finallyKept := a.apps["j.cleanup"]
	a.mu.Unlock()
	if mainKilled {
		t.Fatal("main step entry must be dropped by KillAll")
	}
	if !finallyKept {
		t.Fatal("finally step entry must survive KillAll")
	}
}

// A strict workflow fails a step whose expression cannot resolve, before any
// client call; the lenient default embeds the expression literally.
func TestStrictExpressionsFailStep(t *testing.T) {
	wf := &models.Workflow{
		Name:              "strict-demo",
		StrictExpressions: true,
		Jobs: map[string]*models.Job{
			"build": {Name: "build", Steps: []models.Step{
				{Name: "greet", Type: models.StepCommand, Command: "echo ${{ inputz.name }}"},
			}},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run1", 0, Options{
		OnJobDone: func(_, _, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code == 0 {
		t.Fatalf("exit 0, want 1 (unresolved expression must fail the step)")
	}
	s := snap["greet"]
	if s == nil || s["status"] != models.StatusFailure {
		t.Fatalf("step result = %v, want failure", s)
	}
	if stdout, _ := s["stdout"].(string); !strings.Contains(stdout, "unresolved expression") {
		t.Fatalf("step stdout = %q, want unresolved-expression message", stdout)
	}
}

// A plain-text message step's missing outputs must fail the referencing step
// with the clear engine error, not reach the shell as a literal.
func TestMessageOutputsPlainTextFailsStepClearly(t *testing.T) {
	wf := &models.Workflow{
		Name: "ask",
		Jobs: map[string]*models.Job{
			"j": {Name: "j", Steps: []models.Step{
				{Name: "qa", Type: models.StepMessage,
					Message: &models.MessageConfig{App: "py-task", Payload: "{}"}, Timeout: 30},
				{Name: "use", Type: models.StepCommand, Command: "echo got: ${{ steps.qa.outputs.answer }}"},
			}},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run5", 0, Options{
		CompletedSteps: map[string]map[string]bool{"j": {"qa": true}},
		RecoveredSteps: map[string]map[string]map[string]any{
			"j": {"qa": {"stdout": "answer-from-py", "exit_code": 0, "status": "success",
				"response": "answer-from-py", "outputs": nil}},
		},
		OnJobDone: func(_, _ string, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code == 0 {
		t.Fatalf("exit 0, want 1 (unresolved outputs.answer must fail the step)")
	}
	s := snap["use"]
	if s == nil || s["status"] != models.StatusFailure {
		t.Fatalf("step result = %v, want failure", s)
	}
	if stdout, _ := s["stdout"].(string); !strings.Contains(stdout, `message step "qa" produced no answer`) {
		t.Fatalf("step stdout = %q, want the plain-text no-answer engine error", stdout)
	}
}

// A message→message chain: the downstream message step's payload referencing the
// upstream plain-text step's missing answer fails the downstream step clearly,
// before any client call (recovered step state drives the upstream producer).
func TestMessageChainDownstreamMessageMissFailsStep(t *testing.T) {
	wf := &models.Workflow{
		Name: "chain",
		Jobs: map[string]*models.Job{
			"j": {Name: "j", Steps: []models.Step{
				{Name: "qa", Type: models.StepMessage,
					Message: &models.MessageConfig{App: "py-task", Payload: "{}"}, Timeout: 30},
				{Name: "follow", Type: models.StepMessage,
					Message: &models.MessageConfig{App: "py-task",
						Payload: `{"q":"${{ steps.qa.outputs.answer }}"}`}, Timeout: 30},
			}},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run6", 0, Options{
		CompletedSteps: map[string]map[string]bool{"j": {"qa": true}},
		RecoveredSteps: map[string]map[string]map[string]any{
			"j": {"qa": {"stdout": "answer-from-py", "exit_code": 0, "status": "success",
				"response": "answer-from-py", "outputs": nil}},
		},
		OnJobDone: func(_, _ string, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code != 1 {
		t.Fatalf("exit %d, want 1 (downstream payload miss must fail the step)", code)
	}
	s := snap["follow"]
	if s == nil || s["status"] != models.StatusFailure {
		t.Fatalf("step result = %v, want failure", s)
	}
	if stdout, _ := s["stdout"].(string); !strings.Contains(stdout, `message step "qa" produced no answer`) {
		t.Fatalf("step stdout = %q, want the plain-text no-answer engine error", stdout)
	}
}

// A failed message step produces no outputs either: a downstream step that
// survives it via continue-on-error fails with the did-not-succeed miss.
func TestFailedMessageStepOutputsMissFailsDownstream(t *testing.T) {
	wf := &models.Workflow{
		Name: "flaky-ask",
		Jobs: map[string]*models.Job{
			"j": {Name: "j", Steps: []models.Step{
				{Name: "qa", Type: models.StepMessage, ContinueOnError: true,
					Message: &models.MessageConfig{App: "py-task", Payload: "{}"}, Timeout: 30},
				{Name: "use", Type: models.StepCommand, Command: "echo got: ${{ steps.qa.outputs.answer }}"},
			}},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run7", 0, Options{
		CompletedSteps: map[string]map[string]bool{"j": {"qa": true}},
		RecoveredSteps: map[string]map[string]map[string]any{
			"j": {"qa": {"stdout": "", "exit_code": 1, "status": "failure", "response": "boom", "outputs": nil}},
		},
		OnJobDone: func(_, _ string, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code != 1 {
		t.Fatalf("exit %d, want 1 (outputs of a failed message step must miss)", code)
	}
	s := snap["use"]
	if s == nil || s["status"] != models.StatusFailure {
		t.Fatalf("step result = %v, want failure", s)
	}
	if stdout, _ := s["stdout"].(string); !strings.Contains(stdout, `message step "qa" did not succeed`) {
		t.Fatalf("step stdout = %q, want the did-not-succeed miss", stdout)
	}
}

// if: ${{ steps.qa.outputs.answer }} with the answer missing evaluates false
// (empty string), so the step is skipped — not gated open by a truthy literal.
func TestConditionMissingAnswerSkipsStep(t *testing.T) {
	wf := &models.Workflow{
		Name: "gated-ask",
		Jobs: map[string]*models.Job{
			"j": {Name: "j", Steps: []models.Step{
				{Name: "qa", Type: models.StepMessage,
					Message: &models.MessageConfig{App: "py-task", Payload: "{}"}, Timeout: 30},
				{Name: "gated", Type: models.StepCommand, Command: "echo hi",
					Condition: "${{ steps.qa.outputs.answer }}"},
			}},
		},
	}
	var snap map[string]map[string]any
	code, _ := RunWithContext(context.Background(), wf, nil, nil, "run8", 0, Options{
		CompletedSteps: map[string]map[string]bool{"j": {"qa": true}},
		RecoveredSteps: map[string]map[string]map[string]any{
			"j": {"qa": {"stdout": "answer-from-py", "exit_code": 0, "status": "success",
				"response": "answer-from-py", "outputs": nil}},
		},
		OnJobDone: func(_, _ string, _ string, steps map[string]map[string]any) { snap = steps },
	})
	if code != 0 {
		t.Fatalf("exit %d, want 0 (the gated step is skipped, not run against the nil client)", code)
	}
	if s := snap["gated"]; s == nil || s["status"] != models.StatusSkipped {
		t.Fatalf("step result = %v, want skipped (missing answer must gate the condition closed)", s)
	}
}

// A workflow_call output referencing a message step that never produced outputs
// fails the sub-workflow call with the miss named in the reason.
func TestSubWorkflowCallOutputsMissFailsCall(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sub-plain")
	if err := os.MkdirAll(subDir, 0700); err != nil {
		t.Fatal(err)
	}
	yaml := `
name: sub-plain
on:
  workflow_call:
    outputs:
      answer:
        value: "${{ jobs.j.steps.qa.outputs.answer }}"
jobs:
  j:
    steps:
      - name: qa
        if: "1 == 2"
        message:
          app: py-task
          payload: "{}"
`
	if err := os.WriteFile(filepath.Join(subDir, "workflow.yaml"), []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	code, outputs, _, reason := runSubWorkflow(context.Background(), nil, "sub-plain", nil, 1,
		Options{WorkflowBaseDir: dir})
	if code != 1 {
		t.Fatalf("exit %d, want 1 (a missed call output must fail the sub-workflow call)", code)
	}
	if len(outputs) != 0 {
		t.Fatalf("outputs = %v, want none on a failed call", outputs)
	}
	for _, want := range []string{`workflow_call output "answer"`, `message step "qa" did not succeed`} {
		if !strings.Contains(reason, want) {
			t.Errorf("reason %q does not mention %q", reason, want)
		}
	}
}
