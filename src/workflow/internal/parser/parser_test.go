package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "wf-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestMinimal(t *testing.T) {
	path := writeTmp(t, `
name: minimal
jobs:
  hello:
    steps:
      - name: greet
        command: "echo hello"
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Name != "minimal" {
		t.Errorf("name: %q", wf.Name)
	}
	if len(wf.Jobs) != 1 {
		t.Fatalf("jobs: %d", len(wf.Jobs))
	}
	job := wf.Jobs["hello"]
	if len(job.Steps) != 1 {
		t.Fatalf("steps: %d", len(job.Steps))
	}
	if job.Steps[0].Type != models.StepCommand {
		t.Errorf("type: %v", job.Steps[0].Type)
	}
}

func TestOwnerPermission(t *testing.T) {
	path := writeTmp(t, `
name: sec
owner: admin
permission: 200
jobs:
  a:
    steps:
      - name: s
        command: echo
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Owner != "admin" || wf.Permission != 200 {
		t.Errorf("owner=%q perm=%d", wf.Owner, wf.Permission)
	}
}

func TestOnTrigger_YAMLBoolKey(t *testing.T) {
	path := writeTmp(t, `
name: trig
on:
  app_event:
    app: collector
    events: [EXIT]
    condition: "exit_code == 0"
  schedule:
    - cron: "0 2 * * *"
  manual:
    inputs:
      env:
        type: string
        default: staging
jobs:
  a:
    steps:
      - name: s
        command: echo
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.On == nil {
		t.Fatal("on is nil")
	}
	if wf.On.AppEvent == nil || wf.On.AppEvent.App != "collector" {
		t.Errorf("app_event: %+v", wf.On.AppEvent)
	}
	if len(wf.On.Schedule) != 1 || wf.On.Schedule[0].Cron != "0 2 * * *" {
		t.Errorf("schedule: %+v", wf.On.Schedule)
	}
	if wf.On.Manual == nil || len(wf.On.Manual.Inputs) != 1 {
		t.Errorf("manual: %+v", wf.On.Manual)
	}
}

func TestWorkflowCallTrigger(t *testing.T) {
	path := writeTmp(t, `
name: callable
on:
  workflow_call:
    inputs:
      region:
        type: string
        required: true
    outputs:
      url:
        value: "${{ jobs.deploy.steps.get-url.stdout }}"
jobs:
  deploy:
    steps:
      - name: get-url
        command: "echo https://prod"
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.On.WorkflowCall == nil {
		t.Fatal("workflow_call is nil")
	}
	if _, ok := wf.On.WorkflowCall.Inputs["region"]; !ok {
		t.Error("missing region input")
	}
	if _, ok := wf.On.WorkflowCall.Outputs["url"]; !ok {
		t.Error("missing url output")
	}
}

func TestConcurrency(t *testing.T) {
	path := writeTmp(t, `
name: conc
concurrency:
  group: deploy
  cancel-in-progress: true
jobs:
  a:
    steps:
      - name: s
        command: echo
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Concurrency == nil || wf.Concurrency.Group != "deploy" || !wf.Concurrency.CancelInProgress {
		t.Errorf("concurrency: %+v", wf.Concurrency)
	}
}

func TestJobNeedsAndCondition(t *testing.T) {
	path := writeTmp(t, `
name: dag
jobs:
  build:
    steps:
      - name: compile
        command: make
  deploy:
    needs: [build]
    if: "success()"
    steps:
      - name: go
        command: deploy.sh
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Jobs["deploy"].Needs) != 1 || wf.Jobs["deploy"].Needs[0] != "build" {
		t.Errorf("needs: %v", wf.Jobs["deploy"].Needs)
	}
	if wf.Jobs["deploy"].Condition != "success()" {
		t.Errorf("condition: %q", wf.Jobs["deploy"].Condition)
	}
}

func TestStepTypes(t *testing.T) {
	path := writeTmp(t, `
name: types
jobs:
  a:
    steps:
      - name: cmd
        command: "ls -la"
      - name: ap
        app: deployer
      - name: msg
        message:
          app: ml
          payload: '{"x":1}'
      - name: wf
        workflow: sub-wf
        with:
          region: us
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	steps := wf.Jobs["a"].Steps
	if steps[0].Type != models.StepCommand {
		t.Errorf("step 0: %v", steps[0].Type)
	}
	if steps[1].Type != models.StepApp || steps[1].App != "deployer" {
		t.Errorf("step 1: type=%v app=%q", steps[1].Type, steps[1].App)
	}
	if steps[2].Type != models.StepMessage || steps[2].Message.App != "ml" {
		t.Errorf("step 2: type=%v", steps[2].Type)
	}
	if steps[3].Type != models.StepWorkflow || steps[3].WorkflowRef != "sub-wf" {
		t.Errorf("step 3: type=%v ref=%q", steps[3].Type, steps[3].WorkflowRef)
	}
	if steps[3].With["region"] != "us" {
		t.Errorf("step 3 with: %v", steps[3].With)
	}
}

func TestRetry(t *testing.T) {
	path := writeTmp(t, `
name: retry
jobs:
  a:
    steps:
      - name: flaky
        command: curl
        retry:
          max: 3
          backoff: exponential
          interval: 5
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	r := wf.Jobs["a"].Steps[0].Retry
	if r == nil || r.Max != 3 || r.Backoff != "exponential" || r.Interval != 5 {
		t.Errorf("retry: %+v", r)
	}
}

func TestRetryDefaults(t *testing.T) {
	path := writeTmp(t, `
name: retry-defaults
jobs:
  a:
    steps:
      - name: flaky
        command: curl
        retry:
          max: 2
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	r := wf.Jobs["a"].Steps[0].Retry
	if r == nil || r.Max != 2 || r.Backoff != "fixed" || r.Interval != 10 {
		t.Errorf("retry defaults: %+v", r)
	}
}

func TestRejectsStepWithoutType(t *testing.T) {
	path := writeTmp(t, `
name: invalid
jobs:
  a:
    steps:
      - name: noop
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectsStepWithMultipleTypes(t *testing.T) {
	path := writeTmp(t, `
name: invalid
jobs:
  a:
    steps:
      - name: ambiguous
        command: echo
        app: deployer
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestRejectsDuplicateStepNamesInJob(t *testing.T) {
	path := writeTmp(t, `
name: invalid
jobs:
  a:
    steps:
      - name: duplicate
        command: echo one
    finally:
      - name: duplicate
        command: echo two
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestFinally(t *testing.T) {
	path := writeTmp(t, `
name: fin
jobs:
  a:
    steps:
      - name: main
        command: echo main
    finally:
      - name: cleanup
        command: echo cleanup
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(wf.Jobs["a"].Finally) != 1 {
		t.Errorf("finally: %d", len(wf.Jobs["a"].Finally))
	}
}

func TestFileNotFound(t *testing.T) {
	_, err := LoadWorkflow("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error")
	}
}

func TestFullExample(t *testing.T) {
	example := filepath.Join("..", "..", "examples", "data-pipeline.yaml")
	if _, err := os.Stat(example); os.IsNotExist(err) {
		t.Skip("example not found")
	}
	wf, err := LoadWorkflow(example)
	if err != nil {
		t.Fatal(err)
	}
	if wf.Name != "data-pipeline" {
		t.Errorf("name: %q", wf.Name)
	}
	if len(wf.Jobs) != 4 {
		t.Errorf("jobs: %d", len(wf.Jobs))
	}
}
