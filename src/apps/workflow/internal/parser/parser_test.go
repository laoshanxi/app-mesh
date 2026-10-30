package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
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

func TestStrictExpressions(t *testing.T) {
	path := writeTmp(t, `
name: strict
strict_expressions: true
jobs:
  hello:
    steps:
      - name: greet
        command: "echo hi"
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if !wf.StrictExpressions {
		t.Error("strict_expressions: not parsed")
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

func TestNegativeTimeoutRejected(t *testing.T) {
	path := writeTmp(t, `
name: neg-timeout
jobs:
  a:
    steps:
      - name: s
        command: "true"
        timeout: -5
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("expected error")
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

// Strict decoding: a typoed field must be rejected at parse time, not silently
// dropped (a lost `needs:` would silently change execution order).
func TestUnknownFieldRejected(t *testing.T) {
	path := writeTmp(t, `
name: typo
jobs:
  build:
    neeeds: [other]
    steps:
      - name: greet
        command: "echo hello"
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("misspelled field 'neeeds' must fail strict parsing")
	}
}

func TestUnknownStepFieldRejected(t *testing.T) {
	path := writeTmp(t, `
name: typo2
jobs:
  build:
    steps:
      - name: greet
        command: "echo hello"
        retires: {max: 3}
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("misspelled field 'retires' must fail strict parsing")
	}
}

// Documented input schema: type must be string/number/boolean when given.
func TestInputTypeValidated(t *testing.T) {
	path := writeTmp(t, `
name: badtype
on:
  manual:
    inputs:
      env:
        type: integer
jobs:
  build:
    steps:
      - name: greet
        command: "echo hello"
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("invalid input type must be rejected")
	}
}

// An app_event trigger without app/events can never fire — reject at parse.
func TestAppEventRequiresAppAndEvents(t *testing.T) {
	path := writeTmp(t, `
name: badevent
on:
  app_event:
    app: ""
jobs:
  build:
    steps:
      - name: greet
        command: "echo hello"
`)
	if _, err := LoadWorkflow(path); err == nil {
		t.Fatal("app_event without app/events must be rejected")
	}
}

func TestStepEnvKeysRejected(t *testing.T) {
	path := writeTmp(t, `
name: env-keys
jobs:
  a:
    steps:
      - name: s
        command: "true"
        env:
          "FOO BAR": x
`)
	if _, err := LoadWorkflow(path); err == nil || !strings.Contains(err.Error(), "env key") {
		t.Fatalf("expected env key error, got %v", err)
	}
	path = writeTmp(t, `
name: secret-env-keys
jobs:
  a:
    steps:
      - name: s
        command: "true"
        secret_env:
          "A=B": y
`)
	if _, err := LoadWorkflow(path); err == nil || !strings.Contains(err.Error(), "secret_env key") {
		t.Fatalf("expected secret_env key error, got %v", err)
	}
}

// Job- and workflow-level env flow into the same process environment as step env,
// so their keys must pass the same identifier check.
func TestJobAndWorkflowEnvKeysRejected(t *testing.T) {
	path := writeTmp(t, `
name: job-env-keys
jobs:
  a:
    env:
      "JOB KEY": x
    steps:
      - name: s
        command: "true"
`)
	if _, err := LoadWorkflow(path); err == nil || !strings.Contains(err.Error(), `job "a" env key`) {
		t.Fatalf("expected job env key error, got %v", err)
	}
	path = writeTmp(t, `
name: wf-env-keys
env:
  "WF=KEY": x
jobs:
  a:
    steps:
      - name: s
        command: "true"
`)
	if _, err := LoadWorkflow(path); err == nil || !strings.Contains(err.Error(), "workflow env key") {
		t.Fatalf("expected workflow env key error, got %v", err)
	}
}

// `if:` fields accept full expressions inside ${{ }} (the runtime evaluator
// supports operators and status functions there); validation must accept them
// while still rejecting a typo'd operand reference.
func TestConditionExpressions(t *testing.T) {
	accepted := []string{
		`${{ steps.make.exit_code >= 0 }}`,
		`${{ steps.make.exit_code == 0 }}`,
		`${{ !failure() }}`,
		`${{ failure() || steps.make.exit_code == 0 }}`,
		`${{ jobs.dep.status == "success" && steps.make.stdout != "" }}`,
		`${{ true }}`,
	}
	for _, cond := range accepted {
		path := writeTmp(t, `
name: cond-ok
jobs:
  dep:
    steps:
      - name: s
        command: "true"
  main:
    needs: [dep]
    steps:
      - name: make
        command: "echo 1"
      - name: gated
        if: '`+cond+`'
        command: "echo ok"
`)
		if _, err := LoadWorkflow(path); err != nil {
			t.Errorf("condition %q rejected: %v", cond, err)
		}
	}
	rejected := []string{
		`${{ steps.typo.exit_code >= 0 }}`,
		`${{ failure() || jobs.nosuch.status == "success" }}`,
	}
	for _, cond := range rejected {
		path := writeTmp(t, `
name: cond-bad
jobs:
  main:
    steps:
      - name: make
        command: "echo 1"
      - name: gated
        if: '`+cond+`'
        command: "echo ok"
`)
		if _, err := LoadWorkflow(path); err == nil {
			t.Errorf("condition %q accepted with an unresolvable operand", cond)
		}
	}
	// Value fields stay strict: an operator expression in a command is not
	// supported by substitution and must still fail the load.
	path := writeTmp(t, `
name: cmd-bad
jobs:
  main:
    steps:
      - name: make
        command: "echo 1"
      - name: use
        command: "echo ${{ steps.make.exit_code >= 0 }}"
`)
	if _, err := LoadWorkflow(path); err == nil || !strings.Contains(err.Error(), "unresolved expression") {
		t.Fatalf("expected command expression error, got %v", err)
	}
}

func TestWorkflowDispatchAlias(t *testing.T) {
	path := writeTmp(t, `
name: dispatch-alias
on:
  workflow_dispatch:
    inputs:
      greet:
        type: string
        required: true
        default: world
jobs:
  build:
    steps:
      - name: greet
        command: echo hello
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if wf.On == nil || wf.On.Manual == nil {
		t.Fatalf("workflow_dispatch not normalized to manual: %+v", wf.On)
	}
	p, ok := wf.On.Manual.Inputs["greet"]
	if !ok || !p.Required {
		t.Fatalf("manual inputs not carried over: %+v", wf.On.Manual.Inputs)
	}
}

func TestManualWinsOverDispatchAlias(t *testing.T) {
	path := writeTmp(t, `
name: dispatch-conflict
on:
  manual:
    inputs:
      a:
        type: string
  workflow_dispatch:
    inputs:
      b:
        type: string
jobs:
  build:
    steps:
      - name: greet
        command: echo hello
`)
	wf, err := LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := wf.On.Manual.Inputs["a"]; !ok {
		t.Fatalf("explicit manual inputs lost: %+v", wf.On.Manual)
	}
	if _, ok := wf.On.Manual.Inputs["b"]; ok {
		t.Fatalf("workflow_dispatch inputs should not merge into explicit manual: %+v", wf.On.Manual)
	}
}

func TestUnknownTriggerFriendlyError(t *testing.T) {
	path := writeTmp(t, `
name: bad-trigger
on:
  workflow_dipatch:
jobs:
  build:
    steps:
      - name: greet
        command: echo hello
`)
	_, err := LoadWorkflow(path)
	if err == nil {
		t.Fatal("expected unknown trigger to fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "unsupported trigger") || strings.Contains(msg, "models.") {
		t.Fatalf("error not user-friendly: %v", msg)
	}
}

func TestOutputsRefOnlyOnWorkflowSteps(t *testing.T) {
	// outputs exists only on sub-workflow steps; any other reference cannot
	// resolve and must fail the load instead of substituting the literal.
	bad := []string{
		// command step
		`name: out-cmd
jobs:
  main:
    steps:
      - name: make
        command: "echo 1"
      - name: use
        command: "echo ${{ steps.make.outputs.tag }}"
`,
		// message step
		`name: out-msg
jobs:
  main:
    steps:
      - name: ask
        message:
          app: py-task
          payload: "print(1)"
      - name: use
        command: "echo ${{ steps.ask.outputs.answer }}"
`,
		// bare outputs without a key, on a workflow step
		`name: out-bare
jobs:
  main:
    steps:
      - name: call
        workflow: callee
        with: {}
      - name: use
        command: "echo ${{ steps.call.outputs }}"
`,
		// cross-job reference to a command step
		`name: out-cross
jobs:
  build:
    steps:
      - name: make
        command: "echo 1"
  use:
    needs: [build]
    steps:
      - name: use
        command: "echo ${{ jobs.build.steps.make.outputs.tag }}"
`,
	}
	for i, yaml := range bad {
		path := writeTmp(t, yaml)
		_, err := LoadWorkflow(path)
		if err == nil {
			t.Errorf("case %d: outputs reference accepted", i)
			continue
		}
		if !strings.Contains(err.Error(), "no outputs") && !strings.Contains(err.Error(), "requires a key") {
			t.Errorf("case %d: unexpected error: %v", i, err)
		}
	}

	// A sub-workflow step with a key stays valid.
	path := writeTmp(t, `
name: out-ok
jobs:
  main:
    steps:
      - name: call
        workflow: callee
        with: {}
      - name: use
        command: "echo ${{ steps.call.outputs.tag }}"
`)
	if _, err := LoadWorkflow(path); err != nil {
		t.Fatalf("workflow-step outputs reference must load: %v", err)
	}
}
