//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/dag"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/parser"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/trigger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
)

var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func writeTmpWorkflow(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "workflow.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// E2E-1: Full parse → DAG → expression pipeline for a diamond workflow.
func TestE2E_DiamondWorkflow_ParseAndDAG(t *testing.T) {
	path := writeTmpWorkflow(t, `
name: diamond
owner: admin
env:
  GLOBAL_VAR: "hello"

on:
  manual:
    inputs:
      target:
        type: string
        default: staging

concurrency:
  group: diamond
  cancel-in-progress: false

jobs:
  build:
    steps:
      - name: compile
        command: "make build"
        timeout: 600
        retry:
          max: 2
          backoff: exponential
          interval: 5
        env:
          BUILD_MODE: release

  test-unit:
    needs: [build]
    steps:
      - name: run-tests
        command: "make test"
        continue-on-error: true

  test-e2e:
    needs: [build]
    node_label:
      role: test-server
    steps:
      - name: run-e2e
        app: e2e-runner
        timeout: 300

  deploy:
    needs: [test-unit, test-e2e]
    if: "success()"
    steps:
      - name: deploy-prod
        command: "deploy.sh"
        env:
          TARGET: "${{ inputs.target }}"

      - name: verify
        command: "curl -f https://prod/health"
        if: "steps.deploy-prod.exit_code == 0"

      - name: rollback
        app: rollback-service
        if: "steps.deploy-prod.exit_code != 0"

    finally:
      - name: cleanup
        command: "rm -rf /tmp/workflow/${{ workflow.run_id }}"
      - name: notify
        message:
          app: slack-bot
          payload: '{"status": "${{ job.status }}"}'
`)

	wf, err := parser.LoadWorkflow(path)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	// Verify basic structure.
	if wf.Name != "diamond" {
		t.Errorf("name=%q", wf.Name)
	}
	if wf.Owner != "admin" {
		t.Errorf("owner=%q", wf.Owner)
	}
	if wf.Env["GLOBAL_VAR"] != "hello" {
		t.Errorf("env=%v", wf.Env)
	}
	if wf.Concurrency == nil || wf.Concurrency.Group != "diamond" {
		t.Errorf("concurrency=%v", wf.Concurrency)
	}

	// Verify trigger.
	if wf.On == nil || wf.On.Manual == nil || len(wf.On.Manual.Inputs) != 1 {
		t.Fatal("trigger parsing failed")
	}
	if wf.On.Manual.Inputs["target"].Default != "staging" {
		t.Errorf("input default=%v", wf.On.Manual.Inputs["target"].Default)
	}

	// Verify DAG topology.
	layers, err := dag.TopoSort(wf.Jobs)
	if err != nil {
		t.Fatalf("DAG error: %v", err)
	}
	if len(layers) != 3 {
		t.Fatalf("want 3 layers, got %d: %v", len(layers), layers)
	}
	if layers[0][0] != "build" {
		t.Errorf("layer 0: %v", layers[0])
	}
	layer1 := map[string]bool{}
	for _, n := range layers[1] {
		layer1[n] = true
	}
	if !layer1["test-unit"] || !layer1["test-e2e"] {
		t.Errorf("layer 1: %v", layers[1])
	}
	if layers[2][0] != "deploy" {
		t.Errorf("layer 2: %v", layers[2])
	}

	// Verify step types.
	deploy := wf.Jobs["deploy"]
	if deploy.Condition != "success()" {
		t.Errorf("deploy condition=%q", deploy.Condition)
	}
	if deploy.Steps[0].Type != models.StepCommand {
		t.Errorf("step 0 type=%v", deploy.Steps[0].Type)
	}
	if deploy.Steps[2].Type != models.StepApp {
		t.Errorf("step 2 type=%v", deploy.Steps[2].Type)
	}

	// Verify finally steps.
	if len(deploy.Finally) != 2 {
		t.Fatalf("finally steps=%d", len(deploy.Finally))
	}
	if !deploy.Finally[0].ContinueOnError {
		t.Error("finally default continue-on-error should be true")
	}
	if deploy.Finally[1].Type != models.StepMessage {
		t.Errorf("finally step 1 type=%v", deploy.Finally[1].Type)
	}

	// Verify retry.
	build := wf.Jobs["build"]
	if build.Steps[0].Retry == nil || build.Steps[0].Retry.Max != 2 {
		t.Errorf("retry=%v", build.Steps[0].Retry)
	}

	// Verify node label.
	if wf.Jobs["test-e2e"].NodeLabel["role"] != "test-server" {
		t.Errorf("node_label=%v", wf.Jobs["test-e2e"].NodeLabel)
	}
}

// E2E-2: Expression engine full pipeline — substitution + condition across steps and jobs.
func TestE2E_ExpressionFullPipeline(t *testing.T) {
	ctx := expression.NewContext()
	ctx.WfName = "e2e-test"
	ctx.WfRunID = "run-abc123"
	ctx.Inputs = map[string]string{"env": "prod", "version": "2.0"}
	ctx.Env = map[string]string{"REGION": "us-east"}

	// Step 1: build succeeds.
	ctx.SetStepResult("test", "build", "v2.0.1\n", 0, "success", "", nil)

	// Step 2: test fails.
	ctx.SetStepResult("test", "test", "FAIL: TestFoo", 1, "failure", "", nil)

	// Test substitution.
	cases := []struct {
		tmpl, want string
	}{
		{"${{ workflow.name }}", "e2e-test"},
		{"${{ workflow.run_id }}", "run-abc123"},
		{"${{ inputs.env }}", "prod"},
		{"${{ env.REGION }}", "us-east"},
		{"${{ steps.build.stdout }}", "v2.0.1"},
		{"${{ steps.build.exit_code }}", "0"},
		{"${{ steps.test.status }}", "failure"},
		{"ver=${{ steps.build.stdout }},env=${{ inputs.env }}", "ver=v2.0.1,env=prod"},
		{"${{ steps.missing.stdout }}", ""},
	}
	for _, tc := range cases {
		got := expression.SubstituteForJob(tc.tmpl, ctx, "test")
		if got != tc.want {
			t.Errorf("SubstituteForJob(%q) = %q, want %q", tc.tmpl, got, tc.want)
		}
	}

	// Test conditions.
	condCases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"always()", true},
		{"success()", false},
		{"failure()", true},
		{"steps.build.exit_code == 0", true},
		{"steps.test.exit_code != 0", true},
		{`steps.build.status == "success"`, true},
		{`steps.build.status == "success" && steps.test.status == "failure"`, true},
		{`steps.build.status == "failure" || steps.test.status == "failure"`, true},
		{`steps.build.status == "failure" || steps.test.status == "success"`, false},
		{"!success()", true},
		{"steps.test.exit_code > 0", true},
	}
	for _, tc := range condCases {
		got := expression.EvalConditionForJob(tc.expr, ctx, "test")
		if got != tc.want {
			t.Errorf("EvalConditionForJob(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}

	// Test cross-job context.
	ctx.SetJobResult("build", ctx.SnapshotJobSteps("test"), "success")
	got := expression.Substitute("${{ jobs.build.steps.build.stdout }}", ctx)
	if got != "v2.0.1" {
		t.Errorf("cross-job ref = %q", got)
	}
	got = expression.Substitute("${{ jobs.build.status }}", ctx)
	if got != "success" {
		t.Errorf("job status ref = %q", got)
	}
}

// E2E-3: Workflow call nesting — parse a sub-workflow with workflow_call trigger.
func TestE2E_WorkflowCallParsing(t *testing.T) {
	subPath := writeTmpWorkflow(t, `
name: deploy-template
on:
  workflow_call:
    inputs:
      region:
        type: string
        required: true
      version:
        type: string
    outputs:
      url:
        value: "${{ jobs.deploy.steps.get-url.stdout }}"
jobs:
  deploy:
    steps:
      - name: do-deploy
        command: "deploy.sh ${{ inputs.region }}"
      - name: get-url
        command: "echo https://prod/${{ inputs.region }}"
`)

	mainPath := writeTmpWorkflow(t, `
name: multi-region-deploy
jobs:
  deploy-us:
    steps:
      - name: deploy
        workflow: deploy-template
        with:
          region: us-east
          version: "2.0"
        timeout: 600
  deploy-eu:
    steps:
      - name: deploy
        workflow: deploy-template
        with:
          region: eu-west
`)

	sub, err := parser.LoadWorkflow(subPath)
	if err != nil {
		t.Fatalf("sub parse: %v", err)
	}
	if sub.On == nil || sub.On.WorkflowCall == nil {
		t.Fatal("missing workflow_call trigger")
	}
	if len(sub.On.WorkflowCall.Inputs) != 2 {
		t.Errorf("inputs: %d", len(sub.On.WorkflowCall.Inputs))
	}
	if !sub.On.WorkflowCall.Inputs["region"].Required {
		t.Error("region should be required")
	}
	if len(sub.On.WorkflowCall.Outputs) != 1 {
		t.Errorf("outputs: %d", len(sub.On.WorkflowCall.Outputs))
	}

	main, err := parser.LoadWorkflow(mainPath)
	if err != nil {
		t.Fatalf("main parse: %v", err)
	}
	if len(main.Jobs) != 2 {
		t.Fatalf("jobs: %d", len(main.Jobs))
	}

	deployUS := main.Jobs["deploy-us"]
	if deployUS.Steps[0].Type != models.StepWorkflow {
		t.Errorf("type=%v", deployUS.Steps[0].Type)
	}
	if deployUS.Steps[0].WorkflowRef != "deploy-template" {
		t.Errorf("ref=%q", deployUS.Steps[0].WorkflowRef)
	}
	if deployUS.Steps[0].With["region"] != "us-east" {
		t.Errorf("with=%v", deployUS.Steps[0].With)
	}

	// DAG: two independent jobs.
	layers, err := dag.TopoSort(main.Jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 1 || len(layers[0]) != 2 {
		t.Errorf("layers=%v (want 1 layer with 2 jobs)", layers)
	}
}

// E2E-4: Error handling — continue-on-error, retry, finally, conditional steps.
func TestE2E_ErrorHandlingModel(t *testing.T) {
	path := writeTmpWorkflow(t, `
name: error-handling
jobs:
  flaky-job:
    steps:
      - name: flaky-step
        command: "curl http://unstable"
        retry:
          max: 3
          backoff: exponential
          interval: 2
        continue-on-error: true

      - name: always-runs
        command: "echo still here"

      - name: only-if-flaky-failed
        command: "echo fallback"
        if: "steps.flaky-step.exit_code != 0"

    finally:
      - name: cleanup
        command: "rm -rf /tmp/test"
      - name: notify
        message:
          app: notifier
          payload: '{"job": "${{ job.status }}"}'
`)

	wf, err := parser.LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}

	job := wf.Jobs["flaky-job"]

	// Step 0: retry + continue.
	s0 := job.Steps[0]
	if s0.Retry == nil || s0.Retry.Max != 3 || s0.Retry.Backoff != "exponential" || s0.Retry.Interval != 2 {
		t.Errorf("step 0 retry=%v", s0.Retry)
	}
	if !s0.ContinueOnError {
		t.Error("step 0 continue-on-error should be true")
	}

	// Step 1: unconditional (defaults to stop on failure).
	if job.Steps[1].ContinueOnError {
		t.Error("step 1 continue-on-error should be false")
	}

	// Step 2: conditional.
	if job.Steps[2].Condition != "steps.flaky-step.exit_code != 0" {
		t.Errorf("step 2 condition=%q", job.Steps[2].Condition)
	}

	// Finally: both steps default to continue.
	for i, fs := range job.Finally {
		if !fs.ContinueOnError {
			t.Errorf("finally[%d] continue-on-error should be true", i)
		}
	}

	// Simulate: flaky-step fails, check condition evaluation.
	ctx := expression.NewContext()
	ctx.SetStepResult("test", "flaky-step", "", 1, "failure", "", nil)
	ctx.SetStepResult("test", "always-runs", "still here", 0, "success", "", nil)

	if !expression.EvalConditionForJob("steps.flaky-step.exit_code != 0", ctx, "test") {
		t.Error("conditional step should execute when flaky failed")
	}
	if expression.EvalConditionForJob("steps.flaky-step.exit_code == 0", ctx, "test") {
		t.Error("verify step should NOT execute when flaky failed")
	}
}

// E2E-5: Concurrency model parsing — matches GitHub Actions semantics.
func TestE2E_ConcurrencyModel(t *testing.T) {
	tests := []struct {
		name     string
		yaml     string
		group    string
		cancelIP bool
	}{
		{
			name:     "no concurrency",
			yaml:     "name: no-conc\njobs:\n  a:\n    steps:\n      - name: s\n        command: echo",
			group:    "",
			cancelIP: false,
		},
		{
			name:     "queue mode",
			yaml:     "name: queue\nconcurrency:\n  group: deploy\njobs:\n  a:\n    steps:\n      - name: s\n        command: echo",
			group:    "deploy",
			cancelIP: false,
		},
		{
			name:     "cancel in progress",
			yaml:     "name: cancel\nconcurrency:\n  group: deploy\n  cancel-in-progress: true\njobs:\n  a:\n    steps:\n      - name: s\n        command: echo",
			group:    "deploy",
			cancelIP: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTmpWorkflow(t, tc.yaml)
			wf, err := parser.LoadWorkflow(path)
			if err != nil {
				t.Fatal(err)
			}
			if tc.group == "" {
				if wf.Concurrency != nil {
					t.Error("expected nil concurrency")
				}
				return
			}
			if wf.Concurrency == nil {
				t.Fatal("expected non-nil concurrency")
			}
			if wf.Concurrency.Group != tc.group {
				t.Errorf("group=%q", wf.Concurrency.Group)
			}
			if wf.Concurrency.CancelInProgress != tc.cancelIP {
				t.Errorf("cancel=%v", wf.Concurrency.CancelInProgress)
			}
		})
	}
}

// E2E-6: All four step types parse correctly from a single YAML.
func TestE2E_AllFourStepTypes(t *testing.T) {
	path := writeTmpWorkflow(t, `
name: all-types
jobs:
  mixed:
    steps:
      - name: cmd-step
        command: "echo hello"
        workdir: /tmp
        timeout: 30
        docker_image: alpine:3.19

      - name: app-step
        app: my-service
        timeout: 60

      - name: msg-step
        message:
          app: ml-model
          payload: '{"x": 1}'
        timeout: 120

      - name: wf-step
        workflow: sub-pipeline
        with:
          region: us
          count: "5"
        timeout: 600
`)

	wf, err := parser.LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}

	steps := wf.Jobs["mixed"].Steps
	if len(steps) != 4 {
		t.Fatalf("steps=%d", len(steps))
	}

	// Command step.
	s := steps[0]
	if s.Type != models.StepCommand || s.Command != "echo hello" || s.Workdir != "/tmp" || s.Timeout != 30 || s.DockerImage != "alpine:3.19" {
		t.Errorf("cmd step: type=%v cmd=%q workdir=%q timeout=%d docker=%q", s.Type, s.Command, s.Workdir, s.Timeout, s.DockerImage)
	}

	// App step.
	s = steps[1]
	if s.Type != models.StepApp || s.App != "my-service" || s.Timeout != 60 {
		t.Errorf("app step: type=%v app=%q timeout=%d", s.Type, s.App, s.Timeout)
	}

	// Message step.
	s = steps[2]
	if s.Type != models.StepMessage || s.Message == nil || s.Message.App != "ml-model" || s.Message.Payload != `{"x": 1}` {
		t.Errorf("msg step: type=%v msg=%+v", s.Type, s.Message)
	}

	// Workflow step.
	s = steps[3]
	if s.Type != models.StepWorkflow || s.WorkflowRef != "sub-pipeline" || s.With["region"] != "us" || s.With["count"] != "5" {
		t.Errorf("wf step: type=%v ref=%q with=%v", s.Type, s.WorkflowRef, s.With)
	}
}

// E2E-7: DAG cycle detection with meaningful error.
func TestE2E_DAGCycleDetection(t *testing.T) {
	path := writeTmpWorkflow(t, `
name: cycle
jobs:
  a:
    needs: [c]
    steps:
      - name: s
        command: echo
  b:
    needs: [a]
    steps:
      - name: s
        command: echo
  c:
    needs: [b]
    steps:
      - name: s
        command: echo
`)

	wf, err := parser.LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = dag.TopoSort(wf.Jobs)
	if err == nil {
		t.Fatal("expected cycle error")
	}
	if !contains(err.Error(), "cyclic") {
		t.Errorf("error=%v", err)
	}
}

// E2E-8: Environment variable precedence (step > job > global).
func TestE2E_EnvPrecedence(t *testing.T) {
	path := writeTmpWorkflow(t, `
name: env-test
env:
  SHARED: global
  ONLY_GLOBAL: g
jobs:
  a:
    env:
      SHARED: job
      ONLY_JOB: j
    steps:
      - name: s
        command: "echo $SHARED"
        env:
          SHARED: step
          ONLY_STEP: s
`)

	wf, err := parser.LoadWorkflow(path)
	if err != nil {
		t.Fatal(err)
	}

	if wf.Env["SHARED"] != "global" {
		t.Errorf("global SHARED=%q", wf.Env["SHARED"])
	}

	job := wf.Jobs["a"]
	if job.Env["SHARED"] != "job" {
		t.Errorf("job SHARED=%q", job.Env["SHARED"])
	}

	step := job.Steps[0]
	if step.Env["SHARED"] != "step" {
		t.Errorf("step SHARED=%q", step.Env["SHARED"])
	}

	// Simulate merge precedence.
	ctx := expression.NewContext()
	ctx.Env = wf.Env

	merged := map[string]string{}
	for k, v := range wf.Env {
		merged[k] = v
	}
	for k, v := range job.Env {
		merged[k] = v
	}
	for k, v := range step.Env {
		merged[k] = v
	}

	if merged["SHARED"] != "step" {
		t.Errorf("merged SHARED=%q (step should win)", merged["SHARED"])
	}
	if merged["ONLY_GLOBAL"] != "g" {
		t.Errorf("merged ONLY_GLOBAL=%q", merged["ONLY_GLOBAL"])
	}
	if merged["ONLY_JOB"] != "j" {
		t.Errorf("merged ONLY_JOB=%q", merged["ONLY_JOB"])
	}
	if merged["ONLY_STEP"] != "s" {
		t.Errorf("merged ONLY_STEP=%q", merged["ONLY_STEP"])
	}
}

// E2E-9: Full example YAML from examples/ directory.
func TestE2E_FullExamplePipeline(t *testing.T) {
	example := filepath.Join("..", "..", "examples", "data-pipeline.yaml")
	if _, err := os.Stat(example); os.IsNotExist(err) {
		t.Skip("example file not found")
	}

	wf, err := parser.LoadWorkflow(example)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if wf.Name != "data-pipeline" {
		t.Errorf("name=%q", wf.Name)
	}
	if len(wf.Jobs) != 4 {
		t.Errorf("jobs=%d", len(wf.Jobs))
	}

	// Verify full DAG is valid.
	layers, err := dag.TopoSort(wf.Jobs)
	if err != nil {
		t.Fatalf("DAG: %v", err)
	}
	if len(layers) != 3 {
		t.Errorf("layers=%d", len(layers))
	}

	// Verify triggers parsed.
	if wf.On == nil {
		t.Fatal("triggers nil")
	}
	if wf.On.AppEvent == nil || wf.On.AppEvent.App != "data-collector" {
		t.Errorf("app_event=%+v", wf.On.AppEvent)
	}
	if len(wf.On.Schedule) != 1 || wf.On.Schedule[0].Cron != "0 2 * * *" {
		t.Errorf("schedule=%+v", wf.On.Schedule)
	}

	// Verify deploy job has finally block.
	deploy := wf.Jobs["deploy"]
	if len(deploy.Finally) != 2 {
		t.Errorf("deploy finally=%d", len(deploy.Finally))
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// E2E-10: Workdir full run lifecycle — add, update, complete, list, read logs.
func TestE2E_WorkdirRunLifecycle(t *testing.T) {
	dir := t.TempDir()
	wdir := workdir.NewManager(dir, 5)
	wdir.EnsureWorkflowDir("pipe")

	wdir.AddRunToIndex("pipe", workdir.RunIndex{
		RunID: "r1", Workflow: "pipe", Status: "running",
		Source: "manual", StartedAt: "2026-01-01T00:00:00Z",
		Inputs: map[string]string{"env": "prod"},
	})
	wdir.WriteStepLog("pipe", "r1", "build", "compile", "gcc ok\n")
	wdir.UpdateRunInIndex("pipe", "r1", "success", 12.5)

	runs := wdir.ListRuns("pipe")
	if len(runs) != 1 || runs[0].Status != "success" || runs[0].Duration != 12.5 {
		t.Fatalf("runs: %+v", runs)
	}
	if runs[0].Inputs["env"] != "prod" {
		t.Errorf("inputs not persisted: %v", runs[0].Inputs)
	}

	log := wdir.ReadStepLog("pipe", "r1", "build", "compile")
	if log != "gcc ok\n" {
		t.Errorf("step log=%q", log)
	}
	if wdir.ReadStepLog("pipe", "r1", "build", "missing") != "" {
		t.Error("missing step log should return empty")
	}
}

// E2E-11: Checkpoint preserved after completion — run_detail works for finished runs.
func TestE2E_CheckpointPreservedForDetail(t *testing.T) {
	dir := t.TempDir()
	wdir := workdir.NewManager(dir, 10)
	cp := trigger.NewCheckpoint(wdir)

	cp.SaveRunning("wf", "r1", "manual", map[string]string{"x": "1"}, []string{"build", "test"})
	cp.UpdateJob("wf", "r1", "build", "success", "node-1", map[string]trigger.StepState{
		"compile": {Stdout: "ok", ExitCode: 0, Status: "success"},
	})
	cp.UpdateJob("wf", "r1", "test", "failure", "node-2", map[string]trigger.StepState{
		"unit": {Stdout: "FAIL", ExitCode: 1, Status: "failure"},
	})
	cp.MarkComplete("wf", "r1", "failure")

	rec := cp.GetRunRecord("wf", "r1")
	if rec == nil {
		t.Fatal("checkpoint should be preserved after MarkComplete")
	}
	if rec.Status != "failure" {
		t.Errorf("status=%q", rec.Status)
	}
	if rec.Jobs["build"].Node != "node-1" {
		t.Errorf("build node=%q", rec.Jobs["build"].Node)
	}
	if rec.Jobs["test"].Steps["unit"].ExitCode != 1 {
		t.Errorf("test.unit.exit_code=%d", rec.Jobs["test"].Steps["unit"].ExitCode)
	}

	stale := cp.RecoverStale(dir)
	if len(stale) != 0 {
		t.Errorf("completed run should not be recovered: %d stale", len(stale))
	}
}

// E2E-12: Recovery includes failed jobs — prevents re-execution.
func TestE2E_RecoveryIncludesFailedJobs(t *testing.T) {
	dir := t.TempDir()
	wdir := workdir.NewManager(dir, 10)
	cp := trigger.NewCheckpoint(wdir)

	cp.SaveRunning("wf", "r2", "event", nil, []string{"a", "b", "c"})
	cp.UpdateJob("wf", "r2", "a", "success", "", nil)
	cp.UpdateJob("wf", "r2", "b", "failure", "", nil)

	completed := cp.CompletedJobs("wf", "r2")
	if len(completed) != 2 {
		t.Fatalf("want 2 completed (success+failure), got %d", len(completed))
	}
	if completed["a"] != "success" || completed["b"] != "failure" {
		t.Errorf("completed: %v", completed)
	}
	if _, ok := completed["c"]; ok {
		t.Error("pending job c should not be in completed")
	}
}

// E2E-13: Workdir retention protects running/pending runs.
func TestE2E_RetentionProtectsActiveRuns(t *testing.T) {
	dir := t.TempDir()
	wdir := workdir.NewManager(dir, 2)
	wdir.EnsureWorkflowDir("wf")

	for i := 0; i < 5; i++ {
		status := "success"
		if i == 3 {
			status = "running"
		}
		if i == 4 {
			status = "pending"
		}
		wdir.AddRunToIndex("wf", workdir.RunIndex{
			RunID: fmt.Sprintf("r%d", i), Workflow: "wf", Status: status,
			Source: "manual", StartedAt: fmt.Sprintf("2026-01-0%dT00:00:00Z", i+1),
		})
	}
	wdir.CleanOldRuns("wf")

	runs := wdir.ListRuns("wf")
	statuses := map[string]bool{}
	for _, r := range runs {
		statuses[r.Status] = true
	}
	if !statuses["running"] {
		t.Error("running run should be protected")
	}
	if !statuses["pending"] {
		t.Error("pending run should be protected")
	}
}

// E2E-15: safeID validation rejects path traversal characters.
func TestE2E_SafeIDValidation(t *testing.T) {
	bad := []string{"../etc", "foo/bar", "a b", "test;rm", "a\x00b"}
	for _, id := range bad {
		if safeID.MatchString(id) {
			t.Errorf("safeID should reject %q", id)
		}
	}
	good := []string{"my-workflow", "run_123", "abc", "A-B_C-0"}
	for _, id := range good {
		if !safeID.MatchString(id) {
			t.Errorf("safeID should accept %q", id)
		}
	}
}
