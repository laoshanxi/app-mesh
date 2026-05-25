package expression

import (
	"testing"
)

func TestSubstitute_StepStdout(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "v1.2.3\n", 0, "success", "", nil)
	got := SubstituteForJob("${{ steps.build.stdout }}", ctx, "test")
	if got != "v1.2.3" {
		t.Errorf("got %q, want %q", got, "v1.2.3")
	}
}

func TestSubstitute_StepExitCode(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "test", "", 1, "failure", "", nil)
	if got := SubstituteForJob("${{ steps.build.exit_code }}", ctx, "test"); got != "0" {
		t.Errorf("build exit_code: got %q, want %q", got, "0")
	}
	if got := SubstituteForJob("${{ steps.test.exit_code }}", ctx, "test"); got != "1" {
		t.Errorf("test exit_code: got %q, want %q", got, "1")
	}
}

func TestSubstitute_WorkflowFields(t *testing.T) {
	ctx := NewContext()
	ctx.WfName = "test-wf"
	ctx.WfRunID = "run-001"
	if got := Substitute("${{ workflow.name }}", ctx); got != "test-wf" {
		t.Errorf("name: got %q", got)
	}
	if got := Substitute("${{ workflow.run_id }}", ctx); got != "run-001" {
		t.Errorf("run_id: got %q", got)
	}
}

func TestSubstitute_Inputs(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs["env"] = "staging"
	if got := Substitute("${{ inputs.env }}", ctx); got != "staging" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_Env(t *testing.T) {
	ctx := NewContext()
	ctx.Env["VER"] = "2.0"
	if got := Substitute("${{ env.VER }}", ctx); got != "2.0" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_Missing(t *testing.T) {
	ctx := NewContext()
	if got := SubstituteForJob("${{ steps.nope.stdout }}", ctx, "test"); got != "" {
		t.Errorf("missing step: got %q, want empty", got)
	}
}

func TestSubstitute_Multiple(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "x", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "y", 1, "failure", "", nil)
	got := SubstituteForJob("a=${{ steps.a.stdout }},b=${{ steps.b.status }}", ctx, "test")
	if got != "a=x,b=failure" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_Response(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "api", "", 0, "success", `{"ok":true}`, nil)
	if got := SubstituteForJob("${{ steps.api.response }}", ctx, "test"); got != `{"ok":true}` {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_Outputs(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "sub", "", 0, "success", "", map[string]string{"url": "https://prod"})
	if got := SubstituteForJob("${{ steps.sub.outputs.url }}", ctx, "test"); got != "https://prod" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_CrossJob(t *testing.T) {
	ctx := NewContext()
	steps := map[string]map[string]any{
		"compile": {"stdout": "done", "exit_code": 0, "status": "success"},
	}
	ctx.SetJobResult("build", steps, "success")
	if got := SubstituteForJob("${{ jobs.build.steps.compile.stdout }}", ctx, "test"); got != "done" {
		t.Errorf("got %q", got)
	}
}

func TestSubstituteForJob_IsolatesParallelJobs(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("job-a", "build", "a-out", 0, "success", "", nil)
	ctx.SetStepResult("job-b", "build", "b-out", 0, "success", "", nil)

	if got := SubstituteForJob("${{ steps.build.stdout }}", ctx, "job-a"); got != "a-out" {
		t.Errorf("job-a got %q, want a-out", got)
	}
	if got := SubstituteForJob("${{ steps.build.stdout }}", ctx, "job-b"); got != "b-out" {
		t.Errorf("job-b got %q, want b-out", got)
	}
}

func TestSubstitute_JobStatus(t *testing.T) {
	ctx := NewContext()
	ctx.SetJobStatusForJob("test", "failure")
	if got := SubstituteForJob("${{ job.status }}", ctx, "test"); got != "failure" {
		t.Errorf("got %q", got)
	}
}

func TestSubstituteForJob_JobStatus(t *testing.T) {
	ctx := NewContext()
	ctx.SetJobStatusForJob("deploy", "failure")
	if got := SubstituteForJob("${{ job.status }}", ctx, "deploy"); got != "failure" {
		t.Errorf("got %q", got)
	}
}

// --- EvalCondition ---

func TestEval_Empty(t *testing.T) {
	if !EvalConditionForJob("", NewContext(), "") {
		t.Error("empty should be true")
	}
}

func TestEval_Always(t *testing.T) {
	if !EvalConditionForJob("always()", NewContext(), "") {
		t.Error("always should be true")
	}
}

func TestEval_Success_AllPass(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 0, "success", "", nil)
	if !EvalConditionForJob("success()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Success_OneFails(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if EvalConditionForJob("success()", ctx, "test") {
		t.Error("should be false")
	}
}

func TestEval_Failure_OneFails(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if !EvalConditionForJob("failure()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_ExitCodeEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "", 0, "success", "", nil)
	if !EvalConditionForJob("steps.build.exit_code == 0", ctx, "test") {
		t.Error("should be true")
	}
	if EvalConditionForJob("steps.build.exit_code == 1", ctx, "test") {
		t.Error("should be false")
	}
}

func TestEval_ExitCodeNotEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "test", "", 1, "failure", "", nil)
	if !EvalConditionForJob("steps.test.exit_code != 0", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_StatusEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "", 0, "success", "", nil)
	if !EvalConditionForJob(`steps.build.status == "success"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_GreaterThan(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "test", "", 2, "failure", "", nil)
	if !EvalConditionForJob("steps.test.exit_code > 1", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_And(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if !EvalConditionForJob(`steps.a.status == "success" && steps.b.status == "failure"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Or(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 1, "failure", "", nil)
	if !EvalConditionForJob(`steps.a.status == "success" || steps.a.status == "failure"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Not(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	if !EvalConditionForJob("!failure()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEvalConditionForJob_IsolatesParallelJobs(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("job-a", "check", "", 0, "success", "", nil)
	ctx.SetStepResult("job-b", "check", "", 1, "failure", "", nil)

	if !EvalConditionForJob(`steps.check.status == "success"`, ctx, "job-a") {
		t.Error("job-a condition should be true")
	}
	if EvalConditionForJob(`steps.check.status == "success"`, ctx, "job-b") {
		t.Error("job-b condition should be false")
	}
}

func TestEvalConditionForJobWithStatus_UsesJobStatusFunctions(t *testing.T) {
	ctx := NewContext()
	if EvalConditionForJobWithStatus("success()", ctx, "deploy", func() bool { return false }, func() bool { return true }) {
		t.Error("success() should use supplied job status function")
	}
	if !EvalConditionForJobWithStatus("failure()", ctx, "deploy", func() bool { return false }, func() bool { return true }) {
		t.Error("failure() should use supplied job status function")
	}
}
