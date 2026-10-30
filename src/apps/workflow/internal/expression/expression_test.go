package expression

import (
	"encoding/json"
	"strings"
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
	// Unknown references stay literal (with a warning) so the corruption is
	// visible instead of silently substituting empty; strict mode errors.
	if got := SubstituteForJob("${{ steps.nope.stdout }}", ctx, "test"); got != "${{ steps.nope.stdout }}" {
		t.Errorf("missing step: got %q, want the literal reference kept", got)
	}
	ctx.Strict = true
	if _, err := SubstituteForJobChecked("${{ steps.nope.stdout }}", ctx, "test"); err == nil {
		t.Errorf("missing step in strict mode: want unresolved-expression error")
	}
}

func TestSubstituteChecked_StrictFails(t *testing.T) {
	ctx := NewContext()
	ctx.Strict = true
	got, err := SubstituteForJobChecked("echo ${{ inputz.name }}", ctx, "build")
	if err == nil || !strings.Contains(err.Error(), "${{ inputz.name }}") {
		t.Fatalf("err = %v, want unresolved-expression error", err)
	}
	if got != "" {
		t.Errorf("got %q, want empty on error", got)
	}
}

func TestSubstituteChecked_StrictResolvesNormally(t *testing.T) {
	ctx := NewContext()
	ctx.Strict = true
	ctx.Inputs["env"] = "staging"
	got, err := SubstituteForJobChecked("deploy ${{ inputs.env }}", ctx, "build")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != "deploy staging" {
		t.Errorf("got %q", got)
	}
}

func TestSubstituteChecked_LenientKeepsLiteral(t *testing.T) {
	ctx := NewContext()
	if got := SubstituteForJob("echo ${{ inputz.name }}", ctx, "build"); got != "echo ${{ inputz.name }}" {
		t.Errorf("got %q, want the literal expression embedded", got)
	}
	if _, err := SubstituteForJobChecked("echo ${{ inputz.name }}", ctx, "build"); err != nil {
		t.Errorf("lenient checked form must not error: %v", err)
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
	if EvalConditionForJobWithStatus("success()", ctx, "deploy", func() bool { return false },
		func() bool { return true }) {
		t.Error("success() should use supplied job status function")
	}
	if !EvalConditionForJobWithStatus("failure()", ctx, "deploy", func() bool { return false },
		func() bool { return true }) {
		t.Error("failure() should use supplied job status function")
	}
}

// Boolean literals and truthiness follow GitHub Actions semantics: an `if`
// that evaluates to false/0/"" must skip, not silently run.
func TestEvalConditionForJob_BooleanLiterals(t *testing.T) {
	ctx := NewContext()
	if EvalConditionForJob("false", ctx, "") {
		t.Error("`if: false` must be false")
	}
	if !EvalConditionForJob("true", ctx, "") {
		t.Error("`if: true` must be true")
	}
	if EvalConditionForJob("0", ctx, "") {
		t.Error("`if: 0` must be false")
	}
	ctx.Inputs = map[string]string{"enabled": "false", "flag": "true"}
	if EvalConditionForJob("${{ inputs.enabled }}", ctx, "") {
		t.Error("input resolved to 'false' must be falsy")
	}
	if !EvalConditionForJob("${{ inputs.flag }}", ctx, "") {
		t.Error("input resolved to 'true' must be truthy")
	}
}

func TestEvalConditionForJob_BooleanComparison(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"enabled": "true"}
	if !EvalConditionForJob("inputs.enabled == true", ctx, "") {
		t.Error("string 'true' should compare equal to boolean literal true")
	}
	if EvalConditionForJob("inputs.enabled == false", ctx, "") {
		t.Error("string 'true' should not equal boolean literal false")
	}
}

// A quoted literal 'success()' is an operand, not a status function — jobs with
// failed deps must still be skipped when the condition has no real status call.
func TestHasStatusFunction(t *testing.T) {
	if !HasStatusFunction("failure() || always()") {
		t.Error("bare status function should be detected")
	}
	if HasStatusFunction(`steps.x.stdout == 'success()'`) {
		t.Error("quoted literal must not count as a status function")
	}
	if HasStatusFunction("steps.x.stdout == 'ok'") {
		t.Error("no status function present")
	}
}

func TestSubstitute_ToJSON(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs["question"] = `He said "hi" \ and ${{ inputs.other }}`
	if got := Substitute(`{"input":${{ toJSON(inputs.question) }}}`, ctx); got != `{"input":"He said \"hi\" \\ and ${{ inputs.other }}"}` {
		t.Errorf("got %q", got)
	}
	// CJK and control characters stay valid JSON
	ctx.Inputs["q2"] = "报销\n流程"
	if got := Substitute(`{"input":${{ toJSON(inputs.q2) }}}`, ctx); got != "{\"input\":\"报销\\n流程\"}" {
		t.Errorf("got %q", got)
	}
}

func TestSubstitute_ToJSONUnresolved(t *testing.T) {
	ctx := NewContext()
	// Missing inputs resolve to "" by existing convention; toJSON must still emit valid JSON.
	if got := Substitute(`{"input":${{ toJSON(inputs.missing) }}}`, ctx); got != `{"input":""}` {
		t.Errorf("got %q", got)
	}
	// An unresolvable root keeps the literal text, matching plain substitution.
	if got := Substitute(`{"input":${{ toJSON(nosuchroot.x) }}}`, ctx); got != `{"input":${{ toJSON(nosuchroot.x) }}}` {
		t.Errorf("got %q", got)
	}
}

func TestSubstituteForCommand_SingleQuotedExpression(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "ask", "", 0, "success", `{"answer": "it's 42"}`, nil)
	cmd, bindings, err := SubstituteForCommand(`echo '${{ steps.ask.response }}' | jq .`, ctx, "j")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The quoted expression is substituted textually: the shell keeps one closed
	// quote around the value, and no $WF_E binding shadows it.
	want := `echo '{"answer": "it'\''s 42"}' | jq .`
	if cmd != want {
		t.Errorf("command: got %q, want %q", cmd, want)
	}
	if len(bindings) != 0 {
		t.Errorf("quoted expression must not create bindings, got %v", bindings)
	}
}

func TestSubstituteForCommand_MixedQuotedAndPlain(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "ver", "1.2.3", 0, "success", "", nil)
	cmd, bindings, err := SubstituteForCommand(`echo 'v=${{ steps.ver.stdout }}' plain=${{ steps.ver.stdout }}`, ctx, "j")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != `echo 'v=1.2.3' plain=$WF_E0` {
		t.Errorf("command: got %q", cmd)
	}
	if bindings["WF_E0"] != "1.2.3" {
		t.Errorf("plain expression binding missing: %v", bindings)
	}
}

func TestSubstituteForCommand_QuotedStrictUnresolved(t *testing.T) {
	ctx := NewContext()
	ctx.Strict = true
	if _, _, err := SubstituteForCommand(`echo '${{ steps.ghost.stdout }}'`, ctx, "j"); err == nil {
		t.Error("strict mode must fail on an unresolved quoted expression")
	}
}

func TestSubstituteForCommand_QuoteInsideDoubleQuotesUntouched(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "x", "VAL", 0, "success", "", nil)
	// "don't ${{ ... }}" — the apostrophe is inside double quotes, so the
	// expression is not single-quoted and keeps the environment mechanism.
	cmd, bindings, err := SubstituteForCommand(`echo "don't ${{ steps.x.stdout }}"`, ctx, "j")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cmd != `echo "don't $WF_E0"` || bindings["WF_E0"] != "VAL" {
		t.Errorf("got %q bindings %v", cmd, bindings)
	}
}

// A ${{ }}-wrapped condition must evaluate as its inner expression: operators
// inside the braces take effect instead of the unresolved text turning into a
// truthy literal.
func TestEvalCondition_WrappedExpression(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "make", "7", 0, "success", "", nil)
	cases := []struct {
		cond string
		want bool
	}{
		{`${{ steps.make.exit_code == 0 }}`, true},
		{`${{ steps.make.exit_code > 3 }}`, false},
		{`${{ !failure() }}`, true},
		{`${{ failure() || steps.make.exit_code == 0 }}`, true},
		{`${{ failure() || steps.make.exit_code > 3 }}`, false},
		{`steps.make.exit_code == 0`, true}, // bare form unchanged
		{`failure()`, false},
	}
	for _, c := range cases {
		if got := EvalConditionForJob(c.cond, ctx, "j"); got != c.want {
			t.Errorf("condition %q: got %v, want %v", c.cond, got, c.want)
		}
	}
}

// A JSON document payload substitutes with JSON string escaping, so quotes,
// backslashes, and newlines in a value cannot break the document; any other
// payload keeps the textual behavior.
func TestSubstituteMessagePayload_JSONEscaping(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{
		"code": `x = "hello" ` + "\\\n" + ` y`,
	}
	tmpl := `{"action":"send","input":"code: ${{ inputs.code }}","n":123}`
	out, err := SubstituteMessagePayload(tmpl, ctx, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var doc map[string]any
	if e := json.Unmarshal([]byte(out), &doc); e != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", e, out)
	}
	if doc["input"] != "code: "+`x = "hello" `+"\\"+"\n"+" y" {
		t.Errorf("value not preserved: %q", doc["input"])
	}
	if doc["n"] != float64(123) {
		t.Errorf("non-string literal altered: %v", doc["n"])
	}
}

// A non-JSON template (plain text or the bare toJSON pattern) substitutes
// textually, exactly as SubstituteForJobChecked.
func TestSubstituteMessagePayload_NonJSONFallsBack(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"q": "what"}
	out, err := SubstituteMessagePayload(`plain ${{ inputs.q }} text`, ctx, "")
	if err != nil || out != "plain what text" {
		t.Errorf("got %q err %v", out, err)
	}
}

// Strict mode must fail the substitution instead of embedding an unresolved
// expression into a JSON payload.
func TestSubstituteMessagePayload_StrictUnresolved(t *testing.T) {
	ctx := NewContext()
	ctx.Strict = true
	if _, err := SubstituteMessagePayload(`{"a":"${{ steps.nosuch.stdout }}"}`, ctx, ""); err == nil {
		t.Error("expected strict error for unresolved expression")
	}
}

// success()/failure() tolerate a continue-on-error failure (GitHub Actions
// conclusion semantics) while steps.<name>.status keeps the raw outcome.
func TestSuccessFailure_ToleratedFailure(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "flaky", "", 3, "failure", "", nil)
	ctx.MarkContinueOnError("j", "flaky")
	ctx.SetStepResult("j", "real", "", 0, "success", "", nil)
	if !EvalConditionForJob("success()", ctx, "j") {
		t.Error("success() must tolerate a continue-on-error failure")
	}
	if EvalConditionForJob("failure()", ctx, "j") {
		t.Error("failure() must not fire for a tolerated failure")
	}
	// The raw outcome stays visible to expressions.
	if !EvalConditionForJob("steps.flaky.status == 'failure'", ctx, "j") {
		t.Error("steps.flaky.status must keep the raw failure")
	}
	// An untolerated failure still fails the job.
	ctx.SetStepResult("j", "fatal", "", 1, "failure", "", nil)
	if EvalConditionForJob("success()", ctx, "j") {
		t.Error("success() must fail on an untolerated failure")
	}
}
