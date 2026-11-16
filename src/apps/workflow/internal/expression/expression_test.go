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

// evalOK evaluates a condition that must parse; a parse error fails the test.
func evalOK(t *testing.T, expr string, ctx *Context, jobName string) bool {
	t.Helper()
	met, err := EvalConditionForJob(expr, ctx, jobName)
	if err != nil {
		t.Fatalf("EvalConditionForJob(%q) returned error: %v", expr, err)
	}
	return met
}

func TestEval_Empty(t *testing.T) {
	if !evalOK(t, "", NewContext(), "") {
		t.Error("empty should be true")
	}
}

func TestEval_Always(t *testing.T) {
	if !evalOK(t, "always()", NewContext(), "") {
		t.Error("always should be true")
	}
}

func TestEval_Success_AllPass(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 0, "success", "", nil)
	if !evalOK(t, "success()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Success_OneFails(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if evalOK(t, "success()", ctx, "test") {
		t.Error("should be false")
	}
}

func TestEval_Failure_OneFails(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if !evalOK(t, "failure()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_ExitCodeEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "", 0, "success", "", nil)
	if !evalOK(t, "steps.build.exit_code == 0", ctx, "test") {
		t.Error("should be true")
	}
	if evalOK(t, "steps.build.exit_code == 1", ctx, "test") {
		t.Error("should be false")
	}
}

func TestEval_ExitCodeNotEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "test", "", 1, "failure", "", nil)
	if !evalOK(t, "steps.test.exit_code != 0", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_StatusEquals(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "build", "", 0, "success", "", nil)
	if !evalOK(t, `steps.build.status == "success"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_GreaterThan(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "test", "", 2, "failure", "", nil)
	if !evalOK(t, "steps.test.exit_code > 1", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_And(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	ctx.SetStepResult("test", "b", "", 1, "failure", "", nil)
	if !evalOK(t, `steps.a.status == "success" && steps.b.status == "failure"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Or(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 1, "failure", "", nil)
	if !evalOK(t, `steps.a.status == "success" || steps.a.status == "failure"`, ctx, "test") {
		t.Error("should be true")
	}
}

func TestEval_Not(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("test", "a", "", 0, "success", "", nil)
	if !evalOK(t, "!failure()", ctx, "test") {
		t.Error("should be true")
	}
}

func TestEvalConditionForJob_IsolatesParallelJobs(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("job-a", "check", "", 0, "success", "", nil)
	ctx.SetStepResult("job-b", "check", "", 1, "failure", "", nil)

	if !evalOK(t, `steps.check.status == "success"`, ctx, "job-a") {
		t.Error("job-a condition should be true")
	}
	if evalOK(t, `steps.check.status == "success"`, ctx, "job-b") {
		t.Error("job-b condition should be false")
	}
}

func TestEvalConditionForJobWithStatus_UsesJobStatusFunctions(t *testing.T) {
	ctx := NewContext()
	if ok, err := EvalConditionForJobWithStatus("success()", ctx, "deploy", func() bool { return false },
		func() bool { return true }); err != nil || ok {
		t.Error("success() should use supplied job status function")
	}
	if ok, err := EvalConditionForJobWithStatus("failure()", ctx, "deploy", func() bool { return false },
		func() bool { return true }); err != nil || !ok {
		t.Error("failure() should use supplied job status function")
	}
}

// Boolean literals and truthiness follow GitHub Actions semantics: an `if`
// that evaluates to false/0/"" must skip, not silently run.
func TestEvalConditionForJob_BooleanLiterals(t *testing.T) {
	ctx := NewContext()
	if evalOK(t, "false", ctx, "") {
		t.Error("`if: false` must be false")
	}
	if !evalOK(t, "true", ctx, "") {
		t.Error("`if: true` must be true")
	}
	if evalOK(t, "0", ctx, "") {
		t.Error("`if: 0` must be false")
	}
	ctx.Inputs = map[string]string{"enabled": "false", "flag": "true"}
	if evalOK(t, "${{ inputs.enabled }}", ctx, "") {
		t.Error("input resolved to 'false' must be falsy")
	}
	if !evalOK(t, "${{ inputs.flag }}", ctx, "") {
		t.Error("input resolved to 'true' must be truthy")
	}
}

func TestEvalConditionForJob_BooleanComparison(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"enabled": "true"}
	if !evalOK(t, "inputs.enabled == true", ctx, "") {
		t.Error("string 'true' should compare equal to boolean literal true")
	}
	if evalOK(t, "inputs.enabled == false", ctx, "") {
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
		if got := evalOK(t, c.cond, ctx, "j"); got != c.want {
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
	if !evalOK(t, "success()", ctx, "j") {
		t.Error("success() must tolerate a continue-on-error failure")
	}
	if evalOK(t, "failure()", ctx, "j") {
		t.Error("failure() must not fire for a tolerated failure")
	}
	// The raw outcome stays visible to expressions.
	if !evalOK(t, "steps.flaky.status == 'failure'", ctx, "j") {
		t.Error("steps.flaky.status must keep the raw failure")
	}
	// An untolerated failure still fails the job.
	ctx.SetStepResult("j", "fatal", "", 1, "failure", "", nil)
	if evalOK(t, "success()", ctx, "j") {
		t.Error("success() must fail on an untolerated failure")
	}
}

// plainMessageCtx builds a message step that completed with a plain-text reply (no outputs).
func plainMessageCtx(job, step string) *Context {
	ctx := NewContext()
	ctx.SetStepResult(job, step, "answer-from-py", 0, "success", "answer-from-py", nil)
	ctx.MarkMessageStep(job, step)
	return ctx
}

// An outputs.answer reference at a plain-text message step fails substitution clearly.
func TestSubstituteForCommand_MessageOutputsPlainTextFails(t *testing.T) {
	_, _, err := SubstituteForCommand(`echo got: ${{ steps.qa.outputs.answer }}`, plainMessageCtx("j", "qa"), "j")
	if err == nil || !strings.Contains(err.Error(), `unresolved expression ${{ steps.qa.outputs.answer }}`) ||
		!strings.Contains(err.Error(), `message step "qa" produced no answer`) ||
		!strings.Contains(err.Error(), "plain-text responders expose stdout") {
		t.Fatalf("err = %v, want the plain-text no-answer engine error", err)
	}
	// The cross-job shape fails the same way.
	_, _, err = SubstituteForCommand(`echo ${{ jobs.other.steps.qa.outputs.answer }}`, plainMessageCtx("other", "qa"), "j")
	if err == nil || !strings.Contains(err.Error(), `message step "qa" produced no answer`) {
		t.Fatalf("cross-job err = %v, want the plain-text no-answer engine error", err)
	}
	// toJSON(...) of the same reference too.
	_, _, err = SubstituteForCommand(`echo ${{ toJSON(steps.qa.outputs.answer) }}`, plainMessageCtx("j", "qa"), "j")
	if err == nil || !strings.Contains(err.Error(), `message step "qa" produced no answer`) {
		t.Fatalf("toJSON err = %v, want the plain-text no-answer engine error", err)
	}
	// The shell=false path goes through the same detection.
	if _, err := SubstituteCommandText(`echo got: ${{ steps.qa.outputs.answer }}`, plainMessageCtx("j", "qa"), "j"); err == nil {
		t.Fatal("SubstituteCommandText must fail on the same reference")
	}
}

// Envelope responders still substitute outputs.answer as before.
func TestSubstituteForCommand_MessageOutputsEnvelopeSubstitutes(t *testing.T) {
	ctx := NewContext()
	ctx.SetStepResult("j", "qa", "", 0, "success", `{"status":"ok","data":{"answer":"42"}}`,
		map[string]string{"answer": "42"})
	ctx.MarkMessageStep("j", "qa")
	cmd, bindings, err := SubstituteForCommand(`echo got: ${{ steps.qa.outputs.answer }}`, ctx, "j")
	if err != nil || cmd != "echo got: $WF_E0" || bindings["WF_E0"] != "42" {
		t.Fatalf("got %q bindings %v err %v, want the answer substituted", cmd, bindings, err)
	}
}

// Other unresolved references keep the lenient literal-kept behavior.
func TestSubstituteForCommand_OtherUnresolvedRefsStayLiteral(t *testing.T) {
	ctx := plainMessageCtx("j", "qa")
	ctx.SetStepResult("j", "sub", "", 0, "success", "", nil) // workflow sub-step, no outputs
	for _, cmd := range []string{
		`echo ${{ steps.ghost.outputs.answer }}`,
		`echo '${{ nosuchroot.x }}'`,
		`echo ${{ steps.qa.outputs.answer.here }}`,
		`echo ${{ steps.sub.outputs.missing }}`,
	} {
		got, _, err := SubstituteForCommand(cmd, ctx, "j")
		if err != nil || got != cmd {
			t.Errorf("%q: got %q err %v, want literal kept", cmd, got, err)
		}
	}
}

// The miss fires only for a completed message step; plain text stays reachable via stdout.
func TestSubstituteForCommand_MissOnlyForCompletedMessageSteps(t *testing.T) {
	failed := NewContext()
	failed.SetStepResult("j", "qa", "", 1, "failure", "boom", nil)
	failed.MarkMessageStep("j", "qa")
	got, _, err := SubstituteForCommand(`echo ${{ steps.qa.outputs.answer }}`, failed, "j")
	if err != nil || got != `echo ${{ steps.qa.outputs.answer }}` {
		t.Errorf("failed message step: got %q err %v, want literal kept", got, err)
	}
	if got, bindings, err := SubstituteForCommand(`echo ${{ steps.qa.stdout }}`, plainMessageCtx("j", "qa"), "j"); err != nil ||
		got != "echo $WF_E0" || bindings["WF_E0"] != "answer-from-py" {
		t.Errorf("plain-text stdout: got %q bindings %v err %v, want it substituted", got, bindings, err)
	}
}

// --- Parenthesized conditions ---

// A whole-condition parenthesis group must not turn the condition into an
// opaque truthy operand (the bug: `(${{ inputs.a }} == 'x')` was always false
// because the == inside the parentheses was never found at top level).
func TestEvalCondition_ParenthesizedComparison(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"a": "x"}
	if !evalOK(t, "(${{ inputs.a }} == 'x')", ctx, "") {
		t.Error("parenthesized comparison that holds must be true")
	}
	if evalOK(t, "(${{ inputs.a }} == 'y')", ctx, "") {
		t.Error("parenthesized comparison that fails must be false")
	}
	// Multiple wrapping layers unwrap recursively.
	if !evalOK(t, "(((${{ inputs.a }} == 'x')))", ctx, "") {
		t.Error("multi-layer wrapping must unwrap")
	}
}

// Deep but legitimate nesting must still evaluate.
func TestEvalCondition_DeepParenNesting(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"a": "1"}
	deep := strings.Repeat("(", 50) + "inputs.a == '1'" + strings.Repeat(")", 50)
	if !evalOK(t, deep, ctx, "") {
		t.Error("50-level nesting must evaluate")
	}
}

// Parentheses inside string literals are data, not grouping.
func TestEvalCondition_ParensInLiterals(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"smile": "(x)"}
	if !evalOK(t, "inputs.smile == '(x)'", ctx, "") {
		t.Error("parenthesis inside a quoted literal must not affect grouping")
	}
	if !evalOK(t, `'(((' == '((('`, ctx, "") {
		t.Error("unbalanced-looking parens inside quotes must stay literal")
	}
	if !evalOK(t, `(inputs.smile == '(x)') && (inputs.smile == "(x)")`, ctx, "") {
		t.Error("quoted parens inside groups must not unbalance the scan")
	}
}

// Grouping changes precedence: `a && (b || c)` is not `a && b || c`.
func TestEvalCondition_GroupingPrecedence(t *testing.T) {
	ctx := NewContext()
	ctx.Inputs = map[string]string{"a": "true", "b": "false", "c": "true"}
	if !evalOK(t, "inputs.a == 'true' && (inputs.b == 'true' || inputs.c == 'true')", ctx, "") {
		t.Error("a && (b || c) with a,c true must be true")
	}
	if evalOK(t, "(inputs.a == 'true' && inputs.b == 'true') || false", ctx, "") {
		t.Error("(a && b) || false with b false must be false")
	}
	// Grouped operands on both sides of a comparison unwrap before coercion.
	if !evalOK(t, "(inputs.a) == ('true')", ctx, "") {
		t.Error("parenthesized operands must unwrap before comparison")
	}
	if !evalOK(t, "!(inputs.b == 'true')", ctx, "") {
		t.Error("negation must apply to the grouped sub-expression")
	}
}

// Unbalanced parentheses are an author error: report it, never a silent false.
func TestEvalCondition_UnbalancedParens(t *testing.T) {
	ctx := NewContext()
	for _, expr := range []string{
		"(inputs.a == 'x'",
		"inputs.a == 'x')",
		"((inputs.a == 'x')",
		"inputs.a == 'x') && (inputs.b == 'y'",
	} {
		if _, err := EvalConditionForJob(expr, ctx, ""); err == nil {
			t.Errorf("condition %q must report unbalanced parentheses", expr)
		}
	}
	// Balanced conditions keep evaluating without error.
	if _, err := EvalConditionForJob("(inputs.a == 'x') || (inputs.b == 'y')", ctx, ""); err != nil {
		t.Errorf("balanced condition errored: %v", err)
	}
}

// Status-function detection sees through author grouping.
func TestHasStatusFunction_Grouped(t *testing.T) {
	if !HasStatusFunction("(success() || always())") {
		t.Error("grouped status functions must be detected")
	}
	if !HasStatusFunction("failure() && (steps.a.status == 'failure')") {
		t.Error("status function outside the group must be detected")
	}
	if HasStatusFunction(`(steps.x.stdout == 'success()')`) {
		t.Error("quoted status text inside a group must not count")
	}
}
