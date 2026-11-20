package executor

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
)

func TestInjectToken(t *testing.T) {
	cases := []struct {
		name, payload, token, want string
	}{
		{"object without token gets it", `{"a":1}`, "JWT", `{"a":1,"token":"JWT"}`}, // map marshal sorts keys
		{"author token wins", `{"token":"mine","a":1}`, "JWT", `{"token":"mine","a":1}`},
		{"json array untouched", `[1,2,3]`, "JWT", `[1,2,3]`},
		{"json scalar untouched", `"hi"`, "JWT", `"hi"`},
		{"json null untouched", `null`, "JWT", `null`},
		{"empty payload untouched", ``, "JWT", ``},
		{"invalid json untouched", `{bad`, "JWT", `{bad`},
		{"token is json-escaped", `{}`, `a"b`, `{"token":"a\"b"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := injectToken(c.payload, c.token); got != c.want {
				t.Errorf("injectToken(%q, %q) = %q, want %q", c.payload, c.token, got, c.want)
			}
		})
	}
}

func TestAppLevelError(t *testing.T) {
	cases := []struct {
		name, resp, wantMsg string
		wantErr             bool
	}{
		{"status error with message", `{"status":"error","message":"token required"}`, "token required", true},
		{"status error no message", `{"status":"error"}`, "app returned status=error", true},
		{"status ok", `{"status":"ok","data":{}}`, "", false},
		{"no status field", `{"answer":"hi"}`, "", false},
		{"plain text", `hello`, "", false},
		{"json array", `[1,2]`, "", false},
		{"empty", ``, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, isErr := appLevelError(c.resp)
			if isErr != c.wantErr || msg != c.wantMsg {
				t.Errorf("appLevelError(%q) = (%q,%v), want (%q,%v)", c.resp, msg, isErr, c.wantMsg, c.wantErr)
			}
		})
	}
}

func TestStepAppMetadata(t *testing.T) {
	ectx := expression.NewContext()
	ectx.WfName = "sub-workflow"
	ectx.WfRunID = "sub-sub-workflow-c4t9"

	// The daemon validates temporary App metadata against the capability claims
	// with exact equality. A sub-workflow runs under the top-level run capability,
	// so its Apps must carry the top-level identity — the sub-workflow context
	// identity would be rejected with 403.
	meta := stepAppMetadata("top-wf", "top-run-1", ectx, "proc-1")
	var m map[string]string
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("metadata is not valid JSON: %v", err)
	}
	if m["type"] != "workflow-step" || m["process_uuid"] != "proc-1" {
		t.Fatalf("unexpected base metadata: %v", m)
	}
	if m["workflow_id"] != "top-wf" || m["run_id"] != "top-run-1" {
		t.Fatalf("capability identity must override the sub-workflow context identity, got: %v", m)
	}

	// A top-level run has no inherited capability identity: the metadata falls
	// back to the run's own workflow and run identity.
	meta = stepAppMetadata("", "", ectx, "proc-1")
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatalf("metadata is not valid JSON: %v", err)
	}
	if m["workflow_id"] != "sub-workflow" || m["run_id"] != "sub-sub-workflow-c4t9" {
		t.Fatalf("empty capability identity must fall back to the context identity, got: %v", m)
	}
}

func TestResolveTargetNodeNoClusterNodes(t *testing.T) {
	// Without -cluster-nodes the error must name the missing configuration,
	// and the host key must still route directly.
	_, err := ResolveTargetNode(nil, "https://127.0.0.1:6058", map[string]string{"role": "test"}, nil, "bearer")
	if err == nil {
		t.Fatal("expected an error for a remote selector without cluster nodes")
	}
	for _, want := range []string{"-cluster-nodes", "no node matches label selector role=test"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err.Error(), want)
		}
	}

	// The direct host key routes without any cluster configuration.
	node, err := ResolveTargetNode(nil, "https://127.0.0.1:6058", map[string]string{"host": "node-a"}, nil, "bearer")
	if err != nil || node != "node-a" {
		t.Errorf("host key must route directly, got node=%q err=%v", node, err)
	}
}

// The outputs.answer miss fails at substitution, before any App runs.
func TestExecCommandMessageOutputsMissFailsBeforeShell(t *testing.T) {
	ectx := expression.NewContext()
	ectx.SetStepResult("j", "qa", "answer-from-py", 0, "success", "answer-from-py", nil)
	ectx.MarkMessageStep("j", "qa")
	e := &StepExecutor{Ctx: ectx, JobName: "j"}
	res := e.Execute(&models.Step{Name: "use", Type: models.StepCommand,
		Command: "echo got: ${{ steps.qa.outputs.answer }}"}, nil, nil)
	if res.Status != models.StatusFailure || res.ExitCode == nil || *res.ExitCode != 1 {
		t.Fatalf("result = %+v, want failure with exit 1", res)
	}
	if !strings.Contains(res.Response, `unresolved expression ${{ steps.qa.outputs.answer }}`) ||
		!strings.Contains(res.Response, `message step "qa" produced no answer`) {
		t.Fatalf("response = %q, want the plain-text no-answer engine error", res.Response)
	}
}

func TestAppLevelAnswer(t *testing.T) {
	cases := []struct {
		name, resp string
		want       map[string]string
	}{
		{"string answer", `{"status":"ok","data":{"answer":"42"}}`, map[string]string{"answer": "42"}},
		{"number answer", `{"status":"ok","data":{"answer":42}}`, map[string]string{"answer": "42"}},
		{"float answer", `{"data":{"answer":1.5}}`, map[string]string{"answer": "1.5"}},
		{"true answer", `{"data":{"answer":true}}`, map[string]string{"answer": "true"}},
		{"false answer is still a scalar", `{"data":{"answer":false}}`, map[string]string{"answer": "false"}},
		{"object answer is plain text", `{"data":{"answer":{"nested":1}}}`, nil},
		{"array answer is plain text", `{"data":{"answer":[1,2]}}`, nil},
		{"null answer is plain text", `{"data":{"answer":null}}`, nil},
		{"empty string answer is plain text", `{"data":{"answer":""}}`, nil},
		{"missing answer field", `{"status":"ok","data":{}}`, nil},
		{"missing data field", `{"status":"ok"}`, nil},
		{"plain text", `hello`, nil},
		{"json array", `[1,2]`, nil},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := appLevelAnswer(c.resp)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("appLevelAnswer(%q) = %v, want %v", c.resp, got, c.want)
			}
		})
	}
}

// An env value referencing a missing outputs.answer fails the step before any
// App runs, naming both the env key and the missing output.
func TestExecuteEnvMessageOutputsMissFails(t *testing.T) {
	ectx := expression.NewContext()
	ectx.SetStepResult("j", "qa", "answer-from-py", 0, "success", "answer-from-py", nil)
	ectx.MarkMessageStep("j", "qa")
	e := &StepExecutor{Ctx: ectx, JobName: "j"}
	res := e.Execute(&models.Step{Name: "use", Type: models.StepCommand, Command: "echo hi"},
		map[string]string{"ANSWER": "${{ steps.qa.outputs.answer }}"}, nil)
	if res.Status != models.StatusFailure {
		t.Fatalf("result = %+v, want failure", res)
	}
	for _, want := range []string{`env "ANSWER"`, `unresolved expression ${{ steps.qa.outputs.answer }}`,
		`message step "qa" produced no answer`} {
		if !strings.Contains(res.Response, want) {
			t.Errorf("response %q does not mention %q", res.Response, want)
		}
	}
}

// workdir and docker_image share the miss contract; both fail before any App runs.
func TestExecCommandWorkdirAndImageMissFail(t *testing.T) {
	ectx := expression.NewContext()
	ectx.SetStepResult("j", "qa", "answer-from-py", 0, "success", "answer-from-py", nil)
	ectx.MarkMessageStep("j", "qa")
	e := &StepExecutor{Ctx: ectx, JobName: "j"}

	res := e.execCommand(&models.Step{Name: "use", Type: models.StepCommand, Command: "echo hi",
		Workdir: "/w/${{ steps.qa.outputs.answer }}"}, nil, nil)
	if res.Status != models.StatusFailure || !strings.Contains(res.Response, "workdir") ||
		!strings.Contains(res.Response, `message step "qa" produced no answer`) {
		t.Fatalf("workdir result = %+v, want failure naming workdir and the miss", res)
	}

	res = e.execCommand(&models.Step{Name: "use2", Type: models.StepCommand, Command: "echo hi",
		DockerImage: "img:${{ steps.qa.outputs.answer }}"}, nil, nil)
	if res.Status != models.StatusFailure || !strings.Contains(res.Response, "docker_image") ||
		!strings.Contains(res.Response, `message step "qa" produced no answer`) {
		t.Fatalf("docker_image result = %+v, want failure naming docker_image and the miss", res)
	}
}

// execMessage drives the message→message chain: a downstream payload referencing
// the upstream plain-text step's missing answer fails before any client call.
func TestExecMessageDownstreamPayloadMissFails(t *testing.T) {
	ectx := expression.NewContext()
	ectx.SetStepResult("j", "qa", "answer-from-py", 0, "success", "answer-from-py", nil)
	ectx.MarkMessageStep("j", "qa")
	e := &StepExecutor{Ctx: ectx, JobName: "j"}

	res := e.execMessage(&models.Step{Name: "follow", Type: models.StepMessage,
		Message: &models.MessageConfig{App: "py-task", Payload: `{"q":"${{ steps.qa.outputs.answer }}"}`}})
	if res.Status != models.StatusFailure || !strings.Contains(res.Response, `message step "qa" produced no answer`) {
		t.Fatalf("json payload result = %+v, want failure with the plain-text no-answer error", res)
	}

	res = e.execMessage(&models.Step{Name: "follow2", Type: models.StepMessage,
		Message: &models.MessageConfig{App: "py-task", Payload: `ask: ${{ steps.qa.outputs.answer }}`}})
	if res.Status != models.StatusFailure || !strings.Contains(res.Response, `message step "qa" produced no answer`) {
		t.Fatalf("plain payload result = %+v, want failure with the plain-text no-answer error", res)
	}
}
