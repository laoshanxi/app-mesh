package executor

import (
	"encoding/json"
	"testing"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
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
