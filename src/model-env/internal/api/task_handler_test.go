package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/agent"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/budget"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/session"
)

// fakeTools advertises one tool ("echo") and records invocations — lets the
// dispatch tests exercise the full agent loop without a daemon.
type fakeTools struct{ invoked int }

func (f *fakeTools) Specs(ctx context.Context) ([]llm.ToolSpec, error) {
	return []llm.ToolSpec{{Name: "echo", Parameters: []byte(`{"type":"object"}`)}}, nil
}
func (f *fakeTools) Invoke(ctx context.Context, c llm.ToolCall) (string, error) {
	f.invoked++
	return `{"ok":true}`, nil
}

// newHandler builds a TaskHandler with the network seams faked: authFn trusts the
// token's subject claim, toolsFn returns the in-memory fake. Everything else
// (store, agent loop, budget) is real — this is the end-to-end smoke test path.
func newHandler(t *testing.T, ceiling budget.TurnLimits, ft *fakeTools) *TaskHandler {
	t.Helper()
	store, err := session.NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return &TaskHandler{
		store:   store,
		ledger:  budget.NewLedger(nil),
		ceiling: ceiling,
		backend: llm.NewStubBackend(),
		tenant:  "acme",
		admins:  map[string]bool{"admin": true},
		authFn:  func(token string) (string, error) { return usernameFromJWT(token), nil },
		toolsFn: func(token, sessionID string) (agent.ToolProvider, func(), error) { return ft, func() {}, nil },
	}
}

// fakeJWT builds a token whose payload base64-decodes to {"sub":user} so
// usernameFromJWT resolves it without a real signer.
func fakeJWT(user string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + user + `"}`))
	return "h." + payload + ".s"
}

func call(h *TaskHandler, req Request) Response {
	payload, _ := json.Marshal(req)
	return h.dispatch(string(payload))
}

func TestDispatchOpenSendClose(t *testing.T) {
	ft := &fakeTools{}
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, ft)
	tok := fakeJWT("alice")

	open := call(h, Request{Action: "session_open", Token: tok})
	if open.Status != "ok" {
		t.Fatalf("open: %+v", open)
	}
	sid := open.Data.(map[string]string)["session_id"]
	if sid == "" {
		t.Fatal("no session id")
	}

	// End-to-end: send → agent loop → stub backend → final answer.
	send := call(h, Request{Action: "session_send", Token: tok, SessionID: sid, Input: "hello"})
	if send.Status != "ok" {
		t.Fatalf("send: %+v", send)
	}
	data := send.Data.(map[string]interface{})
	if data["answer"] != "stub: hello" {
		t.Errorf("answer = %v", data["answer"])
	}

	if c := call(h, Request{Action: "session_close", Token: tok, SessionID: sid}); c.Status != "ok" {
		t.Errorf("close: %+v", c)
	}
}

// A worker handler rejects session_open (it owns one pre-assigned session) and
// refuses a session id other than the one it was assigned.
func TestWorkerRejectsForeignActions(t *testing.T) {
	ft := &fakeTools{}
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, ft)
	h.workerSessionID = "assigned"

	if r := call(h, Request{Action: "session_open", Token: fakeJWT("alice")}); r.Status != "error" {
		t.Errorf("worker open = %+v, want error", r)
	}
	if r := call(h, Request{Action: "session_send", Token: fakeJWT("alice"), SessionID: "other", Input: "hi"}); r.Status != "error" {
		t.Errorf("worker foreign-session send = %+v, want error", r)
	}
}

func TestDispatchToolLoop(t *testing.T) {
	ft := &fakeTools{}
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, ft)
	tok := fakeJWT("alice")
	sid := call(h, Request{Action: "session_open", Token: tok}).Data.(map[string]string)["session_id"]

	// "use tool echo {}" makes the stub emit a tool call; the loop should invoke
	// the fake tool, then the stub returns a final answer.
	send := call(h, Request{Action: "session_send", Token: tok, SessionID: sid, Input: "use tool echo {}"})
	if send.Status != "ok" {
		t.Fatalf("send: %+v", send)
	}
	if ft.invoked != 1 {
		t.Errorf("tool invoked %d times, want 1", ft.invoked)
	}
}

func TestDispatchAuthzCrossUserDenied(t *testing.T) {
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, &fakeTools{})
	sid := call(h, Request{Action: "session_open", Token: fakeJWT("alice")}).Data.(map[string]string)["session_id"]

	// Bob (non-admin) cannot send to Alice's session (L2 PDP).
	resp := call(h, Request{Action: "session_send", Token: fakeJWT("bob"), SessionID: sid, Input: "hi"})
	if resp.Status != "error" {
		t.Errorf("cross-user send = %+v, want error", resp)
	}

	// Admin can.
	admin := call(h, Request{Action: "session_send", Token: fakeJWT("admin"), SessionID: sid, Input: "hi"})
	if admin.Status != "ok" {
		t.Errorf("admin send = %+v, want ok", admin)
	}
}

func TestDispatchBudgetExceeded(t *testing.T) {
	h := newHandler(t, budget.TurnLimits{MaxIterations: 1}, &fakeTools{})
	tok := fakeJWT("alice")
	sid := call(h, Request{Action: "session_open", Token: tok}).Data.(map[string]string)["session_id"]

	// One iteration + a tool round → no room for a final answer → breach.
	resp := call(h, Request{Action: "session_send", Token: tok, SessionID: sid, Input: "use tool echo {}"})
	if resp.Status != "error" || resp.Message != "budget_exceeded" {
		t.Errorf("resp = %+v, want budget_exceeded", resp)
	}
}

// Streaming against the shared App is rejected (no clean per-session stdout there);
// streaming requires a worker App.
func TestDispatchStreamOnSharedAppRejected(t *testing.T) {
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, &fakeTools{})
	tok := fakeJWT("alice")
	sid := call(h, Request{Action: "session_open", Token: tok}).Data.(map[string]string)["session_id"]

	resp := call(h, Request{Action: "session_send", Token: tok, SessionID: sid, Input: "hi", Stream: true})
	if resp.Status != "error" {
		t.Errorf("shared-App stream send = %+v, want error (streaming needs a worker App)", resp)
	}
}

func TestDispatchAuthFailure(t *testing.T) {
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, &fakeTools{})
	h.authFn = func(token string) (string, error) { return "", errBadToken }

	resp := call(h, Request{Action: "session_open", Token: "bad"})
	if resp.Status != "error" {
		t.Errorf("resp = %+v, want auth error", resp)
	}
}

func TestDispatchUnknownAction(t *testing.T) {
	h := newHandler(t, budget.TurnLimits{MaxIterations: 8}, &fakeTools{})
	resp := call(h, Request{Action: "frobnicate", Token: fakeJWT("alice")})
	if resp.Status != "error" {
		t.Errorf("resp = %+v, want error", resp)
	}
}

var errBadToken = errTest("bad token")

type errTest string

func (e errTest) Error() string { return string(e) }
