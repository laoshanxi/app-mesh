package agent

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/budget"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/session"
)

// fakeTools advertises one tool and records invocations. The mutex makes it safe
// for the agent loop's concurrent tool dispatch.
type fakeTools struct {
	mu      sync.Mutex
	invoked []string
}

func (f *fakeTools) Specs(ctx context.Context) ([]llm.ToolSpec, error) {
	return []llm.ToolSpec{{Name: "echo", Description: "echo", Parameters: []byte(`{"type":"object"}`)}}, nil
}

func (f *fakeTools) Invoke(ctx context.Context, call llm.ToolCall) (string, error) {
	f.mu.Lock()
	f.invoked = append(f.invoked, call.Name)
	f.mu.Unlock()
	return `{"ok":true}`, nil
}

// twoToolBackend emits two tool calls on its first turn, then a final answer —
// exercising the loop's concurrent multi-tool dispatch.
type twoToolBackend struct{ calls int }

func (b *twoToolBackend) Name() string { return "twotool" }
func (b *twoToolBackend) Complete(ctx context.Context, msgs []llm.Message, tools []llm.ToolSpec, stream llm.StreamFunc) (*llm.Completion, error) {
	b.calls++
	if b.calls == 1 {
		return &llm.Completion{Message: llm.Message{Role: llm.RoleAssistant, ToolCalls: []llm.ToolCall{
			{ID: "a", Name: "echo", Arguments: []byte(`{}`)},
			{ID: "b", Name: "echo", Arguments: []byte(`{}`)},
		}}, Usage: llm.Usage{InputTokens: 1}}, nil
	}
	return &llm.Completion{Message: llm.Message{Role: llm.RoleAssistant, Content: "done"}, Usage: llm.Usage{OutputTokens: 1}}, nil
}

func newSession() *session.Session { return &session.Session{ID: "s1", Owner: "alice", Tenant: "acme"} }

func TestRunTurnFinalAnswer(t *testing.T) {
	sess := newSession()
	ctx := WithInput(context.Background(), "hello")
	res, err := RunTurn(ctx, llm.NewStubBackend(), sess, &fakeTools{}, budget.TurnLimits{MaxIterations: 8}, nil)
	if err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	if res.Answer != "stub: hello" {
		t.Errorf("answer = %q", res.Answer)
	}
	if res.Iterations != 1 {
		t.Errorf("iterations = %d, want 1 (no tool call)", res.Iterations)
	}
	// history: user + assistant
	if len(sess.Messages) != 2 {
		t.Errorf("history len = %d, want 2", len(sess.Messages))
	}
}

func TestRunTurnToolCallThenAnswer(t *testing.T) {
	sess := newSession()
	ft := &fakeTools{}
	ctx := WithInput(context.Background(), "use tool echo {}")
	res, err := RunTurn(ctx, llm.NewStubBackend(), sess, ft, budget.TurnLimits{MaxIterations: 8}, nil)
	if err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	if len(ft.invoked) != 1 || ft.invoked[0] != "echo" {
		t.Errorf("tool invocations = %v, want [echo]", ft.invoked)
	}
	if res.Iterations != 2 {
		t.Errorf("iterations = %d, want 2 (tool round + answer)", res.Iterations)
	}
	// history: user + assistant(toolcall) + tool + assistant(answer)
	if len(sess.Messages) != 4 {
		t.Errorf("history len = %d, want 4: %+v", len(sess.Messages), sess.Messages)
	}
}

// Two tool calls in one turn are both dispatched, and their results are appended
// in call order (matched by ToolCallID) regardless of completion order.
func TestRunTurnParallelToolCalls(t *testing.T) {
	sess := newSession()
	ft := &fakeTools{}
	ctx := WithInput(context.Background(), "do two things")
	res, err := RunTurn(ctx, &twoToolBackend{}, sess, ft, budget.TurnLimits{MaxIterations: 8}, nil)
	if err != nil {
		t.Fatalf("RunTurn: %v", err)
	}
	if len(ft.invoked) != 2 {
		t.Errorf("invoked %d tools, want 2", len(ft.invoked))
	}
	// history: user + assistant(2 toolcalls) + tool(a) + tool(b) + assistant(answer).
	// Results must be appended in call order regardless of completion order.
	if len(sess.Messages) != 5 {
		t.Fatalf("history len = %d, want 5", len(sess.Messages))
	}
	if sess.Messages[2].ToolCallID != "a" || sess.Messages[3].ToolCallID != "b" {
		t.Errorf("tool result order = %q,%q want a,b", sess.Messages[2].ToolCallID, sess.Messages[3].ToolCallID)
	}
	if res.Answer != "done" {
		t.Errorf("answer = %q", res.Answer)
	}
}

func TestRunTurnBudgetExceeded(t *testing.T) {
	sess := newSession()
	ctx := WithInput(context.Background(), "use tool echo {}")
	// One iteration only: the tool round happens but no final answer fits → breach.
	_, err := RunTurn(ctx, llm.NewStubBackend(), sess, &fakeTools{}, budget.TurnLimits{MaxIterations: 1}, nil)
	if !errors.Is(err, budget.ErrBudgetExceeded) {
		t.Errorf("err = %v, want ErrBudgetExceeded", err)
	}
}

func TestRunTurnStreams(t *testing.T) {
	sess := newSession()
	var streamed string
	ctx := WithInput(context.Background(), "hello world")
	_, err := RunTurn(ctx, llm.NewStubBackend(), sess, &fakeTools{}, budget.TurnLimits{MaxIterations: 8},
		func(chunk string) { streamed += chunk })
	if err != nil {
		t.Fatal(err)
	}
	if streamed == "" {
		t.Error("expected streamed tokens, got none")
	}
}
