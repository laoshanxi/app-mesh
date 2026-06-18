// Package agent implements the reason→act→observe (ReAct) loop.
//
// The loop runs inside the model-env App (see design doc): one user turn drives
// repeated model calls until the model returns a final answer with no tool
// calls, bounded by hard per-turn limits. Tool calls are dispatched to a
// ToolProvider (registered Apps via RunTask). The DAG never sees these
// iterations — to the workflow a turn is a single message step.
package agent

import (
	"context"
	"fmt"
	"sync"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/budget"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/session"
)

// ToolProvider advertises and invokes tools. tools.Catalog satisfies it.
type ToolProvider interface {
	Specs(ctx context.Context) ([]llm.ToolSpec, error)
	Invoke(ctx context.Context, call llm.ToolCall) (string, error)
}

// Result is the outcome of one turn.
type Result struct {
	Answer     string `json:"answer"`
	Iterations int    `json:"iterations"`
	TurnTokens int    `json:"turn_tokens"`
}

// RunTurn appends the user message to the session and runs the agent loop until
// a final answer or a hard limit. It assumes the caller holds sess.Lock().
//
// stream (optional, Scenario B) receives generated text as it is produced.
// On a budget breach it returns budget.ErrBudgetExceeded; the partial history is
// still recorded on the session so the conversation stays consistent.
func RunTurn(
	ctx context.Context,
	be llm.Backend,
	sess *session.Session,
	tools ToolProvider,
	limits budget.TurnLimits,
	stream llm.StreamFunc,
) (*Result, error) {
	sess.Messages = append(sess.Messages, llm.Message{Role: llm.RoleUser, Content: userInput(ctx)})

	specs, err := tools.Specs(ctx)
	if err != nil {
		return nil, fmt.Errorf("load tools: %w", err)
	}

	res := &Result{}
	for i := 0; i < max(limits.MaxIterations, 1); i++ {
		res.Iterations = i + 1

		comp, err := be.Complete(ctx, sess.Messages, specs, stream)
		if err != nil {
			return res, fmt.Errorf("model call: %w", err)
		}
		turnTokens := comp.Usage.InputTokens + comp.Usage.OutputTokens
		res.TurnTokens += turnTokens
		sess.CostTokens += turnTokens
		sess.Messages = append(sess.Messages, comp.Message)

		// Hard per-turn token ceiling.
		if limits.MaxTokens > 0 && res.TurnTokens > limits.MaxTokens {
			return res, budget.ErrBudgetExceeded
		}

		// No tool calls → final answer.
		if len(comp.Message.ToolCalls) == 0 {
			res.Answer = comp.Message.Content
			return res, nil
		}

		// Dispatch the turn's tool calls concurrently (the caller client is
		// concurrency-enabled), collecting results in call order. A failed call
		// becomes a structured error the model can react to.
		results := make([]llm.Message, len(comp.Message.ToolCalls))
		var wg sync.WaitGroup
		for i := range comp.Message.ToolCalls {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				call := comp.Message.ToolCalls[i]
				out, err := tools.Invoke(ctx, call)
				if err != nil {
					out = fmt.Sprintf(`{"error":%q}`, err.Error())
				}
				results[i] = llm.Message{
					Role:       llm.RoleTool,
					ToolCallID: call.ID,
					Name:       call.Name,
					Content:    out,
				}
			}(i)
		}
		wg.Wait()
		sess.Messages = append(sess.Messages, results...)
	}

	// Exhausted MaxIterations without a final answer.
	return res, budget.ErrBudgetExceeded
}

// inputKey is the context key carrying the user input for a turn. Passing it via
// context keeps RunTurn's signature stable as more per-turn options are added.
type inputKey struct{}

// WithInput attaches the user input for the turn to ctx.
func WithInput(ctx context.Context, input string) context.Context {
	return context.WithValue(ctx, inputKey{}, input)
}

func userInput(ctx context.Context) string {
	if v, ok := ctx.Value(inputKey{}).(string); ok {
		return v
	}
	return ""
}
