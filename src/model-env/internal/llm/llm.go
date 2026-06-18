// Package llm defines the model-backend contract used by the agent loop.
//
// The contract is intentionally provider-neutral: the agent loop, the session
// store, and the tool catalog all speak these types, and a concrete Backend
// (stub for tests/dev, real HTTP providers later) is selected at runtime. This
// keeps "which model/provider" a per-tenant configuration concern (one backend
// per tenant, see the design doc) without leaking into the orchestration code.
package llm

import (
	"context"
	"encoding/json"
)

// Role identifies who produced a Message.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
	RoleTool      = "tool" // a tool result fed back to the model
)

// Message is one entry in a conversation history.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content,omitempty"`

	// ToolCalls is set on an assistant Message that requests tool invocations.
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// ToolCallID and Name are set on a RoleTool Message, linking the result back
	// to the assistant's ToolCall it answers.
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"`
}

// ToolCall is the model's request to invoke a tool with JSON arguments.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ToolSpec is the function schema advertised to the model. It maps 1:1 to a
// registered App carrying metadata.tool (see tools.Catalog).
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"` // JSON Schema object
}

// Usage reports token consumption for one model call. The agent loop sums these
// into the session/tenant budget.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Completion is the result of one model call.
type Completion struct {
	Message Message `json:"message"` // the assistant turn (final content, or tool calls)
	Usage   Usage   `json:"usage"`
}

// StreamFunc receives generated text incrementally. It is nil when the caller
// does not want streaming (Scenario A / DAG). When non-nil (Scenario B), the
// backend should invoke it for each token/chunk as it is produced.
type StreamFunc func(chunk string)

// Backend is a single model provider. One Backend serves one tenant.
type Backend interface {
	// Name identifies the backend/model for logging and ledgers.
	Name() string

	// Complete runs one model call over the given history, advertising the given
	// tools. If stream is non-nil, generated text is also delivered to it as it is
	// produced. The returned Completion's Message is the assistant turn.
	Complete(ctx context.Context, messages []Message, tools []ToolSpec, stream StreamFunc) (*Completion, error)
}
