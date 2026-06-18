package llm

import (
	"context"
	"encoding/json"
	"strings"
)

// StubBackend is a deterministic, network-free Backend for tests and local
// development. It does not call any external service.
//
// Behavior:
//   - If the latest user message contains "use tool <name> <json-args>", it emits
//     a single ToolCall for that tool (once per distinct call id), letting the
//     agent loop exercise the tool path without a real model.
//   - Otherwise it echoes a final assistant answer.
//
// This lets the whole orchestration (sessions, agent loop, budget, tools) be
// unit-tested end to end with no API key and no network. Real providers are
// added as separate Backend implementations.
type StubBackend struct {
	calls int // number of Complete calls so far (drives one-shot tool emission)
}

// NewStubBackend returns a StubBackend.
func NewStubBackend() *StubBackend { return &StubBackend{} }

// Name implements Backend.
func (b *StubBackend) Name() string { return "stub" }

// Complete implements Backend.
func (b *StubBackend) Complete(ctx context.Context, messages []Message, tools []ToolSpec, stream StreamFunc) (*Completion, error) {
	b.calls++

	lastUser := lastUserContent(messages)

	// Emit a tool call only on the first turn, and only if asked and the tool exists.
	if b.calls == 1 {
		if name, args, ok := parseToolDirective(lastUser); ok && hasTool(tools, name) {
			return &Completion{
				Message: Message{
					Role: RoleAssistant,
					ToolCalls: []ToolCall{{
						ID:        "call_1",
						Name:      name,
						Arguments: args,
					}},
				},
				Usage: Usage{InputTokens: len(lastUser), OutputTokens: 0},
			}, nil
		}
	}

	answer := "stub: " + lastUser
	if stream != nil {
		for _, tok := range strings.Fields(answer) {
			stream(tok + " ")
		}
	}
	return &Completion{
		Message: Message{Role: RoleAssistant, Content: answer},
		Usage:   Usage{InputTokens: len(lastUser), OutputTokens: len(answer)},
	}, nil
}

func lastUserContent(messages []Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == RoleUser {
			return messages[i].Content
		}
	}
	return ""
}

// parseToolDirective parses "use tool <name> <json>" out of a user message.
func parseToolDirective(s string) (name string, args json.RawMessage, ok bool) {
	const prefix = "use tool "
	idx := strings.Index(s, prefix)
	if idx < 0 {
		return "", nil, false
	}
	rest := strings.TrimSpace(s[idx+len(prefix):])
	sp := strings.IndexByte(rest, ' ')
	if sp < 0 {
		return rest, json.RawMessage(`{}`), rest != ""
	}
	name = rest[:sp]
	raw := strings.TrimSpace(rest[sp+1:])
	if !json.Valid([]byte(raw)) {
		raw = "{}"
	}
	return name, json.RawMessage(raw), name != ""
}

func hasTool(tools []ToolSpec, name string) bool {
	for _, t := range tools {
		if t.Name == name {
			return true
		}
	}
	return false
}
