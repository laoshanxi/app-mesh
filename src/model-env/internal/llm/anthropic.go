package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// AnthropicBackend calls the Anthropic Messages API (POST /v1/messages) over raw
// HTTP. It supports tool use and SSE streaming. Credentials are read from the
// environment — never hardcoded (a tenant configures ANTHROPIC_API_KEY via the
// App's sec_env).
//
// Defaults: model claude-opus-4-8, API version 2023-06-01. Thinking is left
// unset (off) so conversation history is a plain text/tool round-trip with no
// thinking blocks to echo back.
type AnthropicBackend struct {
	apiKey     string
	baseURL    string
	model      string
	apiVersion string
	maxTokens  int
	http       *http.Client
}

// NewAnthropicBackend builds the backend from the environment. Returns an error
// (fail closed) if ANTHROPIC_API_KEY is unset.
func NewAnthropicBackend() (*AnthropicBackend, error) {
	key := os.Getenv("ANTHROPIC_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("anthropic backend requires ANTHROPIC_API_KEY")
	}
	model := os.Getenv("MODELENV_MODEL")
	if model == "" {
		model = "claude-opus-4-8"
	}
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	return &AnthropicBackend{
		apiKey:     key,
		baseURL:    strings.TrimRight(base, "/"),
		model:      model,
		apiVersion: "2023-06-01",
		maxTokens:  maxOutputTokens(8192),
		http:       &http.Client{Timeout: 10 * time.Minute},
	}, nil
}

// Name implements Backend.
func (b *AnthropicBackend) Name() string { return "anthropic:" + b.model }

// --- wire types ---

type antTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type antRequest struct {
	Model     string           `json:"model"`
	MaxTokens int              `json:"max_tokens"`
	System    string           `json:"system,omitempty"`
	Messages  []map[string]any `json:"messages"`
	Tools     []antTool        `json:"tools,omitempty"`
	Stream    bool             `json:"stream,omitempty"`
}

// buildRequest converts the provider-neutral history into a Messages API request.
// System messages are hoisted into the top-level `system` field; runs of tool
// results are merged into a single user message (the API requires alternating
// roles and all tool_results for one assistant turn in the following user turn).
func (b *AnthropicBackend) buildRequest(messages []Message, tools []ToolSpec, stream bool) antRequest {
	var system []string
	var msgs []map[string]any

	flushToolRun := func(blocks []map[string]any) {
		if len(blocks) > 0 {
			msgs = append(msgs, map[string]any{"role": "user", "content": blocks})
		}
	}

	var toolRun []map[string]any
	for _, m := range messages {
		if m.Role == RoleTool {
			toolRun = append(toolRun, map[string]any{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			})
			continue
		}
		// A non-tool message ends any pending run of tool results.
		flushToolRun(toolRun)
		toolRun = nil

		switch m.Role {
		case RoleSystem:
			system = append(system, m.Content)
		case RoleUser:
			msgs = append(msgs, map[string]any{
				"role":    "user",
				"content": []map[string]any{{"type": "text", "text": m.Content}},
			})
		case RoleAssistant:
			var blocks []map[string]any
			if m.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Name,
					"input": tc.Arguments,
				})
			}
			msgs = append(msgs, map[string]any{"role": "assistant", "content": blocks})
		}
	}
	flushToolRun(toolRun)

	req := antRequest{
		Model:     b.model,
		MaxTokens: b.maxTokens,
		System:    strings.Join(system, "\n\n"),
		Messages:  msgs,
		Stream:    stream,
	}
	for _, t := range tools {
		req.Tools = append(req.Tools, antTool{Name: t.Name, Description: t.Description, InputSchema: t.Parameters})
	}
	return req
}

func (b *AnthropicBackend) newHTTPRequest(ctx context.Context, body []byte) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", b.apiKey)
	httpReq.Header.Set("anthropic-version", b.apiVersion)
	return httpReq, nil
}

// Complete implements Backend.
func (b *AnthropicBackend) Complete(ctx context.Context, messages []Message, tools []ToolSpec, stream StreamFunc) (*Completion, error) {
	req := b.buildRequest(messages, tools, stream != nil)
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := b.newHTTPRequest(ctx, body)
	if err != nil {
		return nil, err
	}

	resp, err := b.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("anthropic API status %d: %s", resp.StatusCode, buf.String())
	}

	if stream != nil {
		return b.parseStream(resp, stream)
	}
	return b.parseResponse(resp)
}

type antContentBlock struct {
	Type  string          `json:"type"`
	Text  string          `json:"text"`
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Input json.RawMessage `json:"input"`
}

func (b *AnthropicBackend) parseResponse(resp *http.Response) (*Completion, error) {
	var out struct {
		Content    []antContentBlock `json:"content"`
		StopReason string            `json:"stop_reason"`
		Usage      struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}

	msg := Message{Role: RoleAssistant}
	var text strings.Builder
	for _, blk := range out.Content {
		switch blk.Type {
		case "text":
			text.WriteString(blk.Text)
		case "tool_use":
			msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: blk.ID, Name: blk.Name, Arguments: blk.Input})
		}
	}
	msg.Content = text.String()
	return &Completion{
		Message: msg,
		Usage:   Usage{InputTokens: out.Usage.InputTokens, OutputTokens: out.Usage.OutputTokens},
	}, nil
}

// parseStream consumes the SSE event stream, forwarding text deltas to stream and
// accumulating tool_use blocks (whose JSON arguments arrive as input_json_delta
// fragments) into the final Completion.
func (b *AnthropicBackend) parseStream(resp *http.Response, stream StreamFunc) (*Completion, error) {
	type pending struct {
		id, name string
		args     strings.Builder
	}
	blocks := map[int]*pending{}
	var text strings.Builder
	usage := Usage{}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		var ev struct {
			Type    string `json:"type"`
			Index   int    `json:"index"`
			Message *struct {
				Usage struct {
					InputTokens  int `json:"input_tokens"`
					OutputTokens int `json:"output_tokens"`
				} `json:"usage"`
			} `json:"message"`
			ContentBlock *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block"`
			Delta *struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				PartialJSON string `json:"partial_json"`
			} `json:"delta"`
			Usage *struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue // tolerate non-JSON keepalives
		}

		switch ev.Type {
		case "message_start":
			if ev.Message != nil {
				usage.InputTokens = ev.Message.Usage.InputTokens
			}
		case "content_block_start":
			if ev.ContentBlock != nil && ev.ContentBlock.Type == "tool_use" {
				blocks[ev.Index] = &pending{id: ev.ContentBlock.ID, name: ev.ContentBlock.Name}
			}
		case "content_block_delta":
			if ev.Delta == nil {
				continue
			}
			switch ev.Delta.Type {
			case "text_delta":
				text.WriteString(ev.Delta.Text)
				stream(ev.Delta.Text)
			case "input_json_delta":
				if p := blocks[ev.Index]; p != nil {
					p.args.WriteString(ev.Delta.PartialJSON)
				}
			}
		case "message_delta":
			if ev.Usage != nil {
				usage.OutputTokens = ev.Usage.OutputTokens
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read anthropic stream: %w", err)
	}

	msg := Message{Role: RoleAssistant, Content: text.String()}
	// Emit tool calls in content-block index order so they are deterministic.
	indices := make([]int, 0, len(blocks))
	for i := range blocks {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for _, i := range indices {
		p := blocks[i]
		args := p.args.String()
		if args == "" {
			args = "{}"
		}
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: p.id, Name: p.name, Arguments: json.RawMessage(args)})
	}
	return &Completion{Message: msg, Usage: usage}, nil
}
