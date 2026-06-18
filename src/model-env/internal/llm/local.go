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

// LocalBackend targets a locally-deployed inference server through the
// OpenAI-compatible Chat Completions API (POST /v1/chat/completions). This is
// the de-facto standard exposed by vLLM, Ollama (its OpenAI-compat endpoint),
// Text Generation Inference, llama.cpp's server, and LM Studio — so one backend
// covers self-hosted models without a provider-specific client.
//
// In the App Mesh model, the inference server is an ordinary managed App
// (process lifecycle + GPU pinning via env; see the design doc); this backend is
// the model-env client that points at its endpoint. Config is from the
// environment (no hardcoded URL/key):
//
//	MODELENV_LOCAL_BASE_URL  — e.g. http://127.0.0.1:8000/v1  (required)
//	MODELENV_MODEL           — model name the server expects (required)
//	MODELENV_LOCAL_API_KEY   — bearer token, if the server requires one (optional)
type LocalBackend struct {
	baseURL   string
	model     string
	apiKey    string
	maxTokens int
	http      *http.Client
}

// NewLocalBackend builds the backend from the environment. Fails closed if the
// base URL or model is unset.
func NewLocalBackend() (*LocalBackend, error) {
	base := os.Getenv("MODELENV_LOCAL_BASE_URL")
	if base == "" {
		return nil, fmt.Errorf("local backend requires MODELENV_LOCAL_BASE_URL (e.g. http://127.0.0.1:8000/v1)")
	}
	model := os.Getenv("MODELENV_MODEL")
	if model == "" {
		return nil, fmt.Errorf("local backend requires MODELENV_MODEL (the served model name)")
	}
	return &LocalBackend{
		baseURL:   strings.TrimRight(base, "/"),
		model:     model,
		apiKey:    os.Getenv("MODELENV_LOCAL_API_KEY"),
		maxTokens: maxOutputTokens(8192),
		http:      &http.Client{Timeout: 10 * time.Minute},
	}, nil
}

// Name implements Backend.
func (b *LocalBackend) Name() string { return "local:" + b.model }

// --- OpenAI-compatible wire types ---

type oaiTool struct {
	Type     string `json:"type"` // "function"
	Function struct {
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"function"`
}

type oaiToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"` // JSON-encoded string per the OpenAI spec
	} `json:"function"`
}

type oaiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content,omitempty"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"` // for role=tool
}

type oaiRequest struct {
	Model     string       `json:"model"`
	Messages  []oaiMessage `json:"messages"`
	Tools     []oaiTool    `json:"tools,omitempty"`
	MaxTokens int          `json:"max_tokens,omitempty"`
	Stream    bool         `json:"stream,omitempty"`
}

func (b *LocalBackend) buildRequest(messages []Message, tools []ToolSpec, stream bool) oaiRequest {
	req := oaiRequest{Model: b.model, MaxTokens: b.maxTokens, Stream: stream}
	for _, m := range messages {
		om := oaiMessage{Role: m.Role, Content: m.Content}
		switch m.Role {
		case RoleTool:
			om.Role = "tool"
			om.ToolCallID = m.ToolCallID
		case RoleAssistant:
			for _, tc := range m.ToolCalls {
				var oc oaiToolCall
				oc.ID = tc.ID
				oc.Type = "function"
				oc.Function.Name = tc.Name
				oc.Function.Arguments = string(tc.Arguments)
				om.ToolCalls = append(om.ToolCalls, oc)
			}
		}
		req.Messages = append(req.Messages, om)
	}
	for _, t := range tools {
		var ot oaiTool
		ot.Type = "function"
		ot.Function.Name = t.Name
		ot.Function.Description = t.Description
		ot.Function.Parameters = t.Parameters
		req.Tools = append(req.Tools, ot)
	}
	return req
}

func (b *LocalBackend) newHTTPRequest(ctx context.Context, body []byte) (*http.Request, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	if b.apiKey != "" {
		httpReq.Header.Set("authorization", "Bearer "+b.apiKey)
	}
	return httpReq, nil
}

// Complete implements Backend.
func (b *LocalBackend) Complete(ctx context.Context, messages []Message, tools []ToolSpec, stream StreamFunc) (*Completion, error) {
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
		return nil, fmt.Errorf("local inference request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("local inference status %d: %s", resp.StatusCode, buf.String())
	}
	if stream != nil {
		return b.parseStream(resp, stream)
	}
	return b.parseResponse(resp)
}

func (b *LocalBackend) parseResponse(resp *http.Response) (*Completion, error) {
	var out struct {
		Choices []struct {
			Message oaiMessage `json:"message"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode local response: %w", err)
	}
	if len(out.Choices) == 0 {
		return nil, fmt.Errorf("local inference returned no choices")
	}
	c := out.Choices[0].Message
	msg := Message{Role: RoleAssistant, Content: c.Content}
	for _, tc := range c.ToolCalls {
		args := tc.Function.Arguments
		if args == "" {
			args = "{}"
		}
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Arguments: json.RawMessage(args)})
	}
	return &Completion{
		Message: msg,
		Usage:   Usage{InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens},
	}, nil
}

// parseStream consumes OpenAI-compatible SSE chunks ("data: {json}\n\n",
// terminated by "data: [DONE]"). Text deltas forward to stream; tool-call
// fragments (name + argument string pieces) accumulate by index.
func (b *LocalBackend) parseStream(resp *http.Response, stream StreamFunc) (*Completion, error) {
	type pending struct {
		id, name string
		args     strings.Builder
	}
	calls := map[int]*pending{}
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
		if data == "" || data == "[DONE]" {
			continue
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
			} `json:"choices"`
			Usage *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}
		if chunk.Usage != nil {
			usage.InputTokens = chunk.Usage.PromptTokens
			usage.OutputTokens = chunk.Usage.CompletionTokens
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				text.WriteString(ch.Delta.Content)
				stream(ch.Delta.Content)
			}
			for _, tc := range ch.Delta.ToolCalls {
				p := calls[tc.Index]
				if p == nil {
					p = &pending{}
					calls[tc.Index] = p
				}
				if tc.ID != "" {
					p.id = tc.ID
				}
				if tc.Function.Name != "" {
					p.name = tc.Function.Name
				}
				p.args.WriteString(tc.Function.Arguments)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read local stream: %w", err)
	}

	msg := Message{Role: RoleAssistant, Content: text.String()}
	// Emit in index order; indices may be sparse/non-zero-based, so sort the keys
	// rather than iterating 0..len (which would drop missing indices).
	indices := make([]int, 0, len(calls))
	for i := range calls {
		indices = append(indices, i)
	}
	sort.Ints(indices)
	for _, i := range indices {
		p := calls[i]
		args := p.args.String()
		if args == "" {
			args = "{}"
		}
		msg.ToolCalls = append(msg.ToolCalls, ToolCall{ID: p.id, Name: p.name, Arguments: json.RawMessage(args)})
	}
	return &Completion{Message: msg, Usage: usage}, nil
}
