package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// These tests validate the request mapping and response/SSE parsing of the real
// backends against canned HTTP responses — the wire logic that cannot be checked
// against live providers. They do not exercise any network.

func TestAnthropicNonStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "test-key" || r.Header.Get("anthropic-version") == "" {
			t.Errorf("missing auth/version headers")
		}
		w.Write([]byte(`{"content":[{"type":"text","text":"hello "},{"type":"tool_use","id":"t1","name":"echo","input":{"x":1}}],"stop_reason":"tool_use","usage":{"input_tokens":10,"output_tokens":5}}`))
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	be, err := NewAnthropicBackend()
	if err != nil {
		t.Fatal(err)
	}
	comp, err := be.Complete(context.Background(),
		[]Message{{Role: RoleUser, Content: "hi"}},
		[]ToolSpec{{Name: "echo", Parameters: json.RawMessage(`{"type":"object"}`)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if comp.Message.Content != "hello " {
		t.Errorf("content = %q", comp.Message.Content)
	}
	if len(comp.Message.ToolCalls) != 1 || comp.Message.ToolCalls[0].Name != "echo" {
		t.Errorf("tool calls = %+v", comp.Message.ToolCalls)
	}
	if comp.Usage.InputTokens != 10 || comp.Usage.OutputTokens != 5 {
		t.Errorf("usage = %+v", comp.Usage)
	}
}

func TestAnthropicStream(t *testing.T) {
	sse := "event: message_start\n" +
		`data: {"type":"message_start","message":{"usage":{"input_tokens":7,"output_tokens":0}}}` + "\n\n" +
		`data: {"type":"content_block_start","index":0,"content_block":{"type":"text"}}` + "\n\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hel"}}` + "\n\n" +
		`data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"lo"}}` + "\n\n" +
		`data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"t1","name":"echo"}}` + "\n\n" +
		`data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"x\":1}"}}` + "\n\n" +
		`data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":4}}` + "\n\n" +
		`data: {"type":"message_stop"}` + "\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		w.Write([]byte(sse))
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_API_KEY", "k")
	t.Setenv("ANTHROPIC_BASE_URL", srv.URL)
	be, _ := NewAnthropicBackend()

	var streamed string
	comp, err := be.Complete(context.Background(),
		[]Message{{Role: RoleUser, Content: "hi"}}, nil,
		func(c string) { streamed += c })
	if err != nil {
		t.Fatal(err)
	}
	if streamed != "hello" || comp.Message.Content != "hello" {
		t.Errorf("streamed=%q content=%q", streamed, comp.Message.Content)
	}
	if len(comp.Message.ToolCalls) != 1 || comp.Message.ToolCalls[0].Name != "echo" ||
		string(comp.Message.ToolCalls[0].Arguments) != `{"x":1}` {
		t.Errorf("tool calls = %+v", comp.Message.ToolCalls)
	}
	if comp.Usage.InputTokens != 7 || comp.Usage.OutputTokens != 4 {
		t.Errorf("usage = %+v", comp.Usage)
	}
}

func TestLocalNonStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi","tool_calls":[{"id":"t1","type":"function","function":{"name":"echo","arguments":"{\"x\":1}"}}]}}],"usage":{"prompt_tokens":3,"completion_tokens":2}}`))
	}))
	defer srv.Close()

	t.Setenv("MODELENV_LOCAL_BASE_URL", srv.URL)
	t.Setenv("MODELENV_MODEL", "test-model")
	be, err := NewLocalBackend()
	if err != nil {
		t.Fatal(err)
	}
	comp, err := be.Complete(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if comp.Message.Content != "hi" || len(comp.Message.ToolCalls) != 1 ||
		string(comp.Message.ToolCalls[0].Arguments) != `{"x":1}` {
		t.Errorf("message = %+v", comp.Message)
	}
	if comp.Usage.InputTokens != 3 || comp.Usage.OutputTokens != 2 {
		t.Errorf("usage = %+v", comp.Usage)
	}
}

func TestLocalStream(t *testing.T) {
	sse := `data: {"choices":[{"delta":{"content":"he"}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"content":"llo"}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"t1","function":{"name":"echo","arguments":"{\"x\":"}}]}}]}` + "\n\n" +
		`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}` + "\n\n" +
		`data: {"usage":{"prompt_tokens":3,"completion_tokens":2}}` + "\n\n" +
		"data: [DONE]\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sse))
	}))
	defer srv.Close()

	t.Setenv("MODELENV_LOCAL_BASE_URL", srv.URL)
	t.Setenv("MODELENV_MODEL", "m")
	be, _ := NewLocalBackend()

	var streamed string
	comp, err := be.Complete(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil,
		func(c string) { streamed += c })
	if err != nil {
		t.Fatal(err)
	}
	if streamed != "hello" || comp.Message.Content != "hello" {
		t.Errorf("streamed=%q content=%q", streamed, comp.Message.Content)
	}
	if len(comp.Message.ToolCalls) != 1 || string(comp.Message.ToolCalls[0].Arguments) != `{"x":1}` {
		t.Errorf("tool calls = %+v", comp.Message.ToolCalls)
	}
}

func TestRemoteNonStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/complete" {
			t.Errorf("path = %s", r.URL.Path)
		}
		// Echo a Completion in the neutral shape.
		json.NewEncoder(w).Encode(Completion{
			Message: Message{Role: RoleAssistant, Content: "done"},
			Usage:   Usage{InputTokens: 1, OutputTokens: 1},
		})
	}))
	defer srv.Close()

	t.Setenv("MODELENV_REMOTE_URL", srv.URL)
	be, err := NewRemoteBackend()
	if err != nil {
		t.Fatal(err)
	}
	comp, err := be.Complete(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if comp.Message.Content != "done" {
		t.Errorf("content = %q", comp.Message.Content)
	}
}

func TestRemoteStream(t *testing.T) {
	sse := `data: {"type":"text","text":"done"}` + "\n\n" +
		`data: {"type":"completion","message":{"role":"assistant","content":"done"},"usage":{"input_tokens":1,"output_tokens":1}}` + "\n\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sse))
	}))
	defer srv.Close()

	t.Setenv("MODELENV_REMOTE_URL", srv.URL)
	be, _ := NewRemoteBackend()

	var streamed string
	comp, err := be.Complete(context.Background(), []Message{{Role: RoleUser, Content: "hi"}}, nil,
		func(c string) { streamed += c })
	if err != nil {
		t.Fatal(err)
	}
	if streamed != "done" || comp.Message.Content != "done" {
		t.Errorf("streamed=%q content=%q", streamed, comp.Message.Content)
	}
}

func TestNewBackendUnknownFailsClosed(t *testing.T) {
	if _, err := NewBackend("nope"); err == nil {
		t.Error("expected error for unknown backend")
	}
	if b, err := NewBackend("stub"); err != nil || b == nil {
		t.Errorf("stub backend: %v", err)
	}
}
