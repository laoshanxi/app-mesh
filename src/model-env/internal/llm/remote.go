package llm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// RemoteBackend forwards a single model call to an external reasoning service
// over HTTP — the seam for hosting the LLM-interaction layer in another language
// (e.g. a Python agent service using the Anthropic/OpenAI SDKs and the wider
// agent ecosystem) while the Go model-env App keeps the platform layer: the
// ReAct loop, tools, budgets, sessions, RBAC, and transport.
//
// The boundary is exactly the Backend contract: the remote service is a
// stateless completion provider — given the conversation history and the tool
// specs, it returns the next assistant turn (text or tool calls) and usage. It
// does NOT run the agent loop or invoke tools; the Go host does that.
//
// Config (no hardcoded URL/key):
//
//	MODELENV_REMOTE_URL      — base URL of the service (required); POSTs to {url}/complete
//	MODELENV_REMOTE_API_KEY  — bearer token, if the service requires one (optional)
//
// Wire protocol (see README "remote backend protocol"):
//
//	POST {url}/complete
//	  request : {"messages":[Message...], "tools":[ToolSpec...], "stream":bool}
//	  response (stream=false): a Completion JSON {"message":{...},"usage":{...}}
//	  response (stream=true) : text/event-stream of
//	      data: {"type":"text","text":"<chunk>"}        (incremental, optional)
//	      data: {"type":"completion","message":{...},"usage":{...}}  (final, authoritative)
//	      data: {"type":"error","error":"<message>"}    (on failure)
//
// Message / ToolCall / ToolSpec / Completion / Usage are the JSON shapes in
// llm.go, so the remote service speaks the same types verbatim.
type RemoteBackend struct {
	url    string
	apiKey string
	http   *http.Client
}

// NewRemoteBackend builds the backend from the environment. Fails closed if the
// service URL is unset.
func NewRemoteBackend() (*RemoteBackend, error) {
	url := os.Getenv("MODELENV_REMOTE_URL")
	if url == "" {
		return nil, fmt.Errorf("remote backend requires MODELENV_REMOTE_URL (base URL of the reasoning service)")
	}
	return &RemoteBackend{
		url:    strings.TrimRight(url, "/"),
		apiKey: os.Getenv("MODELENV_REMOTE_API_KEY"),
		http:   &http.Client{Timeout: 10 * time.Minute},
	}, nil
}

// Name implements Backend.
func (b *RemoteBackend) Name() string { return "remote" }

type remoteRequest struct {
	Messages []Message  `json:"messages"`
	Tools    []ToolSpec `json:"tools"`
	Stream   bool       `json:"stream"`
}

// Complete implements Backend.
func (b *RemoteBackend) Complete(ctx context.Context, messages []Message, tools []ToolSpec, stream StreamFunc) (*Completion, error) {
	body, err := json.Marshal(remoteRequest{Messages: messages, Tools: tools, Stream: stream != nil})
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.url+"/complete", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("content-type", "application/json")
	if b.apiKey != "" {
		httpReq.Header.Set("authorization", "Bearer "+b.apiKey)
	}

	resp, err := b.http.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("remote reasoning request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return nil, fmt.Errorf("remote reasoning status %d: %s", resp.StatusCode, buf.String())
	}

	if stream != nil {
		return b.parseStream(resp, stream)
	}
	var comp Completion
	if err := json.NewDecoder(resp.Body).Decode(&comp); err != nil {
		return nil, fmt.Errorf("decode remote completion: %w", err)
	}
	return &comp, nil
}

// parseStream consumes the service's SSE: "text" events forward to stream for
// live display; the authoritative result is the final "completion" event.
func (b *RemoteBackend) parseStream(resp *http.Response, stream StreamFunc) (*Completion, error) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var final *Completion
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
			Type    string   `json:"type"`
			Text    string   `json:"text"`
			Error   string   `json:"error"`
			Message *Message `json:"message"`
			Usage   Usage    `json:"usage"`
		}
		if err := json.Unmarshal([]byte(data), &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "text":
			stream(ev.Text)
		case "completion":
			if ev.Message != nil {
				final = &Completion{Message: *ev.Message, Usage: ev.Usage}
			}
		case "error":
			return nil, fmt.Errorf("remote reasoning error: %s", ev.Error)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read remote stream: %w", err)
	}
	if final == nil {
		return nil, fmt.Errorf("remote stream ended without a completion event")
	}
	return final, nil
}
