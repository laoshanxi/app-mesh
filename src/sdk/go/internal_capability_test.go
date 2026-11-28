package appmesh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// workflowSecretRequester records one broker call and returns a scripted reply.
type workflowSecretRequester struct {
	method   string
	path     string
	headers  map[string]string
	body     []byte
	status   int
	response string
}

func (f *workflowSecretRequester) Send(method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return f.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

func (f *workflowSecretRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	f.method, f.path, f.headers = method, apiPath, headers
	if body != nil {
		f.body, _ = io.ReadAll(body)
	}
	status := f.status
	if status == 0 {
		status = http.StatusOK
	}
	return status, []byte(f.response), http.Header{}, nil
}

func (f *workflowSecretRequester) Close()                          {}
func (f *workflowSecretRequester) handleTokenUpdate(string)        {}
func (f *workflowSecretRequester) setToken(string)                 {}
func (f *workflowSecretRequester) getAccessToken() string          { return "" }
func (f *workflowSecretRequester) setTokenProvider(TokenProvider)  {}
func (f *workflowSecretRequester) getTokenProvider() TokenProvider { return nil }
func (f *workflowSecretRequester) setForwardTo(string)             {}
func (f *workflowSecretRequester) getForwardTo() string            { return "" }
func (f *workflowSecretRequester) setRequestSigner(*requestSigner) {}

func TestProtectWorkflowSecretsContext(t *testing.T) {
	requester := &workflowSecretRequester{
		response: `{"secrets":[{"key":"TOKEN","value":"sp1:protected"}]}`,
	}
	client := &AppMeshClient{req: requester}
	out, err := client.ProtectWorkflowSecretsContext(context.Background(), "wf-demo",
		[]WorkflowSecretValue{{Key: "TOKEN", Value: "plain"}})
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if len(out) != 1 || out[0].Key != "TOKEN" || out[0].Value != "sp1:protected" {
		t.Fatalf("unexpected response: %+v", out)
	}
	if requester.method != http.MethodPost || requester.path != "/appmesh/internal/workflow/secret" {
		t.Fatalf("unexpected request %s %s", requester.method, requester.path)
	}
	if requester.headers["Content-Type"] != "application/json" {
		t.Fatalf("missing JSON content type: %v", requester.headers)
	}
	var request struct {
		Op       string                `json:"op"`
		Workflow string                `json:"workflow"`
		Secrets  []WorkflowSecretValue `json:"secrets"`
	}
	if err := json.Unmarshal(requester.body, &request); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if request.Op != "protect" || request.Workflow != "wf-demo" || len(request.Secrets) != 1 ||
		request.Secrets[0].Key != "TOKEN" || request.Secrets[0].Value != "plain" {
		t.Fatalf("unexpected request body: %s", requester.body)
	}
}

func TestWorkflowSecretsContextRejectsMismatchedResponse(t *testing.T) {
	requester := &workflowSecretRequester{
		response: `{"secrets":[{"key":"OTHER","value":"plain"}]}`,
	}
	client := &AppMeshClient{req: requester}
	_, err := client.UnprotectWorkflowSecretsContext(context.Background(), "wf-demo",
		[]WorkflowSecretValue{{Key: "TOKEN", Value: "sp1:protected"}})
	if err == nil || !strings.Contains(err.Error(), "in place of") {
		t.Fatalf("a response with the wrong key must fail, got %v", err)
	}
}

func TestUnprotectWorkflowSecretsContextError(t *testing.T) {
	requester := &workflowSecretRequester{
		status:   http.StatusBadRequest,
		response: `{"error":"workflow secret <TOKEN> cannot be decrypted"}`,
	}
	client := &AppMeshClient{req: requester}
	_, err := client.UnprotectWorkflowSecretsContext(context.Background(), "wf-demo",
		[]WorkflowSecretValue{{Key: "TOKEN", Value: "sp1:protected"}})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected an APIError with status 400, got %v", err)
	}
	if !strings.Contains(err.Error(), "workflow secret unprotect") {
		t.Fatalf("error must name the operation: %v", err)
	}
}
