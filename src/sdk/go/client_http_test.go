package appmesh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func requireBearerToken(t *testing.T) string {
	t.Helper()
	token := os.Getenv("APPMESH_BEARER_TOKEN")
	if token == "" {
		t.Skip("APPMESH_BEARER_TOKEN is required for live integration tests")
	}
	return token
}

func TestBearerTokenIsInMemoryOnly(t *testing.T) {
	client, err := NewHTTPClient(Option{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer client.Close()

	require.Empty(t, client.GetToken())
	client.SetToken("test-only-placeholder")
	require.Equal(t, "test-only-placeholder", client.GetToken())
	client.ClearToken()
	require.Empty(t, client.GetToken())

	httpRequester, ok := client.req.(*HTTPRequester)
	require.True(t, ok)
	require.Nil(t, httpRequester.httpClient.Jar, "bearer-only clients must not retain cookies")
}

// fakeRequester scripts one response and records every request's method, path
// and headers so client-side behavior can be asserted without a live daemon.
type fakeRequester struct {
	status int
	body   string
	header http.Header
	sent   []fakeSentRequest
}

type fakeSentRequest struct {
	method string
	path   string
	header map[string]string
}

func (f *fakeRequester) capture(method string, apiPath string, headers map[string]string) {
	copied := make(map[string]string, len(headers))
	for k, v := range headers {
		copied[k] = v
	}
	f.sent = append(f.sent, fakeSentRequest{method: method, path: apiPath, header: copied})
}

func (f *fakeRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return f.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

func (f *fakeRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	f.capture(method, apiPath, headers)
	if f.header == nil {
		return f.status, []byte(f.body), http.Header{}, nil
	}
	return f.status, []byte(f.body), f.header, nil
}

func (f *fakeRequester) Close()                   {}
func (f *fakeRequester) handleTokenUpdate(string) {}
func (f *fakeRequester) setToken(string)          {}
func (f *fakeRequester) getAccessToken() string   { return "" }
func (f *fakeRequester) setForwardTo(string)      {}
func (f *fakeRequester) getForwardTo() string     { return "" }

func newFakeClient(status int, body string) (*AppMeshClient, *fakeRequester) {
	fake := &fakeRequester{status: status, body: body}
	return &AppMeshClient{req: fake}, fake
}

// A 200 run response without a usable app name must be an error: a silently
// empty name gives the caller an AppRun handle that no follow-up call resolves.
func TestRunAppAsyncRequiresNameInResponse(t *testing.T) {
	for _, body := range []string{
		`{"process_uuid":"proc-1"}`,
		`{"name":123,"process_uuid":"proc-1"}`,
	} {
		client, _ := newFakeClient(http.StatusOK, body)
		run, err := client.RunAppAsync(Application{Name: "app1"}, 60, 0)
		require.Error(t, err, "body %s must not produce a runnable AppRun", body)
		assert.Nil(t, run)
		assert.Contains(t, err.Error(), "missing app name")
	}

	client, _ := newFakeClient(http.StatusOK, `{"name":"app-123","process_uuid":"proc-1"}`)
	run, err := client.RunAppAsync(Application{Name: "app1"}, 60, 0)
	require.NoError(t, err)
	require.NotNil(t, run)
	assert.Equal(t, "app-123", run.AppName)
	assert.Equal(t, "proc-1", run.ProcUid)
}

// A successful (200) config update must come back as success. Only a non-200
// response may produce an APIError; an unexpected 200 shape is a parse error.
func TestSetLogLevelSuccessIsNotAnError(t *testing.T) {
	client, _ := newFakeClient(http.StatusOK, `{"BaseConfig":{"LogLevel":"DEBUG"}}`)
	level, err := client.SetLogLevel("DEBUG")
	require.NoError(t, err)
	assert.Equal(t, "DEBUG", level)

	for _, body := range []string{`{}`, `{"BaseConfig":{"LogLevel":1}}`} {
		client, _ := newFakeClient(http.StatusOK, body)
		_, err := client.SetLogLevel("DEBUG")
		require.Error(t, err, "body %s must not parse as a confirmed level", body)
		var apiErr *APIError
		assert.False(t, errors.As(err, &apiErr), "a 200 response must not be reported as an APIError: %v", err)
	}

	client, _ = newFakeClient(http.StatusBadRequest, `{"error":"bad level"}`)
	_, err = client.SetLogLevel("DEBUG")
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadRequest, apiErr.StatusCode)
}

// CancelTask treats "nothing to cancel" as a non-error false, matching the Python
// SDK: 200 = cancelled, 208 = no task pending, 404 = app not found. Only other
// non-200 statuses surface an APIError.
func TestCancelTaskStatusSemantics(t *testing.T) {
	client, _ := newFakeClient(http.StatusOK, "")
	cancelled, err := client.CancelTask("app1")
	require.NoError(t, err)
	assert.True(t, cancelled)

	for _, status := range []int{http.StatusAlreadyReported, http.StatusNotFound} {
		client, _ := newFakeClient(status, "")
		cancelled, err := client.CancelTask("app1")
		require.NoError(t, err, "status %d must not be an error", status)
		assert.False(t, cancelled)
	}

	client, _ = newFakeClient(http.StatusInternalServerError, "boom")
	cancelled, err = client.CancelTask("app1")
	require.Error(t, err)
	assert.False(t, cancelled)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
}

// RunAppSync cannot distinguish a missing X-Exit-Code header from exit code 0;
// RunAppSyncChecked exposes the distinction (Python returns None for a missing header).
func TestRunAppSyncExitCodePresence(t *testing.T) {
	client, fake := newFakeClient(http.StatusOK, "out")
	fake.header = http.Header{"X-Exit-Code": []string{"3"}}
	exit, out, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, 3, exit)
	assert.Equal(t, "out", out)

	client, fake = newFakeClient(http.StatusOK, "out")
	fake.header = http.Header{"X-Exit-Code": []string{"0"}}
	exit, _, ok, err := client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.True(t, ok, "an explicit 0 exit code must be reported as present")
	assert.Equal(t, 0, exit)

	client, _ = newFakeClient(http.StatusOK, "out")
	exit, out, ok, err = client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.False(t, ok, "a missing X-Exit-Code header must not be conflated with exit code 0")
	assert.Equal(t, 0, exit)
	assert.Equal(t, "out", out)

	client, _ = newFakeClient(http.StatusOK, "out")
	exit, _, err = client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, 0, exit, "RunAppSync keeps its legacy zero-default behavior")
}

// JSON request bodies carry Content-Type: application/json so the daemon does
// not have to sniff. Bodies that are not JSON (task payloads are opaque
// octet-stream per openapi.yaml) and empty bodies carry none.
func TestJSONBodyContentType(t *testing.T) {
	client, fake := newFakeClient(http.StatusOK, `{"name":"app1"}`)
	_, err := client.AddApp(Application{Name: "app1"})
	require.NoError(t, err)
	require.Len(t, fake.sent, 1)
	assert.Equal(t, http.MethodPut, fake.sent[0].method)
	assert.Equal(t, "application/json", fake.sent[0].header["Content-Type"])

	client, fake = newFakeClient(http.StatusOK, `{"BaseConfig":{"LogLevel":"INFO"}}`)
	_, err = client.SetLogLevel("INFO")
	require.NoError(t, err)
	require.Len(t, fake.sent, 1)
	assert.Equal(t, http.MethodPost, fake.sent[0].method)
	assert.Equal(t, "application/json", fake.sent[0].header["Content-Type"])

	// Task payload is opaque application/octet-stream: no Content-Type is set.
	client, fake = newFakeClient(http.StatusOK, "result")
	_, err = client.RunTask("app1", `{"any":"payload"}`, 5)
	require.NoError(t, err)
	require.Len(t, fake.sent, 1)
	assert.Equal(t, "", fake.sent[0].header["Content-Type"])

	// Body-less POST carries no Content-Type.
	client, fake = newFakeClient(http.StatusOK, "")
	_, err = client.EnableApp("app1")
	require.NoError(t, err)
	require.Len(t, fake.sent, 1)
	assert.Equal(t, "", fake.sent[0].header["Content-Type"])
}
