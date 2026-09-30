package appmesh

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
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

func (f *fakeRequester) Close()                          {}
func (f *fakeRequester) handleTokenUpdate(string)        {}
func (f *fakeRequester) setToken(string)                 {}
func (f *fakeRequester) getAccessToken() string          { return "" }
func (f *fakeRequester) setTokenProvider(TokenProvider)  {}
func (f *fakeRequester) getTokenProvider() TokenProvider { return nil }
func (f *fakeRequester) setForwardTo(string)             {}
func (f *fakeRequester) getForwardTo() string            { return "" }

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

// fakeRefreshProvider is a refresh-capable TokenProvider that records every
// RefreshAccessToken call (count and rejected token) and rotates its token.
type fakeRefreshProvider struct {
	mu           sync.Mutex
	token        string
	refreshCount int
	rejected     []string
}

func (f *fakeRefreshProvider) AccessToken() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.token, nil
}

func (f *fakeRefreshProvider) CanRefresh() bool { return true }

func (f *fakeRefreshProvider) RefreshAccessToken(rejectedToken string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshCount++
	f.rejected = append(f.rejected, rejectedToken)
	f.token = "fresh-token"
	return f.token, nil
}

func (f *fakeRefreshProvider) Clear() {}

// A 401 against a refresh-capable provider triggers exactly one refresh and one
// replay; the retried request carries the new bearer (mirroring the Python SDK).
func TestTokenProviderRefreshesOn401(t *testing.T) {
	var mu sync.Mutex
	var authHeaders []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		attempt := len(authHeaders)
		mu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"BaseConfig":{"LogLevel":"DEBUG"}}`))
	}))
	defer server.Close()

	provider := &fakeRefreshProvider{token: "stale-token"}
	client, err := NewHTTPClient(Option{AppMeshUri: server.URL, TokenProvider: provider})
	require.NoError(t, err)
	defer client.Close()

	// SetLogLevel POSTs a replayable bytes.Buffer JSON body.
	level, err := client.SetLogLevel("DEBUG")
	require.NoError(t, err)
	assert.Equal(t, "DEBUG", level)

	provider.mu.Lock()
	defer provider.mu.Unlock()
	assert.Equal(t, 1, provider.refreshCount, "refresh must happen exactly once")
	assert.Equal(t, []string{"stale-token"}, provider.rejected)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, authHeaders, 2)
	assert.Equal(t, "Bearer stale-token", authHeaders[0])
	assert.Equal(t, "Bearer fresh-token", authHeaders[1])
}

// A static provider cannot refresh, so a 401 is returned without any retry.
func TestStaticTokenProviderDoesNotRetryOn401(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	provider, err := NewStaticTokenProvider("static-token")
	require.NoError(t, err)
	client, err := NewHTTPClient(Option{AppMeshUri: server.URL, TokenProvider: provider})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.ListLabels()
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	assert.Equal(t, 1, requests, "a static provider must not trigger a retry")
}

// failingRefreshProvider rejects every refresh, e.g. after invalid_grant.
type failingRefreshProvider struct{ token string }

func (f *failingRefreshProvider) AccessToken() (string, error) { return f.token, nil }
func (f *failingRefreshProvider) CanRefresh() bool             { return true }
func (f *failingRefreshProvider) RefreshAccessToken(rejectedToken string) (string, error) {
	return "", errors.New("refresh token rejected (invalid_grant)")
}
func (f *failingRefreshProvider) Clear() {}

// A failed 401 refresh must surface as an error, not a nil-response panic.
func TestTokenProviderRefreshFailureReturnsError(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	client, err := NewHTTPClient(Option{AppMeshUri: server.URL, TokenProvider: &failingRefreshProvider{token: "stale-token"}})
	require.NoError(t, err)
	defer client.Close()

	_, err = client.ListLabels()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")
	assert.Equal(t, 1, requests, "a failed refresh must not replay the request")
}

func TestNewStaticTokenProviderRejectsEmptyToken(t *testing.T) {
	for _, token := range []string{"", "   "} {
		provider, err := NewStaticTokenProvider(token)
		require.Error(t, err, "token %q must be rejected", token)
		assert.Nil(t, provider)
	}

	provider, err := NewStaticTokenProvider("  padded-token  ")
	require.NoError(t, err)
	token, err := provider.AccessToken()
	require.NoError(t, err)
	assert.Equal(t, "padded-token", token)
	assert.False(t, provider.CanRefresh())

	provider.Clear()
	_, err = provider.AccessToken()
	require.Error(t, err, "a cleared provider must not yield a token")
}

// SetToken replaces an attached provider with a static token, so a later 401
// is not refreshed even if the previous provider could refresh.
func TestSetTokenReplacesProvider(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	provider := &fakeRefreshProvider{token: "stale-token"}
	client, err := NewHTTPClient(Option{AppMeshUri: server.URL, TokenProvider: provider})
	require.NoError(t, err)
	defer client.Close()

	client.SetToken("static-token")
	_, err = client.ListLabels()
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
	assert.Equal(t, 1, requests)
	assert.Equal(t, 0, provider.refreshCount)
}
