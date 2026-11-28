package appmesh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scriptedRequester answers with the next scripted response and records the
// requests, so sync run paging can be asserted without a live daemon.
type scriptedRequester struct {
	responses []scriptedResponse
	sent      []scriptedRequest
	// ctxErrAt is the request index from which a cancelled context is honored;
	// the fake checks cancellation itself since it has no I/O to block on.
	ctxErrAt int
}

type scriptedResponse struct {
	status int
	body   []byte
	header http.Header
}

type scriptedRequest struct {
	method  string
	path    string
	queries url.Values
}

func (s *scriptedRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	s.sent = append(s.sent, scriptedRequest{method: method, path: apiPath, queries: queries})
	if len(s.sent) > s.ctxErrAt {
		if err := ctx.Err(); err != nil {
			return 0, nil, http.Header{}, err
		}
	}
	if len(s.responses) == 0 {
		return http.StatusNotFound, []byte("no scripted response"), http.Header{}, nil
	}
	resp := s.responses[0]
	s.responses = s.responses[1:]
	return resp.status, resp.body, resp.header, nil
}

func (s *scriptedRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string,
	body io.Reader) (int, []byte, http.Header, error) {
	return s.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

func (s *scriptedRequester) Close()                          {}
func (s *scriptedRequester) handleTokenUpdate(string)        {}
func (s *scriptedRequester) setToken(string)                 {}
func (s *scriptedRequester) getAccessToken() string          { return "" }
func (s *scriptedRequester) setTokenProvider(TokenProvider)  {}
func (s *scriptedRequester) getTokenProvider() TokenProvider { return nil }
func (s *scriptedRequester) setForwardTo(string)             {}
func (s *scriptedRequester) getForwardTo() string            { return "" }
func (s *scriptedRequester) setRequestSigner(*requestSigner) {}

func (s *scriptedRequester) paths() []string {
	paths := make([]string, 0, len(s.sent))
	for _, req := range s.sent {
		paths = append(paths, req.method+" "+req.path)
	}
	return paths
}

func truncatedRunScript(firstPage, lastPage []byte, deleteStatus int) *scriptedRequester {
	return &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: firstPage, header: http.Header{
			"X-Exit-Code":        []string{"7"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{fmt.Sprintf("%d", len(firstPage))},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusOK, body: lastPage},
		{status: deleteStatus},
	}}
}

func repeat(b byte, n int) []byte {
	page := make([]byte, n)
	for i := range page {
		page[i] = b
	}
	return page
}

// Without the truncation headers the run is a single request and the returned
// values are byte-identical to the previous behavior (no paging, no delete).
func TestRunAppSyncUntruncatedPathUnchanged(t *testing.T) {
	for _, body := range []string{"out", "", "caf\xc3\xa9 \xff raw bytes"} {
		client := &AppMeshClient{req: &scriptedRequester{responses: []scriptedResponse{{status: http.StatusOK,
			body: []byte(body), header: http.Header{"X-Exit-Code": []string{"3"}}}}}}

		exit, out, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
		require.NoError(t, err)
		assert.Equal(t, 3, exit)
		assert.Equal(t, body, out)

		client = &AppMeshClient{req: &scriptedRequester{responses: []scriptedResponse{{status: http.StatusOK,
			body: []byte(body), header: http.Header{"X-Exit-Code": []string{"3"}}}}}}
		exit, out, ok, err := client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 3, exit)
		assert.Equal(t, body, out)
		assert.Equal(t, []string{"POST /appmesh/app/syncrun"}, client.req.(*scriptedRequester).paths())

		// A named run that is not truncated (or an old daemon) is not paged either.
		client = &AppMeshClient{req: &scriptedRequester{responses: []scriptedResponse{{status: http.StatusOK,
			body: []byte(body), header: http.Header{"X-Exit-Code": []string{"0"}, "X-App-Name": []string{"run-x"},
				"X-Output-Position": []string{"4"}}}}}}
		_, out, err = client.RunAppSync(Application{Name: "app1"}, 10, 20)
		require.NoError(t, err)
		assert.Equal(t, body, out)
		assert.Equal(t, []string{"POST /appmesh/app/syncrun"}, client.req.(*scriptedRequester).paths())
	}

	// A failing run keeps returning the API error with the first page as message.
	client, _ := newFakeClient(http.StatusInternalServerError, "boom")
	_, _, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusInternalServerError, apiErr.StatusCode)
	assert.Equal(t, "sync run failed with status 500: boom", err.Error())
}

// A full first page is followed from X-Output-Position; every full page leads
// to another read at a byte position advanced by the raw page length.
func TestRunAppSyncTruncatedJoinsPagesAndAdvancesPosition(t *testing.T) {
	page0 := repeat('a', syncRunOutputPageBytes)
	page1 := repeat('b', syncRunOutputPageBytes)
	page2 := repeat('c', 1000)
	req := &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: page0, header: http.Header{
			"X-Exit-Code":        []string{"0"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{strconv.Itoa(syncRunOutputPageBytes)},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusOK, body: page1},
		{status: http.StatusOK, body: page2},
		{status: http.StatusNoContent},
	}}
	client := &AppMeshClient{req: req}

	exit, out, ok, err := client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, 0, exit)
	assert.Equal(t, string(page0)+string(page1)+string(page2), out)

	require.Len(t, req.sent, 4)
	assert.Equal(t, "POST", req.sent[0].method)
	assert.Equal(t, []string{"10"}, req.sent[0].queries["timeout"])
	assert.Equal(t, []string{"20"}, req.sent[0].queries["lifecycle"])
	for i, want := range []string{strconv.Itoa(syncRunOutputPageBytes), strconv.Itoa(2 * syncRunOutputPageBytes)} {
		assert.Equal(t, "GET", req.sent[i+1].method)
		assert.Equal(t, "/appmesh/app/run-abc/output", req.sent[i+1].path)
		assert.Equal(t, []string{want}, req.sent[i+1].queries["stdout_position"], "page %d", i)
	}
	assert.Equal(t, "DELETE", req.sent[3].method)
	assert.Equal(t, "/appmesh/app/run-abc", req.sent[3].path)
}

// Exactly one page: the follow-up read returns an empty page and the run is removed.
func TestRunAppSyncTruncatedExactlyOnePage(t *testing.T) {
	page := repeat('x', syncRunOutputPageBytes)
	req := &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: page, header: http.Header{
			"X-Exit-Code":        []string{"0"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{strconv.Itoa(syncRunOutputPageBytes)},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusOK, body: nil},
		{status: http.StatusOK},
	}}
	client := &AppMeshClient{req: req}

	_, out, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, string(page), out)
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output",
		"DELETE /appmesh/app/run-abc"}, req.paths())
}

// A multi-byte character split across a page boundary survives: the pages are
// joined as bytes and decoded once.
func TestRunAppSyncTruncatedKeepsSplitMultiByteCharacter(t *testing.T) {
	// "é" is 0xC3 0xA9; cut between its two bytes.
	page0 := append(repeat(' ', syncRunOutputPageBytes-1), 0xc3)
	page1 := append([]byte{0xa9}, repeat(' ', 10)...)
	req := truncatedRunScript(page0, page1, http.StatusOK)
	client := &AppMeshClient{req: req}

	_, out, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, string(append(append([]byte{}, page0...), page1...)), out)
	assert.Equal(t, "é", out[syncRunOutputPageBytes-1:syncRunOutputPageBytes+1])
	assert.True(t, strings.HasSuffix(out, strings.Repeat(" ", 10)))

	// The charset of the first response selects the decoding.
	req = truncatedRunScript(page0, page1, http.StatusOK)
	client = &AppMeshClient{req: req}
	req.responses[0].header.Set("Content-Type", "text/plain; charset=utf-8")
	_, out, err = client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, "é", out[syncRunOutputPageBytes-1:syncRunOutputPageBytes+1])

	req = truncatedRunScript(page0, page1, http.StatusOK)
	client = &AppMeshClient{req: req}
	req.responses[0].header.Set("Content-Type", "text/plain; charset=iso-8859-1")
	_, _, _, err = client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "iso-8859-1")
}

// Exceeding MaxOutputBytes is an error, not a truncated result, and the run is
// left on the daemon so the rest stays readable.
func TestRunAppSyncMaxOutputBytesExceededKeepsRun(t *testing.T) {
	page0 := repeat('a', syncRunOutputPageBytes)
	page1 := repeat('b', syncRunOutputPageBytes)
	req := &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: page0, header: http.Header{
			"X-Exit-Code":        []string{"0"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{strconv.Itoa(syncRunOutputPageBytes)},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusOK, body: page1},
	}}
	client := &AppMeshClient{req: req}

	exit, out, err := client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: syncRunOutputPageBytes + 10})
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("exceeds MaxOutputBytes=%d", syncRunOutputPageBytes+10))
	assert.Contains(t, err.Error(), "application 'run-abc' for 600 seconds")
	assert.Equal(t, 0, exit)
	assert.Empty(t, out)
	// Stops right after the page that crossed the ceiling; no delete.
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output"}, req.paths())

	// The ceiling is inclusive: exactly MaxOutputBytes of output is accepted.
	page2 := repeat('c', 10)
	req = &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: page0, header: http.Header{
			"X-Exit-Code":        []string{"0"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{strconv.Itoa(syncRunOutputPageBytes)},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusOK, body: page1},
		{status: http.StatusOK, body: page2},
		{status: http.StatusOK},
	}}
	client = &AppMeshClient{req: req}
	_, out, err = client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: int64(len(page0) + len(page1) + len(page2))})
	require.NoError(t, err)
	assert.Equal(t, string(page0)+string(page1)+string(page2), out)
	assert.Len(t, req.sent, 4, "the run is removed once read completely")
}

// The ceiling holds for every output size, whatever the shape of the pages.
func TestRunAppSyncMaxOutputBytesCeilingShapes(t *testing.T) {
	page := func(n int) []byte { return repeat('p', n) }
	full := page(syncRunOutputPageBytes)

	// (1) The first page alone is over: no page read, no delete.
	req := truncatedRunScript(full, nil, http.StatusOK)
	client := &AppMeshClient{req: req}
	_, out, err := client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: syncRunOutputPageBytes - 1})
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("exceeds MaxOutputBytes=%d", syncRunOutputPageBytes-1))
	assert.Contains(t, err.Error(), "application 'run-abc' for 600 seconds")
	assert.Empty(t, out)
	assert.Equal(t, []string{"POST /appmesh/app/syncrun"}, req.paths())

	// (2) 1.4 pages over: one read, error, no delete.
	for _, tail := range []int{10, 1200000} {
		req := truncatedRunScript(full, page(tail), http.StatusOK)
		client = &AppMeshClient{req: req}
		_, out, err = client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
			SyncRunOptions{MaxOutputBytes: int64(syncRunOutputPageBytes + tail/2)})
		require.Error(t, err, "tail %d", tail)
		assert.Contains(t, err.Error(), "exceeds MaxOutputBytes=")
		assert.Empty(t, out)
		assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output"}, req.paths())
	}

	// (3) A short final page crosses the ceiling.
	req = truncatedRunScript(full, page(100), http.StatusOK)
	client = &AppMeshClient{req: req}
	_, _, err = client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: syncRunOutputPageBytes + 10})
	require.Error(t, err)
	assert.Contains(t, err.Error(), fmt.Sprintf("exceeds MaxOutputBytes=%d", syncRunOutputPageBytes+10))
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output"}, req.paths())

	// (4) Exactly at the ceiling is returned, on a short final page and on a full one.
	req = truncatedRunScript(full, page(100), http.StatusOK)
	client = &AppMeshClient{req: req}
	_, out, err = client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: syncRunOutputPageBytes + 100})
	require.NoError(t, err)
	assert.Equal(t, string(full)+string(page(100)), out)
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output",
		"DELETE /appmesh/app/run-abc"}, req.paths())

	req = truncatedRunScript(full, full, http.StatusOK)
	req.responses = append(req.responses[:2], scriptedResponse{status: http.StatusOK, body: nil},
		scriptedResponse{status: http.StatusOK})
	client = &AppMeshClient{req: req}
	_, out, err = client.RunAppSyncWithContext(context.Background(), Application{Name: "app1"}, 10, 20,
		SyncRunOptions{MaxOutputBytes: 2 * syncRunOutputPageBytes})
	require.NoError(t, err)
	assert.Equal(t, string(full)+string(full), out)
	assert.Len(t, req.sent, 4, "two full pages, the empty final read, then the delete")
	assert.Equal(t, "DELETE", req.sent[3].method)
}

// Failing to remove the run is logged, not returned.
func TestRunAppSyncTruncatedToleratesDeleteFailure(t *testing.T) {
	for _, deleteStatus := range []int{http.StatusInternalServerError, http.StatusForbidden} {
		req := truncatedRunScript(repeat('h', syncRunOutputPageBytes), []byte("tail"), deleteStatus)
		client := &AppMeshClient{req: req}

		exit, out, ok, err := client.RunAppSyncChecked(Application{Name: "app1"}, 10, 20)
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Equal(t, 7, exit)
		assert.Equal(t, string(repeat('h', syncRunOutputPageBytes))+"tail", out)
	}
}

// A failure while paging is an error and keeps the run for a later read.
func TestRunAppSyncTruncatedPageFailureKeepsRun(t *testing.T) {
	req := &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: repeat('h', syncRunOutputPageBytes), header: http.Header{
			"X-Exit-Code":        []string{"0"},
			"X-Output-Truncated": []string{"1"},
			"X-Output-Position":  []string{strconv.Itoa(syncRunOutputPageBytes)},
			"X-App-Name":         []string{"run-abc"},
		}},
		{status: http.StatusNotFound, body: []byte("gone")},
	}}
	client := &AppMeshClient{req: req}

	_, _, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.StatusCode)
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output"}, req.paths())

	// A truncated reply without a usable position cannot be continued.
	req = &scriptedRequester{responses: []scriptedResponse{
		{status: http.StatusOK, body: repeat('h', syncRunOutputPageBytes), header: http.Header{
			"X-Output-Truncated": []string{"1"},
			"X-App-Name":         []string{"run-abc"},
		}},
	}}
	client = &AppMeshClient{req: req}
	_, _, err = client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "X-Output-Position")

	// Cancelling while paging fails with the context error and leaves the run in place.
	req = truncatedRunScript(repeat('h', syncRunOutputPageBytes), []byte("tail"), http.StatusOK)
	req.ctxErrAt = 1 // the sync run itself succeeds, the first page read observes the cancellation
	client = &AppMeshClient{req: req}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err = client.RunAppSyncWithContext(ctx, Application{Name: "app1"}, 10, 20, SyncRunOptions{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled))
	assert.Equal(t, []string{"POST /appmesh/app/syncrun", "GET /appmesh/app/run-abc/output"}, req.paths())
}

// The real HTTP transport carries the truncation headers through to the shared layer.
func TestRunAppSyncTruncatedOverHTTPTransport(t *testing.T) {
	page := repeat('p', syncRunOutputPageBytes)
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("X-Exit-Code", "0")
			w.Header().Set("X-Output-Truncated", "1")
			w.Header().Set("X-Output-Position", fmt.Sprintf("%d", len(page)))
			w.Header().Set("X-App-Name", "run-abc")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write(page)
		case http.MethodGet:
			if r.URL.Query().Get("stdout_position") != strconv.Itoa(len(page)) {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("tail"))
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()

	client, err := NewHTTPClient(Option{AppMeshURI: server.URL})
	require.NoError(t, err)
	defer client.Close()

	_, out, err := client.RunAppSync(Application{Name: "app1"}, 10, 20)
	require.NoError(t, err)
	assert.Equal(t, string(page)+"tail", out)
	require.Len(t, calls, 3)
	assert.Equal(t, fmt.Sprintf("GET /appmesh/app/run-abc/output?stdout_position=%d", len(page)), calls[1])
	assert.Equal(t, "DELETE /appmesh/app/run-abc", calls[2])
}
