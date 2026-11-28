package appmesh

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sseTaskWire = "event: final\ndata: {\"result\":\"node-b\"}\n\nevent: end\ndata: {\"reason\":\"final\"}\n\n"

// streamRecorder is a stub listener that records every stream request it serves
// (one entry per listener, so the test can tell the agent port from the engine port).
type streamRecorder struct {
	mu      sync.Mutex
	paths   []string
	hosts   map[string]string // request path -> X-Target-Host ("" when absent)
	auth    map[string]string // request path -> Authorization
	signKey map[string]string // request path -> X-Request-Key
	status  int
}

func newStreamRecorder(status int) *streamRecorder {
	return &streamRecorder{hosts: map[string]string{}, auth: map[string]string{}, signKey: map[string]string{},
		status: status}
}

func (r *streamRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.paths = append(r.paths, req.URL.Path+"?"+req.URL.RawQuery+" body="+string(body))
	r.hosts[req.URL.Path] = req.Header.Get(headerTargetHost)
	r.auth[req.URL.Path] = req.Header.Get(headerAuthorization)
	r.signKey[req.URL.Path] = req.Header.Get(headerRequestKey)
	r.mu.Unlock()
	if r.status != http.StatusOK {
		w.WriteHeader(r.status)
		_, _ = w.Write([]byte("stub refusal"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = w.Write([]byte(sseTaskWire))
}

func (r *streamRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.paths)
}

func drainTaskStream(t *testing.T, stream *SseStream, err error) string {
	t.Helper()
	if err != nil {
		return "ERR: " + err.Error()
	}
	defer stream.Close()
	for {
		if _, err := stream.Next(); err != nil {
			break
		}
	}
	return "result=" + stream.End().Result
}

// Option.ForwardTo must reach the streaming calls on every transport. Before
// this coverage the HTTP requester cancelled the target for streams and the
// TCP/WSS side channels never carried it, so RunTaskStream ran on the local
// node while RunTask on the same client ran on the target.
func TestRunTaskStreamCarriesForwardTargetOnHTTPTransport(t *testing.T) {
	agent := newStreamRecorder(http.StatusOK)
	srv := httptest.NewTLSServer(agent)
	defer srv.Close()

	c, err := NewHTTPClient(Option{AppMeshURI: srv.URL, JWTToken: "token", SSLTrustedCA: nil,
		InsecureSkipVerify: true, ForwardTo: "appmesh_slave1"})
	require.NoError(t, err)
	defer c.Close()
	stream, err := c.RunTaskStream("worker", "payload", 30)
	assert.Equal(t, "result=node-b", drainTaskStream(t, stream, err))
	assert.Equal(t, "appmesh_slave1", agent.hosts["/appmesh/app/worker/task/stream"])
	assert.Equal(t, "Bearer token", agent.auth["/appmesh/app/worker/task/stream"])
}

// An explicit TCP port in the target lands a forwarded stream on a listener without
// stream routes (404/405); the error must say which target form to use.
func TestForwardedStreamToTCPPortNamesTheFix(t *testing.T) {
	agent := newStreamRecorder(http.StatusMethodNotAllowed)
	srv := httptest.NewTLSServer(agent)
	defer srv.Close()

	c, err := NewHTTPClient(Option{AppMeshURI: srv.URL, JWTToken: "token", InsecureSkipVerify: true,
		ForwardTo: "appmesh_slave1:6062"})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.RunTaskStream("worker", "payload", 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `"appmesh_slave1:6062" names the target's TCP listener`)
	assert.Contains(t, err.Error(), "bare host")
}

// The agent REST listener answers 502 for a target it cannot reach: a forwarded
// stream to a bad node must fail, never fall back to a local stream.
func TestRunTaskStreamBadTargetFailsOnHTTPTransport(t *testing.T) {
	agent := newStreamRecorder(http.StatusBadGateway)
	srv := httptest.NewTLSServer(agent)
	defer srv.Close()

	c, err := NewHTTPClient(Option{AppMeshURI: srv.URL, JWTToken: "token", InsecureSkipVerify: true,
		ForwardTo: "appmesh_nosuch"})
	require.NoError(t, err)
	defer c.Close()
	stream, err := c.RunTaskStream("worker", "payload", 30)
	require.Error(t, err)
	assert.Nil(t, stream)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusBadGateway, apiErr.StatusCode)
}

// An AppMeshURI on the engine's own listener refuses a forwarded stream with
// 400; the error must name the limitation and the way out.
func TestForwardedStreamOnEngineListenerNamesTheLimitation(t *testing.T) {
	engine := newStreamRecorder(http.StatusBadRequest)
	srv := httptest.NewTLSServer(engine)
	defer srv.Close()

	c, err := NewHTTPClient(Option{AppMeshURI: srv.URL, JWTToken: "token", InsecureSkipVerify: true,
		ForwardTo: "appmesh_slave1"})
	require.NoError(t, err)
	defer c.Close()
	_, err = c.RunTaskStream("worker", "payload", 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not stream through node forwarding")
	assert.Contains(t, err.Error(), "agent REST listener")
	assert.Contains(t, err.Error(), "6060")
	assert.Equal(t, "appmesh_slave1", engine.hosts["/appmesh/app/worker/task/stream"])
}

// A framed transport streams over a direct HTTPS side channel. A forwarded
// stream must dial the agent REST listener with X-Target-Host; a local one keeps
// the engine listener and sends no target.
func TestFramedSseSideChannelDialsAgentPortWhenForwarded(t *testing.T) {
	engine := newStreamRecorder(http.StatusOK)
	engineSrv := httptest.NewTLSServer(engine)
	defer engineSrv.Close()
	agent := newStreamRecorder(http.StatusOK)
	agentSrv := httptest.NewTLSServer(agent)
	defer agentSrv.Close()
	engineURL, _ := url.Parse(engineSrv.URL)
	agentURL, _ := url.Parse(agentSrv.URL)

	type forwarder interface {
		sseRequester
		setForwardTo(string)
	}
	requesters := map[string]forwarder{}
	tcp := &TCPRequester{TCPConnection: NewTCPConnection(), baseURL: *engineURL, restBase: *engineURL,
		agentBase: *agentURL}
	tcp.setToken("token")
	requesters["tcp"] = tcp
	wss := &WSSRequester{WSSConnection: NewWSSConnection(), baseURL: *engineURL, agentBase: *agentURL}
	wss.setToken("token")
	requesters["wss"] = wss

	for name, req := range requesters {
		t.Run(name+" forwarded", func(t *testing.T) {
			req.setForwardTo("appmesh_slave1")
			engineBefore, agentBefore := engine.count(), agent.count()
			code, body, _, err := req.sseRequest(context.Background(), http.MethodPost, "/appmesh/app/worker/task/stream",
				url.Values{"timeout": {"30"}}, nil, []byte("payload"))
			require.NoError(t, err)
			defer body.Close()
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, agentBefore+1, agent.count(), "the agent listener serves a forwarded stream")
			assert.Equal(t, engineBefore, engine.count(), "the engine listener is not dialled for a forwarded stream")
			assert.Equal(t, "appmesh_slave1", agent.hosts["/appmesh/app/worker/task/stream"])
			assert.Equal(t, "Bearer token", agent.auth["/appmesh/app/worker/task/stream"])
			agent.mu.Lock()
			assert.Contains(t, agent.paths[agentBefore], "?timeout=30", "the query is kept on the agent hop")
			assert.Contains(t, agent.paths[agentBefore], "body=payload", "the body is kept on the agent hop")
			agent.mu.Unlock()
		})
		t.Run(name+" local", func(t *testing.T) {
			req.setForwardTo("")
			engineBefore, agentBefore := engine.count(), agent.count()
			code, body, err := openRaw(req)
			require.NoError(t, err)
			defer body.Close()
			assert.Equal(t, http.StatusOK, code)
			assert.Equal(t, engineBefore+1, engine.count(), "a local stream keeps the engine listener")
			assert.Equal(t, "", engine.hosts["/appmesh/app/worker/output/stream"], "no target without forwarding")
			assert.Equal(t, agentBefore, agent.count(), "the agent listener is untouched")
		})
	}
}

// openRaw performs a GET output stream through the side channel.
func openRaw(req sseRequester) (int, io.ReadCloser, error) {
	code, body, _, err := req.sseRequest(context.Background(), http.MethodGet, "/appmesh/app/worker/output/stream",
		url.Values{"follow": {"false"}}, nil, nil)
	return code, body, err
}

// A per-request X-Target-Host override ("" disables) wins over the client-wide
// target on the side channel too, like on framed requests.
func TestFramedSseSideChannelHeaderOverride(t *testing.T) {
	agent := newStreamRecorder(http.StatusOK)
	srv := httptest.NewTLSServer(agent)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	req := &TCPRequester{TCPConnection: NewTCPConnection(), baseURL: *u, restBase: *u, agentBase: *u}
	req.setToken("token")
	req.setForwardTo("appmesh_slave1")

	_, body, _, err := req.sseRequest(context.Background(), http.MethodPost, "/appmesh/app/worker/task/stream", nil,
		map[string]string{headerTargetHost: ""}, nil)
	require.NoError(t, err)
	body.Close()
	assert.Equal(t, "", agent.hosts["/appmesh/app/worker/task/stream"], "empty override streams locally")

	_, body, _, err = req.sseRequest(context.Background(), http.MethodPost, "/appmesh/app/worker/task/stream", nil,
		map[string]string{headerTargetHost: "appmesh_slave2"}, nil)
	require.NoError(t, err)
	body.Close()
	assert.Equal(t, "appmesh_slave2", agent.hosts["/appmesh/app/worker/task/stream"], "override reaches the agent hop")
}

// Without an agent listener address a forwarded stream must fail loudly rather
// than silently stream from the local node.
func TestForwardedStreamWithoutAgentBaseFailsLoudly(t *testing.T) {
	engine := newStreamRecorder(http.StatusOK)
	srv := httptest.NewTLSServer(engine)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	req := &TCPRequester{TCPConnection: NewTCPConnection(), baseURL: *u, restBase: *u}
	req.setToken("token")
	req.setForwardTo("appmesh_slave1")

	_, _, _, err := req.sseRequest(context.Background(), http.MethodPost, "/appmesh/app/worker/task/stream", nil, nil,
		[]byte("payload"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported by this transport")
	assert.Contains(t, err.Error(), "appmesh_slave1")
	assert.Equal(t, 0, engine.count(), "nothing is streamed locally")
}

// Stream endpoints sign the empty-body hash; the forwarded side-channel request
// carries the signature headers as well as X-Target-Host (the signature does not
// cover the target host, so the same signed headers are valid on the agent hop).
func TestForwardedSseSideChannelIsSigned(t *testing.T) {
	agent := newStreamRecorder(http.StatusOK)
	srv := httptest.NewTLSServer(agent)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	req := &TCPRequester{TCPConnection: NewTCPConnection(), baseURL: *u, restBase: *u, agentBase: *u}
	req.setToken("token")
	req.setForwardTo("appmesh_slave1")
	signer, err := newRequestSigner("key-id", "key-secret")
	require.NoError(t, err)
	req.setRequestSigner(signer)

	_, body, _, err := req.sseRequest(context.Background(), http.MethodPost, "/appmesh/app/worker/task/stream", nil, nil,
		[]byte("payload"))
	require.NoError(t, err)
	body.Close()
	assert.Equal(t, "key-id", agent.signKey["/appmesh/app/worker/task/stream"])
	assert.Equal(t, "appmesh_slave1", agent.hosts["/appmesh/app/worker/task/stream"])
}
