package appmesh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"go.uber.org/atomic"
)

// Requester defines the interface for making HTTP requests.
type Requester interface {
	Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte,
		http.Header, error)
	SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string,
		body io.Reader) (int, []byte, http.Header, error)
	Close()

	handleTokenUpdate(token string)
	setToken(token string)
	getAccessToken() string
	setTokenProvider(provider TokenProvider)
	getTokenProvider() TokenProvider
	setForwardTo(forwardTo string)
	getForwardTo() string
	setRequestSigner(signer *requestSigner)
}

// tokenState carries the per-requester static token and forwarding target
// together with their accessors, shared by the HTTP, TCP and WSS requesters.
type tokenState struct {
	forwardingHost atomic.String
	token          atomic.String
	requestSigner  atomic.Pointer[requestSigner] // opt-in HMAC request signing (nil = off)
	tokenProviderHolder
	refreshMu sync.Mutex // serializes 401-triggered refreshes across concurrent requests
}

func (s *tokenState) handleTokenUpdate(token string) {
	s.token.Store(token)
}

// setToken stores a static token and detaches any provider (mirrors Python
// set_bearer_token).
func (s *tokenState) setToken(token string) {
	s.token.Store(token)
	s.setTokenProvider(nil)
}

// getAccessToken consults the attached provider first; it wins over the
// static in-memory token. A provider error yields an empty token.
func (s *tokenState) getAccessToken() string {
	if provider := s.getTokenProvider(); provider != nil {
		token, err := provider.AccessToken()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(token)
	}
	return s.token.Load()
}

// refreshRejectedToken performs the single 401 refresh: the provider replaces
// the rejected token. Concurrent 401s are serialized; when another request
// already rotated the token while waiting, that token is reused instead of
// refreshing twice (provider-side locking is still expected, as in the Python SDK).
func (s *tokenState) refreshRejectedToken(provider TokenProvider, rejectedToken string) (string, error) {
	s.refreshMu.Lock()
	newToken, err := provider.AccessToken()
	if err == nil && newToken != "" && strings.TrimSpace(newToken) != rejectedToken {
		// A concurrent request already refreshed; reuse its token.
	} else {
		newToken, err = provider.RefreshAccessToken(rejectedToken)
	}
	s.refreshMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("token provider failed to refresh a rejected access token: %w", err)
	}
	newToken = strings.TrimSpace(newToken)
	if newToken == "" {
		return "", fmt.Errorf("token provider returned an empty access token on refresh")
	}
	return newToken, nil
}

func (s *tokenState) setForwardTo(forwardTo string) {
	s.forwardingHost.Store(forwardTo)
}

func (s *tokenState) getForwardTo() string {
	return s.forwardingHost.Load()
}

// setRequestSigner attaches (nil detaches) the opt-in HMAC request signer.
// A nil keyID clears signing; the secret stays private to the signer.
func (s *tokenState) setRequestSigner(signer *requestSigner) {
	if signer == nil || signer.keyID == "" {
		s.requestSigner.Store(nil)
		return
	}
	s.requestSigner.Store(signer)
}

func (s *tokenState) getRequestSigner() *requestSigner {
	return s.requestSigner.Load()
}

// HTTP Request executor
type HTTPRequester struct {
	httpClient *HTTPConnection
	baseURL    url.URL

	tokenState
}

// REST request
func (h *HTTPRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string,
	body io.Reader) (int, []byte, http.Header, error) {
	return h.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the REST request with the provided context controlling cancellation.
//
// When a refresh-capable TokenProvider is attached and the caller did not set an
// explicit Authorization header, a 401 triggers exactly one RefreshAccessToken
// call and one request replay (mirroring the Python SDK); a second 401 is
// returned like any other status and surfaced by the client as an *APIError.
func (h *HTTPRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	_, callerAuth := headers[headerAuthorization]
	provider := h.getTokenProvider()
	refreshable := provider != nil && provider.CanRefresh() && !callerAuth

	token := ""
	if !callerAuth {
		var err error
		token, err = h.resolveAccessToken()
		if err != nil {
			return 0, nil, nil, err
		}
	}
	// Snapshot for the 401 gate below: a signed request only refreshes when the
	// server pins the blame on the bearer (shouldRefreshOnUnauthorized).
	signed := h.getRequestSigner() != nil

	// Buffer the body only when a 401 refresh-retry may replay it. Streaming
	// bodies (e.g. the file-upload pipe) are not replayable and keep the
	// single-attempt path.
	var bodyBytes []byte
	replayable := false
	if refreshable {
		if body == nil {
			replayable = true
		} else {
			switch body.(type) {
			case *bytes.Buffer, *bytes.Reader, *strings.Reader:
				var err error
				bodyBytes, err = io.ReadAll(body)
				if err != nil {
					return 0, nil, nil, fmt.Errorf("failed to buffer request body: %w", err)
				}
				replayable = true
			}
		}
	}

	sendBody := body
	if bodyBytes != nil {
		sendBody = bytes.NewReader(bodyBytes)
	}
	resp, err := h.doContext(ctx, method, apiPath, queries, headers, sendBody, token)
	if err != nil {
		return 0, nil, nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized && replayable &&
		shouldRefreshOnUnauthorized(signed, resp.Header.Get("WWW-Authenticate")) {
		resp.Body.Close()
		var retryBody io.Reader
		if body != nil {
			retryBody = bytes.NewReader(bodyBytes)
		}
		resp, err = h.retryWithRefreshedToken(ctx, provider, token, method, apiPath, queries, headers, retryBody)
		if err != nil {
			if resp == nil {
				return 0, nil, nil, err
			}
			return resp.StatusCode, nil, resp.Header, err
		}
	}

	// Ensure response body is always closed
	defer resp.Body.Close()

	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("failed to read response body: %w", err)
	}

	return resp.StatusCode, data, resp.Header, nil
}

// retryWithRefreshedToken performs the single 401 refresh-retry: the provider
// replaces the rejected token and the request is replayed exactly once with it.
func (h *HTTPRequester) retryWithRefreshedToken(ctx context.Context, provider TokenProvider, rejectedToken string,
	method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (*http.Response,
	error) {
	newToken, err := h.refreshRejectedToken(provider, rejectedToken)
	if err != nil {
		return nil, err
	}
	return h.doContext(ctx, method, apiPath, queries, headers, body, newToken)
}

// resolveAccessToken returns the bearer for a request: an attached provider is
// consulted first and wins over the static in-memory token.
func (h *HTTPRequester) resolveAccessToken() (string, error) {
	if provider := h.getTokenProvider(); provider != nil {
		token, err := provider.AccessToken()
		if err != nil {
			return "", fmt.Errorf("token provider failed to supply an access token: %w", err)
		}
		return strings.TrimSpace(token), nil
	}
	return h.token.Load(), nil
}

// getStream performs a GET request and returns the response body as a stream
// without buffering it in memory. The caller must close the returned body.
func (h *HTTPRequester) getStream(apiPath string, queries url.Values, headers map[string]string) (int, io.ReadCloser,
	http.Header, error) {
	token := ""
	if _, callerAuth := headers[headerAuthorization]; !callerAuth {
		var err error
		token, err = h.resolveAccessToken()
		if err != nil {
			return 0, nil, nil, err
		}
	}
	resp, err := h.doContext(context.Background(), http.MethodGet, apiPath, queries, headers, nil, token)
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, resp.Body, resp.Header, nil
}

// sseRequest opens an SSE stream and returns the response body unread; the
// caller must close it. It drops the client's 2-minute timeout: the stream is
// bounded server-side and kept alive by the 15s ping plus the caller's context.
func (h *HTTPRequester) sseRequest(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body []byte) (int, io.ReadCloser, http.Header, error) {
	if h.httpClient == nil {
		return 0, nil, nil, fmt.Errorf("http client is nil")
	}
	token := ""
	if _, callerAuth := headers[headerAuthorization]; !callerAuth {
		var err error
		token, err = h.resolveAccessToken()
		if err != nil {
			return 0, nil, nil, err
		}
	}
	// buildRequest applies the client-wide forward target like any other request;
	// only the engine's own listener refuses a stream (400), reported below.
	forwarded := false
	if _, set := headers[headerTargetHost]; !set {
		forwarded = h.forwardingHost.Load() != ""
	} else if headers[headerTargetHost] != "" {
		forwarded = true
	}
	req, err := h.buildRequest(ctx, method, apiPath, queries, headers, bytes.NewReader(body), token)
	if err != nil {
		return 0, nil, nil, err
	}
	// Share the transport (connection pool) but drop the overall deadline.
	streamClient := *h.httpClient.Client
	streamClient.Timeout = 0
	resp, err := streamClient.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.StatusCode == http.StatusBadRequest && forwarded {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return 0, nil, nil, newAPIErrorText(opForPath(apiPath), resp.StatusCode, string(raw),
			fmt.Sprintf("%s failed with status %d: %s; the endpoint %s does not stream through node forwarding"+
				" (X-Target-Host): use the agent REST listener (default port 6060) as AppMeshURI",
				opForPath(apiPath), resp.StatusCode, strings.TrimSpace(string(raw)), h.baseURL.Redacted()))
	}
	return resp.StatusCode, resp.Body, resp.Header, nil
}

// opForPath names a streaming route in error messages the way the streaming
// callers do ("run task stream", "follow output").
func opForPath(apiPath string) string {
	if strings.HasSuffix(apiPath, "/task/stream") {
		return "run task stream"
	}
	return "follow output"
}

// doContext builds and executes the HTTP request, returning the response with
// its body unread. Callers own resp.Body and must close it.
func (h *HTTPRequester) doContext(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader, token string) (*http.Response, error) {
	// Validate inputs
	if h.httpClient == nil {
		return nil, fmt.Errorf("http client is nil")
	}
	req, err := h.buildRequest(ctx, method, apiPath, queries, headers, body, token)
	if err != nil {
		return nil, err
	}

	// Execute request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	return resp, nil
}

// buildRequest constructs the signed request as it goes on the wire (bearer,
// forwarding, custom headers, opt-in signature); doContext executes it on the
// shared client, sseRequest on a deadline-free copy (streams outlive it).
func (h *HTTPRequester) buildRequest(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader, token string) (*http.Request, error) {
	// Snapshot the signer once: the query encoding below and the signing step
	// at the end must observe the same toggle state — reading it twice could
	// pair a percent-only encoded query from one state with a signature (or its
	// absence) from another under a concurrent toggle.
	signer := h.getRequestSigner()

	// Build URL
	u := h.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		if signer != nil {
			// The daemon percent-decodes the query with '+' kept literal, so a
			// signed request must never rely on '+'-for-space: the decoded
			// values the daemon verifies must equal the values signed below.
			u.RawQuery = encodeQueryPercentOnly(queries)
		} else {
			u.RawQuery = queries.Encode()
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}

	// Apply implicit auth only when the caller did not provide an explicit Authorization header.
	if _, hasAuth := headers[headerAuthorization]; !hasAuth {
		if token != "" {
			req.Header.Set(headerAuthorization, headerBearerSpace+token)
		}
	}

	// Set forwarding header. A caller-supplied X-Target-Host header overrides the
	// client-wide forward target for this request only ("" disables forwarding).
	// Sent as given: a bare host is resolved to the server's own service port; the
	// client-side port may be a host-side mapping that does not exist on the target.
	forwardingHost, forwardOverridden := headers[headerTargetHost]
	if !forwardOverridden {
		forwardingHost = h.forwardingHost.Load()
	}
	if forwardingHost != "" {
		req.Header.Set(headerTargetHost, forwardingHost)
	}

	// Set default headers
	req.Header.Set(userAgentHeaderName, userAgent)

	// Set custom headers (X-Target-Host was already applied, normalized, above)
	for k, v := range headers {
		if k == headerTargetHost {
			continue
		}
		req.Header.Set(k, v)
	}

	// Opt-in request signature (X-Request-Key/X-Timestamp/X-Nonce/X-Signature),
	// applied last so it signs the request exactly as it goes on the wire.
	// Uses the signer snapshot taken above, so encoding and signing stay paired.
	if err := signHTTPRequest(req, queries, signer); err != nil {
		return nil, err
	}

	return req, nil
}

// Close closes the HTTP client and its idle connections.
func (h *HTTPRequester) Close() {
	if h.httpClient != nil {
		h.httpClient.CloseIdleConnections()
	}
}

// waitDemuxResponse waits for a demuxer-routed response, unblocking on context
// cancellation or demuxer shutdown (transport read error) instead of hanging on
// a channel the dead readLoop can never deliver to.
func waitDemuxResponse(ctx context.Context, ch chan *Response, demux *MessageDemuxer) (*Response, error) {
	select {
	case resp, ok := <-ch:
		if !ok || resp == nil {
			return nil, fmt.Errorf("connection closed while waiting for response")
		}
		return resp, nil
	case <-demux.stopCh:
		// The register may have raced with stop() (landed in the fresh pending
		// map), so ch is never closed; drain a response delivered just before.
		select {
		case resp, ok := <-ch:
			if ok && resp != nil {
				return resp, nil
			}
		default:
		}
		return nil, fmt.Errorf("connection closed while waiting for response")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TCPRequester handles TCP requests.
type TCPRequester struct {
	*TCPConnection
	baseURL url.URL

	tokenState
	psk       []byte
	demuxerMu sync.Mutex
	demuxer   *MessageDemuxer

	// Connection parameters retained so a later request can transparently
	// re-establish a connection lost to a transport error (as the Python SDK does).
	connectAddr      net.Addr
	plainTransport   bool // reconnect without TLS (daemon SSL.SSLEnabled=false)
	sslClientCert    string
	sslClientCertKey string
	sslCAFile        string

	// restBase is the REST listener the SSE side channel dials for local streams;
	// from Option.RestPort.
	restBase url.URL
	// agentBase is the agent REST listener (Option.AgentPort) a forwarded SSE side
	// channel dials: the engine listener does not relay X-Target-Host on streams.
	agentBase url.URL
}

// Send performs a REST-like request over TCP.
func (t *TCPRequester) Send(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int,
	[]byte, http.Header, error) {
	return t.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the REST-like request over TCP with the provided context.
// The context cancels the send and, when the demuxer is active (EnableConcurrency/
// Subscribe), the response wait. In legacy synchronous mode the blocking read is
// not cancelable; use Close() to abort.
//
// When a refresh-capable TokenProvider is attached and the caller did not set an
// explicit Authorization header, a 401 triggers exactly one refresh and replay
// (mirroring the Python SDK and the HTTP requester).
func (t *TCPRequester) SendContext(ctx context.Context, method, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	u := t.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	// Buffer the body only when a 401 refresh-retry may replay it (TCP bodies are
	// small; the file-upload path sends no body here).
	_, callerAuth := headers[headerAuthorization]
	provider := t.getTokenProvider()
	refreshable := provider != nil && provider.CanRefresh() && !callerAuth
	var bodyBytes []byte
	if refreshable && body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to buffer request body: %w", err)
		}
	}

	resp, err := t.sendWithRetry(ctx, method, u, queries, headers, body, bodyBytes, refreshable, provider)
	if err != nil {
		if resp != nil {
			// Refresh failed after a 401: surface the original response with the error.
			return resp.HTTPStatus, resp.Body, toHTTPHeader(resp.Headers), err
		}
		return 0, nil, nil, err
	}

	return resp.HTTPStatus, resp.Body, toHTTPHeader(resp.Headers), nil
}

// toHTTPHeader adapts the framed response's plain string map to net/http's
// http.Header, as the Requester contract returns it.
func toHTTPHeader(headers map[string]string) http.Header {
	out := make(http.Header)
	for key, value := range headers {
		out.Add(key, value)
	}
	return out
}

// hydrateFramedRequest copies an HTTP-shaped request into the framed wire
// Request: path, method, first-value headers and query, and the body (except
// on the file-upload path, which streams through the socket side channel).
// clientAddress is the transport's local address.
func hydrateFramedRequest(data *Request, req *http.Request, clientAddress string) error {
	data.RequestURI = req.URL.Path
	data.HTTPMethod = req.Method
	data.ClientAddress = clientAddress
	for key, values := range req.Header {
		if len(values) > 0 {
			data.Headers[key] = values[0] // only first value
		}
	}
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			data.Query[key] = values[0]
		}
	}

	if data.RequestURI != restPathUpload && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		if len(bodyBytes) > 0 {
			data.Body = bodyBytes
		}
	}
	return nil
}

// sendFramedRequest sends the serialized frame and waits for its response:
// through the demuxer when one is running (registered BEFORE the send so the
// response cannot arrive and be dropped before the channel is in place), or
// through a direct blocking read in legacy synchronous mode.
func sendFramedRequest(ctx context.Context, demux *MessageDemuxer, uuid string, buf []byte,
	send func(context.Context, []byte) error, readResponse func() ([]byte, error)) (*Response, error) {
	if demux != nil && demux.isRunning() {
		ch := demux.registerRequest(uuid)
		defer demux.unregisterRequest(uuid)

		if err := send(ctx, buf); err != nil {
			return nil, err
		}

		return waitDemuxResponse(ctx, ch, demux)
	}

	if err := send(ctx, buf); err != nil {
		return nil, err
	}

	respData, err := readResponse()
	if err != nil {
		return nil, err
	}

	respMsg := &Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}

// framedHeaderGet reads a framed header case-insensitively (the daemon forwards its original casing).
func framedHeaderGet(headers map[string]string, name string) string {
	if v, ok := headers[name]; ok {
		return v
	}
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// idempotentMethod reports whether replaying the request cannot apply its
// effect twice on the server.
func idempotentMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

// replayableRequest reports whether a request that failed on a broken
// connection may be replayed: only an idempotent method with no unreplayable
// body, and never after the caller's context was canceled.
func replayableRequest(ctx context.Context, method string, body io.Reader, bodyBytes []byte) bool {
	if ctx.Err() != nil {
		return false
	}
	if !idempotentMethod(method) {
		return false
	}
	return body == nil || bodyBytes != nil
}

// sendWithRetry issues the TCP request, replaying it exactly once with a
// refreshed bearer when the first attempt returns 401 and a refresh-capable
// provider is attached, and exactly once on a fresh connection when an
// idempotent request found its connection closed by the server.
func (t *TCPRequester) sendWithRetry(ctx context.Context, method string, u url.URL, queries url.Values,
	headers map[string]string, body io.Reader, bodyBytes []byte, refreshable bool, provider TokenProvider) (*Response,
	error) {
	signed := t.getRequestSigner() != nil
	transportRetried := false
	authRetried := false
	for {
		bodyReader := body
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, err
		}

		_, hasAuth := headers[headerAuthorization]
		token := t.getAccessToken()
		if !hasAuth && token != "" {
			req.Header.Set(headerAuthorization, headerBearerSpace+token)
		}

		// A caller-supplied X-Target-Host header overrides the client-wide forward
		// target for this request only ("" disables forwarding). Sent as given: a bare
		// host is resolved to the server's own service port.
		forwardingHost, forwardOverridden := headers[headerTargetHost]
		if !forwardOverridden {
			forwardingHost = t.forwardingHost.Load()
		}
		if forwardingHost != "" {
			req.Header.Set(headerTargetHost, forwardingHost)
		}
		req.Header.Set(userAgentHeaderName, userAgentTCP)
		for k, v := range headers {
			if k == headerTargetHost {
				continue // already applied, normalized, above
			}
			req.Header.Set(k, v)
		}

		wasConnected := t.TCPConnection.Connected()
		resp, err := t.request(req)
		if err != nil {
			// The daemon idle-closes pooled connections; the transport closes
			// itself on the first I/O error, so a connection that was live and
			// is now closed was stale. Replay idempotent requests once.
			if !transportRetried && wasConnected && !t.TCPConnection.Connected() &&
				replayableRequest(req.Context(), method, body, bodyBytes) {
				transportRetried = true
				continue
			}
			return nil, err
		}
		if resp.HTTPStatus == http.StatusUnauthorized && refreshable && !authRetried &&
			shouldRefreshOnUnauthorized(signed, framedHeaderGet(resp.Headers, "WWW-Authenticate")) {
			if newToken, rerr := t.refreshRejectedToken(provider, token); rerr != nil {
				// Refresh failed: surface the original 401 response with the error.
				return resp, rerr
			} else if newToken != token {
				authRetried = true
				continue // replay once with the refreshed bearer
			}
			return resp, nil
		}
		return resp, nil
	}
}

// Close closes the TCP connection.
func (t *TCPRequester) Close() {
	t.demuxerMu.Lock()
	if t.demuxer != nil {
		t.demuxer.stop()
		t.demuxer = nil
	}
	t.demuxerMu.Unlock()
	if t.TCPConnection != nil {
		t.TCPConnection.Close()
	}
}

// request sends a request over TCP.
func (t *TCPRequester) request(req *http.Request) (*Response, error) {
	if err := t.ensureConnected(); err != nil {
		return nil, err
	}
	data := NewRequest()
	if err := hydrateFramedRequest(data, req, t.ClientAddress()); err != nil {
		return nil, err
	}
	data.Headers[userAgentHeaderName] = userAgentTCP

	// Sign after the UUID and every header exist, and before the request is framed.
	if err := applyProcessProof(data, t.psk); err != nil {
		return nil, err
	}
	// Opt-in HMAC request signature: the four headers go into the frame header
	// map; the framed uuid serves as the nonce.
	applyRequestSignature(data, t.getRequestSigner())

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	// Receive the response directly (legacy synchronous mode), bounded by ctx.
	return sendFramedRequest(req.Context(), t.getDemuxer(), data.UUID, buf, t.SendMessage,
		func() ([]byte, error) { return t.ReadMessageContext(req.Context()) })
}

func (t *TCPRequester) enableDemuxer() {
	t.demuxerMu.Lock()
	defer t.demuxerMu.Unlock()
	// Replace a stopped demuxer rather than keeping it. stop() (any readLoop error, e.g. a
	// daemon restart) leaves the object in place but not running, and every later request
	// would then silently fall back to the uncancelable legacy read path for the lifetime
	// of the process.
	if t.demuxer != nil && t.demuxer.isRunning() {
		return
	}
	if err := t.ensureConnected(); err != nil {
		logf("enableDemuxer: connect failed: %v", err)
		return
	}
	t.demuxer = newMessageDemuxer(t.TCPConnection.ReadMessage)
	t.demuxer.start()
}

// ensureConnected re-establishes the connection when a previous transport error
// closed it, mirroring the Python SDK's connect-on-next-request recovery: a
// plain redial for a plaintext daemon, TLS otherwise.
func (t *TCPRequester) ensureConnected() error {
	if t.TCPConnection.Connected() {
		return nil
	}
	if t.connectAddr == nil {
		return fmt.Errorf("not connected")
	}
	if t.plainTransport {
		return t.ConnectPlain(t.connectAddr)
	}
	return t.Connect(t.connectAddr, t.sslClientCert, t.sslClientCertKey, t.sslCAFile)
}

func (t *TCPRequester) getDemuxer() *MessageDemuxer {
	t.demuxerMu.Lock()
	defer t.demuxerMu.Unlock()
	return t.demuxer
}

// WSSRequester handles REST-like requests over a WSS transport.
type WSSRequester struct {
	*WSSConnection
	baseURL url.URL

	tokenState
	psk            []byte
	demuxerMu      sync.Mutex
	demuxer        *MessageDemuxer
	connectMu      sync.Mutex
	connectedToken string
	sslClientCert  string
	sslClientKey   string
	sslCAFile      string

	// agentBase is the agent REST listener (Option.AgentPort) a forwarded SSE side
	// channel dials instead of the engine listener behind the WebSocket.
	agentBase url.URL
}

// ensureConnected (re)establishes the WebSocket before a request is sent.
// A live session is kept across token rotations (the upgrade pinned its
// principal; closing it would kill the demuxer reader and every active
// subscription — the refreshed bearer applies on the next natural reconnect,
// mirroring the Python SDK). A session established WITHOUT a bearer pins no
// principal, so it is rebuilt once a token becomes available.
func (w *WSSRequester) ensureConnected() error {
	token := w.getAccessToken()
	// Snapshot demuxer state before taking connectMu: enableDemuxer holds
	// demuxerMu while calling into here (connectMu), so connectMu must never
	// wait on demuxerMu in return.
	demuxerActive := false
	if d := w.getDemuxer(); d != nil && d.isRunning() {
		demuxerActive = true
	}
	w.connectMu.Lock()
	defer w.connectMu.Unlock()
	if w.WSSConnection.Connected() {
		if w.connectedToken != "" || token == "" || demuxerActive {
			return nil
		}
		// Anonymous session, bearer now available: upgrade it. A running demuxer
		// (checked above) defers the upgrade to the next natural reconnect —
		// closing its socket would broadcast a spurious disconnect to every
		// active subscription.
		w.WSSConnection.Close()
	}
	if err := w.WSSConnection.Connect(&w.baseURL, w.sslClientCert, w.sslClientKey, w.sslCAFile, token); err != nil {
		return err
	}
	w.connectedToken = token
	return nil
}

// Send performs the request over WSS.
func (w *WSSRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string,
	body io.Reader) (int, []byte, http.Header, error) {
	return w.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the request over WSS with the provided context.
// The context cancels the send and, when the demuxer is active (EnableConcurrency/
// Subscribe), the response wait. In legacy synchronous mode the blocking read is
// not cancelable; use Close() to abort.
//
// When a refresh-capable TokenProvider is attached and the caller did not set an
// explicit Authorization header, a 401 triggers exactly one refresh and replay
// (mirroring the Python SDK and the HTTP requester).
func (w *WSSRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	u := w.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	_, callerAuth := headers[headerAuthorization]
	provider := w.getTokenProvider()
	refreshable := provider != nil && provider.CanRefresh() && !callerAuth
	var bodyBytes []byte
	if refreshable && body != nil {
		var err error
		bodyBytes, err = io.ReadAll(body)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to buffer request body: %w", err)
		}
	}

	resp, err := w.sendWithRetry(ctx, method, u, queries, headers, body, bodyBytes, refreshable, provider)
	if err != nil {
		if resp != nil {
			return resp.HTTPStatus, resp.Body, toHTTPHeader(resp.Headers), err
		}
		return 0, nil, nil, err
	}

	return resp.HTTPStatus, resp.Body, toHTTPHeader(resp.Headers), nil
}

// sendWithRetry issues the WSS request, replaying it exactly once with a
// refreshed bearer when the first attempt returns 401 and a refresh-capable
// provider is attached.
func (w *WSSRequester) sendWithRetry(ctx context.Context, method string, u url.URL, queries url.Values,
	headers map[string]string, body io.Reader, bodyBytes []byte, refreshable bool, provider TokenProvider) (*Response,
	error) {
	signed := w.getRequestSigner() != nil
	for attempt := 0; ; attempt++ {
		bodyReader := body
		if bodyBytes != nil {
			bodyReader = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
		if err != nil {
			return nil, err
		}

		token := w.getAccessToken()

		// A caller-supplied X-Target-Host header overrides the client-wide forward
		// target for this request only ("" disables forwarding). Sent as given: a bare
		// host is resolved to the server's own service port.
		forwardingHost, forwardOverridden := headers[headerTargetHost]
		if !forwardOverridden {
			forwardingHost = w.forwardingHost.Load()
		}
		if forwardingHost != "" {
			req.Header.Set(headerTargetHost, forwardingHost)
			// The target receives a new TCP request and validates the bearer again.
			// The gateway checks that it resolves to the WSS session principal.
			if _, hasAuth := headers[headerAuthorization]; !hasAuth && token != "" {
				req.Header.Set(headerAuthorization, headerBearerSpace+token)
			}
		}
		req.Header.Set(userAgentHeaderName, userAgentWSS)
		for k, v := range headers {
			if k == headerTargetHost {
				continue // already applied, normalized, above
			}
			req.Header.Set(k, v)
		}

		resp, err := w.request(req)
		if err != nil {
			return nil, err
		}
		if resp.HTTPStatus == http.StatusUnauthorized && refreshable && attempt == 0 &&
			shouldRefreshOnUnauthorized(signed, framedHeaderGet(resp.Headers, "WWW-Authenticate")) {
			if newToken, rerr := w.refreshRejectedToken(provider, token); rerr != nil {
				// Refresh failed: surface the original 401 response with the error.
				return resp, rerr
			} else if newToken != token {
				continue // replay once with the refreshed bearer
			}
			return resp, nil
		}
		return resp, nil
	}
}

// Close closes the underlying WSS connection.
func (w *WSSRequester) Close() {
	w.demuxerMu.Lock()
	if w.demuxer != nil {
		w.demuxer.stop()
		w.demuxer = nil
	}
	w.demuxerMu.Unlock()
	if w.WSSConnection != nil {
		w.WSSConnection.Close()
	}
}

// request serializes an internal Request, sends it over WSSConnection and waits for Response.
func (w *WSSRequester) request(req *http.Request) (*Response, error) {
	if err := w.ensureConnected(); err != nil {
		return nil, err
	}
	data := NewRequest()
	if err := hydrateFramedRequest(data, req, w.ClientAddress()); err != nil {
		return nil, err
	}
	data.Headers[userAgentHeaderName] = userAgentWSS

	// Sign after the UUID and every header exist, and before the frame is sent.
	if err := applyProcessProof(data, w.psk); err != nil {
		return nil, err
	}
	// Opt-in HMAC request signature: the four headers go into the frame header
	// map; the framed uuid serves as the nonce.
	applyRequestSignature(data, w.getRequestSigner())

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	return sendFramedRequest(req.Context(), w.getDemuxer(), data.UUID, buf, w.SendMessage, w.ReadMessage)
}

func (w *WSSRequester) enableDemuxer() {
	w.demuxerMu.Lock()
	if w.demuxer != nil && w.demuxer.isRunning() {
		w.demuxerMu.Unlock()
		return
	}
	w.demuxerMu.Unlock()

	// Connect WITHOUT holding demuxerMu: ensureConnected snapshots demuxer state
	// (getDemuxer takes demuxerMu) and the sync.Mutex is not reentrant.
	// Connect before starting the reader so the demuxer reads a live socket from
	// its first frame (a reader started against an unconnected transport would
	// error out immediately and broadcast a spurious disconnect).
	if err := w.ensureConnected(); err != nil {
		logf("enableDemuxer: connect failed: %v", err)
		return
	}

	w.demuxerMu.Lock()
	defer w.demuxerMu.Unlock()
	// Re-check: another enableDemuxer may have won the race while the lock was
	// released during the connect.
	if w.demuxer != nil && w.demuxer.isRunning() {
		return
	}
	w.demuxer = newMessageDemuxer(w.WSSConnection.ReadMessage)
	w.demuxer.start()
}

func (w *WSSRequester) getDemuxer() *MessageDemuxer {
	w.demuxerMu.Lock()
	defer w.demuxerMu.Unlock()
	return w.demuxer
}
