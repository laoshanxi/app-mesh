package appmesh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"go.uber.org/atomic"
)

// Auth endpoints where the server returns a new access_token in the JSON body.
var (
	// Login/auth/totp_validate: apply token only when X-Set-Cookie header is present
	authSetCookiePaths = map[string]bool{
		"/appmesh/login":         true,
		"/appmesh/auth":          true,
		"/appmesh/totp/validate": true,
	}
	// Renew/setup: always apply (client already has an active session)
	authRenewPaths = map[string]bool{
		"/appmesh/token/renew": true,
		"/appmesh/totp/setup":  true,
	}
)

// syncTransportToken extracts and applies token from auth endpoint responses (TCP/WSS).
// HTTP transport relies on Set-Cookie for automatic cookie jar updates.
func syncTransportToken(statusCode int, raw []byte, apiPath string, headers map[string]string, r Requester) {
	if statusCode != http.StatusOK {
		return
	}

	if apiPath == "/appmesh/self/logoff" {
		r.handleTokenUpdate("")
		return
	}

	if authSetCookiePaths[apiPath] {
		if headers == nil || headers[headerJWTSetCookie] != "true" {
			return
		}
	} else if !authRenewPaths[apiPath] {
		return
	}

	var result JWTResponse
	if err := json.Unmarshal(raw, &result); err == nil && result.AccessToken != "" {
		r.handleTokenUpdate(result.AccessToken)
	}
}

// Requester defines the interface for making HTTP requests.
type Requester interface {
	Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error)
	SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error)
	Close()

	handleTokenUpdate(token string)
	setToken(token string)
	getAccessToken() string
	setForwardTo(forwardTo string)
	getForwardTo() string
}

// HTTP Request executor
type HTTPRequester struct {
	httpClient *HTTPConnection
	baseURL    url.URL

	forwardingHost *atomic.String
}

// REST request
func (h *HTTPRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return h.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the REST request with the provided context controlling cancellation.
func (h *HTTPRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	// Validate inputs
	if h.httpClient == nil {
		return 0, nil, nil, fmt.Errorf("http client is nil")
	}

	// Snapshot token before request for change detection
	oldToken := h.getAccessToken()

	// Build URL
	u := h.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	// Apply implicit auth only when the caller did not provide explicit auth headers.
	if _, hasAuth := headers["Authorization"]; !hasAuth {
		if _, hasCsrf := headers[headerCSRFToken]; !hasCsrf {
			if csrfToken := h.httpClient.getCookie(cookieCSRFToken, &h.baseURL); csrfToken != "" {
				req.Header.Set(headerCSRFToken, csrfToken)
			} else if accessToken := h.httpClient.getCookie(cookieToken, &h.baseURL); accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			}
		}
	}

	// Set forwarding header. A caller-supplied X-Target-Host header overrides the
	// client-wide forward target for this request only ("" disables forwarding).
	forwardingHost, forwardOverridden := headers[headerTargetHost]
	if !forwardOverridden {
		forwardingHost = h.forwardingHost.Load()
	}
	if forwardingHost != "" {
		targetHost := forwardingHost
		if !strings.Contains(forwardingHost, ":") {
			port := u.Port()
			if port == "" {
				port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
			}
			targetHost = forwardingHost + ":" + port
		}
		req.Header.Set(headerTargetHost, targetHost)
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

	// Execute request
	resp, err := h.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("request failed: %w", err)
	}

	// Ensure response body is always closed
	defer func() {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
	}()

	// Read response body
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("failed to read response body: %w", err)
	}

	// Auto-detect token changes from server Set-Cookie responses.
	// Re-set via setToken() to ensure persistence: setCookie() adds an
	// Expires fallback when a cookie file is configured, so the
	// persistent-cookiejar treats the entry as persistent even if the
	// server's Set-Cookie omitted Max-Age.
	newToken := h.getAccessToken()
	if newToken != oldToken {
		h.setToken(newToken)
	}

	return resp.StatusCode, data, resp.Header, nil
}

// Close closes the HTTP client and its idle connections.
func (h *HTTPRequester) Close() {
	if h.httpClient != nil {
		h.httpClient.CloseIdleConnections()
	}
}

func (h *HTTPRequester) handleTokenUpdate(token string) {
	h.httpClient.SaveCookies()
}
func (h *HTTPRequester) setToken(token string) {
	h.httpClient.setCookie(cookieToken, token, &h.baseURL)
	h.handleTokenUpdate(token)
}
func (h *HTTPRequester) getAccessToken() string {
	return h.httpClient.getCookie(cookieToken, &h.baseURL)
}
func (h *HTTPRequester) setForwardTo(forwardTo string) {
	h.forwardingHost.Store(forwardTo)
}
func (h *HTTPRequester) getForwardTo() string {
	return h.forwardingHost.Load()
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

	forwardingHost atomic.String
	token          atomic.String
	demuxerMu      sync.Mutex
	demuxer        *MessageDemuxer
}

// Send performs a REST-like request over TCP.
func (t *TCPRequester) Send(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return t.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the REST-like request over TCP with the provided context.
// The context cancels the send and, when the demuxer is active (EnableConcurrency/
// Subscribe), the response wait. In legacy synchronous mode the blocking read is
// not cancelable; use Close() to abort.
func (t *TCPRequester) SendContext(ctx context.Context, method, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	u := t.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	token := t.token.Load()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// A caller-supplied X-Target-Host header overrides the client-wide forward
	// target for this request only ("" disables forwarding).
	forwardingHost, forwardOverridden := headers[headerTargetHost]
	if !forwardOverridden {
		forwardingHost = t.forwardingHost.Load()
	}
	if forwardingHost != "" {
		if strings.Contains(forwardingHost, ":") {
			req.Header.Set(headerTargetHost, forwardingHost)
		} else {
			req.Header.Set(headerTargetHost, forwardingHost+":"+u.Port())
		}
	}
	req.Header.Set(userAgentHeaderName, userAgentTCP)
	for k, v := range headers {
		if k == headerTargetHost {
			continue // already applied, normalized, above
		}
		req.Header.Set(k, v)
	}

	resp, err := t.request(req)
	if err != nil {
		return 0, nil, nil, err
	}

	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	// Auto-sync token from auth endpoint responses
	syncTransportToken(resp.HttpStatus, resp.Body, apiPath, headers, t)

	return resp.HttpStatus, resp.Body, respHeaders, nil
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
	data := NewRequest()
	data.RequestUri = req.URL.Path
	data.HttpMethod = req.Method
	data.ClientAddress = t.ClientAddress()
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

	if data.RequestUri != restPathUpload && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if len(bodyBytes) > 0 {
			if strings.HasSuffix(data.RequestUri, "/task") {
				data.Body = bodyBytes // pass raw data for task request
			} else {
				data.Body = HtmlUnescapeBytes(bodyBytes)
			}
		}
	}

	data.Headers[userAgentHeaderName] = userAgentTCP

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	// When demuxer is active, register BEFORE send so the response cannot arrive
	// and be dropped before the channel is in place. A stopped demuxer (transport
	// read error) never delivers, so fall back to the direct read below.
	demux := t.getDemuxer()
	if demux != nil && demux.isRunning() {
		ch := demux.registerRequest(data.UUID)
		defer demux.unregisterRequest(data.UUID)

		if err := t.SendMessage(req.Context(), buf); err != nil {
			return nil, err
		}

		return waitDemuxResponse(req.Context(), ch, demux)
	}

	if err := t.SendMessage(req.Context(), buf); err != nil {
		return nil, err
	}

	// Receive the response directly (legacy synchronous mode).
	respData, err := t.ReadMessage()
	if err != nil {
		return nil, err
	}

	// Deserialize the response.
	respMsg := &Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}

func (t *TCPRequester) handleTokenUpdate(token string) {
	t.token.Store(token)
}
func (t *TCPRequester) setToken(token string) {
	t.token.Store(token)
}
func (t *TCPRequester) getAccessToken() string {
	return t.token.Load()
}
func (t *TCPRequester) setForwardTo(forwardTo string) {
	t.forwardingHost.Store(forwardTo)
}
func (h *TCPRequester) getForwardTo() string {
	return h.forwardingHost.Load()
}

func (t *TCPRequester) enableDemuxer() {
	t.demuxerMu.Lock()
	defer t.demuxerMu.Unlock()
	if t.demuxer != nil {
		return
	}
	t.demuxer = newMessageDemuxer(t.TCPConnection.ReadMessage)
	t.demuxer.start()
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

	forwardingHost atomic.String
	token          atomic.String
	demuxerMu      sync.Mutex
	demuxer        *MessageDemuxer
}

// Send performs the request over WSS.
func (w *WSSRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return w.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

// SendContext performs the request over WSS with the provided context.
// The context cancels the send and, when the demuxer is active (EnableConcurrency/
// Subscribe), the response wait. In legacy synchronous mode the blocking read is
// not cancelable; use Close() to abort.
func (w *WSSRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	u := w.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	token := w.token.Load()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// A caller-supplied X-Target-Host header overrides the client-wide forward
	// target for this request only ("" disables forwarding).
	forwardingHost, forwardOverridden := headers[headerTargetHost]
	if !forwardOverridden {
		forwardingHost = w.forwardingHost.Load()
	}
	if forwardingHost != "" {
		if strings.Contains(forwardingHost, ":") {
			req.Header.Set(headerTargetHost, forwardingHost)
		} else {
			req.Header.Set(headerTargetHost, forwardingHost+":"+u.Port())
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
		return 0, nil, nil, err
	}

	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	// Auto-sync token from auth endpoint responses
	syncTransportToken(resp.HttpStatus, resp.Body, apiPath, headers, w)

	return resp.HttpStatus, resp.Body, respHeaders, nil
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
	data := NewRequest()
	data.RequestUri = req.URL.Path
	data.HttpMethod = req.Method
	data.ClientAddress = w.ClientAddress()
	for key, values := range req.Header {
		if len(values) > 0 {
			data.Headers[key] = values[0]
		}
	}
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			data.Query[key] = values[0]
		}
	}

	if data.RequestUri != restPathUpload && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if len(bodyBytes) > 0 {
			if strings.HasSuffix(data.RequestUri, "/task") {
				data.Body = bodyBytes
			} else {
				data.Body = HtmlUnescapeBytes(bodyBytes)
			}
		}
	}

	data.Headers[userAgentHeaderName] = userAgentWSS

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	ctx := req.Context()

	// When demuxer is active, register BEFORE send so the response cannot arrive
	// and be dropped before the channel is in place. A stopped demuxer (transport
	// read error) never delivers, so fall back to the direct read below.
	demux := w.getDemuxer()
	if demux != nil && demux.isRunning() {
		ch := demux.registerRequest(data.UUID)
		defer demux.unregisterRequest(data.UUID)

		if err := w.SendMessage(ctx, buf); err != nil {
			return nil, err
		}

		return waitDemuxResponse(ctx, ch, demux)
	}

	if err := w.SendMessage(ctx, buf); err != nil {
		return nil, err
	}

	respData, err := w.ReadMessage()
	if err != nil {
		return nil, err
	}

	respMsg := &Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}

func (w *WSSRequester) enableDemuxer() {
	w.demuxerMu.Lock()
	defer w.demuxerMu.Unlock()
	if w.demuxer != nil {
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

func (w *WSSRequester) handleTokenUpdate(token string) {
	w.token.Store(token)
}
func (w *WSSRequester) setToken(token string) {
	w.token.Store(token)
}
func (w *WSSRequester) getAccessToken() string {
	return w.token.Load()
}
func (w *WSSRequester) setForwardTo(forwardTo string) {
	w.forwardingHost.Store(forwardTo)
}
func (w *WSSRequester) getForwardTo() string {
	return w.forwardingHost.Load()
}
