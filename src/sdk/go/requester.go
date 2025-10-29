package appmesh

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.uber.org/atomic"
)

// Requester defines the interface for making HTTP requests.
type Requester interface {
	Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error)
	Close()

	handleTokenUpdate(token string)
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
	// Validate inputs
	if h.httpClient == nil {
		return 0, nil, nil, fmt.Errorf("http client is nil")
	}

	// Build URL
	u := h.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	// TODO: Create request with context http.NewRequestWithContext(ctx, method, u.String(), body)
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	// Set authorization header
	if csrfToken := h.httpClient.getCookie(COOKIE_CSRF_TOKEN, &h.baseURL); csrfToken != "" {
		req.Header.Set(HTTP_HEADER_NAME_CSRF_TOKEN, csrfToken)
	}

	// Set forwarding header
	forwardingHost := h.forwardingHost.Load()
	if forwardingHost != "" {
		targetHost := forwardingHost
		if !strings.Contains(forwardingHost, ":") {
			port := u.Port()
			if port == "" {
				port = map[string]string{"https": "443", "http": "80"}[u.Scheme]
			}
			targetHost = forwardingHost + ":" + port
		}
		req.Header.Set("X-Target-Host", targetHost)
	}

	// Set default headers
	req.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT)

	// Set custom headers
	for k, v := range headers {
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
func (h *HTTPRequester) setForwardTo(forwardTo string) {
	h.forwardingHost.Store(forwardTo)
}
func (h *HTTPRequester) getForwardTo() string {
	return h.forwardingHost.Load()
}

// TCPRequester handles TCP requests.
type TCPRequester struct {
	*TCPConnection
	baseURL url.URL

	forwardingHost atomic.String
	token          atomic.String
}

// Send performs a REST-like request over TCP.
func (t *TCPRequester) Send(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	u := t.baseURL
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	token := t.token.Load()
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	forwardingHost := t.forwardingHost.Load()
	if forwardingHost != "" {
		if strings.Contains(forwardingHost, ":") {
			req.Header.Set("X-Target-Host", forwardingHost)
		} else {
			req.Header.Set("X-Target-Host", forwardingHost+":"+u.Port())
		}
	}
	req.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT_TCP)
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := t.request(req)
	if err != nil {
		return 0, nil, nil, err
	}

	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	return resp.HttpStatus, resp.Body, respHeaders, nil
}

// Close closes the TCP connection.
func (t *TCPRequester) Close() {
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

	if data.RequestUri != REST_PATH_UPLOAD && req.Body != nil {
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

	data.Headers[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT_TCP

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	// Send the data over TCP.
	if err := t.SendMessage(req.Context(), buf); err != nil {
		return nil, err
	}

	// Receive the response.
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
func (t *TCPRequester) setForwardTo(forwardTo string) {
	t.forwardingHost.Store(forwardTo)
}
func (h *TCPRequester) getForwardTo() string {
	return h.forwardingHost.Load()
}
