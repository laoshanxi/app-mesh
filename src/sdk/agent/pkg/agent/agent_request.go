// agent_request.go
package agent

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

const maxBodySize = 100 * 1024 * 1024 // 100 MB

type Request struct {
	*appmesh.Request
}

// newRequestFromHTTP creates a new AppMesh request from the HTTP request
func newRequestFromHTTP(req *http.Request) (*Request, error) {
	// Remove "Connection" header to avoid proxying it
	req.Header.Del("Connection")

	r := &Request{appmesh.NewRequest()}
	r.HttpMethod = req.Method
	r.RequestUri = req.URL.Path
	r.ClientAddress = req.RemoteAddr

	// Copy headers and query parameters
	for key, values := range req.Header {
		if len(values) > 0 {
			r.Headers[key] = values[0]
		}
	}

	// Set the browser-facing host for the daemon's CSRF Origin check. As the front proxy (trust
	// boundary) the agent overwrites any client-supplied value so it cannot be forged.
	if req.Host != "" {
		r.Headers["X-Forwarded-Host"] = req.Host
	} else {
		delete(r.Headers, "X-Forwarded-Host")
	}
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			r.Query[key] = values[0]
		}
	}

	// Read body for non-file upload requests
	if req.Body != nil && req.URL.Path != REST_PATH_UPLOAD {
		if err := r.loadBodyFromHTTP(req); err != nil {
			return nil, fmt.Errorf("read request body for %s: %w", req.URL.Path, err)
		}
	}

	// Relay cookie auth to the daemon. CSRF is enforced by the daemon (Origin check on
	// cookie-authenticated state-changing requests); the agent forwards Cookie + Origin as-is.
	r.applyCookieAuth(req)

	return r, nil
}

// loadBodyFromHTTP reads and processes the HTTP request body
func (r *Request) loadBodyFromHTTP(req *http.Request) error {
	defer req.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	// Pass raw data for task requests, otherwise HTML unescape
	if matches := REST_PATH_TASK.FindStringSubmatch(req.URL.Path); len(matches) > 1 {
		r.Body = bodyBytes
	} else {
		r.Body = appmesh.HtmlUnescapeBytes(bodyBytes)
	}

	// Reset the request body to allow subsequent reads
	// req.Body = io.NopCloser(bytes.NewBuffer(buf.Bytes()))

	return nil
}

// applyCookieAuth relays the auth cookie as an Authorization header. CSRF is enforced by the
// daemon (Origin check); SameSite=Strict on the cookie is the baseline.
func (r *Request) applyCookieAuth(req *http.Request) {
	// Already token-authenticated — nothing to do.
	if req.Header.Get("Authorization") != "" {
		return
	}

	authCookie, _ := req.Cookie(COOKIE_TOKEN)
	if authCookie == nil {
		return
	}
	authCookieValue := strings.TrimSpace(authCookie.Value)
	if authCookieValue == "" {
		return
	}

	r.Headers["Authorization"] = "Bearer " + authCookieValue
}
