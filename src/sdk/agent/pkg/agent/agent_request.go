// agent_request.go
package agent

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
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

	// Handle CSRF validation
	if err := r.validateCSRFToken(req); err != nil {
		return nil, err
	}

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

// validateCSRFToken processes CSRF validation
func (r *Request) validateCSRFToken(req *http.Request) error {
	// Skip CSRF check if using token-based auth (server will verify)
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		return nil
	}

	authCookie, _ := req.Cookie(COOKIE_TOKEN)
	csrfCookie, _ := req.Cookie(COOKIE_CSRF_TOKEN)

	// Missing cookies — skip CSRF validation
	if authCookie == nil || csrfCookie == nil {
		return nil
	}

	authCookieValue := strings.TrimSpace(authCookie.Value)
	csrfCookieValue := strings.TrimSpace(csrfCookie.Value)

	// Empty cookies — skip CSRF validation
	if authCookieValue == "" || csrfCookieValue == "" {
		return nil
	}

	csrfHeaderValue := strings.TrimSpace(req.Header.Get(HTTP_HEADER_KEY_X_CSRF_TOKEN))
	if csrfHeaderValue == "" {
		logger.Warnf("CSRF validation failed: missing token - RequestID=%s Path=%s Client=%s", r.UUID, r.RequestUri, r.ClientAddress)
		return errors.New("invalid CSRF token")
	}

	if csrfHeaderValue != csrfCookieValue {
		logger.Warnf("CSRF validation failed: token mismatch - RequestID=%s Path=%s Client=%s", r.UUID, r.RequestUri, r.ClientAddress)
		return errors.New("invalid CSRF token")
	}

	if !cloud.HMAC_SDKToAgent.VerifyHMAC(authCookieValue, csrfCookieValue) {
		logger.Warnf("CSRF validation failed: HMAC verification failed - RequestID=%s Path=%s Client=%s", r.UUID, r.RequestUri, r.ClientAddress)
		return errors.New("invalid CSRF token")
	}

	// CSRF validation passed — inject Authorization header
	r.Headers["Authorization"] = "Bearer " + authCookieValue

	return nil
}
