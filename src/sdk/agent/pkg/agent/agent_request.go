// agent_request.go
package agent

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/valyala/bytebufferpool"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

const maxBodySize = 100 * 1024 * 1024 // 100 MB
var bufferPool = bytebufferpool.Pool{}

// NewAppMeshRequest creates a new AppMesh request from the HTTP request
func NewAppMeshRequest(req *http.Request) (*appmesh.Request, error) {
	// Remove "Connection" header to avoid proxying it
	req.Header.Del("Connection")

	data := appmesh.NewRequest()
	data.HttpMethod = req.Method
	data.RequestUri = req.URL.Path
	data.ClientAddress = req.RemoteAddr

	// Copy headers and query parameters
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

	// Read body for non-file upload requests
	if req.Body != nil && req.URL.Path != REST_PATH_UPLOAD {
		if err := readRequestBody(data, req); err != nil {
			return nil, err
		}
	}

	// Handle CSRF validation
	if err := handleCSRFAuth(data, req); err != nil {
		return nil, err
	}

	return data, nil
}

// readRequestBody reads and processes the HTTP request body
func readRequestBody(data *appmesh.Request, req *http.Request) error {
	defer req.Body.Close()

	buf := bufferPool.Get()
	defer bufferPool.Put(buf)
	buf.Reset()

	n, err := buf.ReadFrom(io.LimitReader(req.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	if n >= maxBodySize {
		return errors.New("request body too large")
	}

	// Pass raw data for task requests, otherwise HTML unescape
	if matches := REST_PATH_TASK.FindStringSubmatch(req.URL.Path); len(matches) > 1 {
		data.Body = make([]byte, len(buf.Bytes()))
		copy(data.Body, buf.Bytes())
	} else {
		data.Body = appmesh.HtmlUnescapeBytes(buf.Bytes())
	}

	// Reset the request body to allow subsequent reads
	// req.Body = io.NopCloser(bytes.NewBuffer(buf.Bytes()))

	return nil
}

// handleCSRFAuth processes CSRF validation
func handleCSRFAuth(data *appmesh.Request, req *http.Request) error {
	// Skip CSRF check if using token-based auth (server will verify)
	if req.Header.Get("Authorization") != "" {
		return nil
	}

	authCookie, _ := req.Cookie(COOKIE_TOKEN)
	csrfCookie, _ := req.Cookie(COOKIE_CSRF_TOKEN)
	if authCookie == nil || csrfCookie == nil {
		// Missing cookies — skip
		return nil
	}

	authCookieValue := strings.TrimSpace(authCookie.Value)
	csrfCookieValue := strings.TrimSpace(csrfCookie.Value)
	if authCookieValue == "" || csrfCookieValue == "" {
		return nil
	}

	csrfHeaderValue := strings.TrimSpace(req.Header.Get(HTTP_HEADER_KEY_X_CSRF_TOKEN))
	if csrfHeaderValue == "" {
		logger.Warnf("CSRF validation failed: missing token - RequestID=%s Path=%s", data.UUID, data.RequestUri)
		return errors.New("invalid CSRF token")
	}

	if csrfHeaderValue != csrfCookieValue {
		logger.Warnf("CSRF validation failed: token mismatch - RequestID=%s Path=%s", data.UUID, data.RequestUri)
		return errors.New("invalid CSRF token")
	}

	if !cloud.HMAC_SDKToAgent.VerifyHMAC(authCookieValue, csrfCookieValue) {
		logger.Warnf("CSRF validation failed: HMAC verification failed - RequestID=%s Path=%s", data.UUID, data.RequestUri)
		return errors.New("invalid CSRF token")
	}

	// CSRF validation passed — inject Authorization header
	data.Headers["Authorization"] = "Bearer " + authCookieValue

	return nil
}
