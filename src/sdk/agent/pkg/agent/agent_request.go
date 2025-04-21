package agent

import (
	"bytes"
	"errors"
	"html"
	"io"
	"net/http"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
)

const maxBodySize = 100 * 1024 * 1024 // 100 MB, adjust as needed

// NewAppMeshRequest creates a new AppMesh request from the HTTP request
func NewAppMeshRequest(req *http.Request) (*appmesh.Request, error) {
	// Remove "Connection" header to avoid proxying it
	req.Header.Del("Connection")

	data := &appmesh.Request{
		Uuid:          xid.New().String(),
		HttpMethod:    req.Method,
		RequestUri:    req.URL.Path,
		ClientAddress: req.RemoteAddr,
		Headers:       make(map[string]string, len(req.Header)),
		Queries:       make(map[string]string, len(req.URL.Query())),
	}

	// Copy headers and query parameters
	for key, values := range req.Header {
		if len(values) > 0 {
			data.Headers[key] = values[0]
		}
	}
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			data.Queries[key] = values[0]
		}
	}

	// Read body for non-file upload requests
	if !(req.Method == http.MethodPost && req.URL.Path == REST_PATH_UPLOAD) && req.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize))
		if err != nil {
			return nil, errors.New("failed to read request body")
		}
		if len(bodyBytes) >= maxBodySize {
			return nil, errors.New("request body too large")
		}
		// Optimize HTML entity check
		if len(bodyBytes) > 0 {
			if bytes.ContainsAny(bodyBytes, "&<>\"'") {
				data.Body = html.UnescapeString(string(bodyBytes))
			} else {
				data.Body = string(bodyBytes)
			}
		}
		// Reset the request body to allow subsequent reads
		// req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Handle authorization and CSRF validation
	if req.Header.Get("Authorization") == "" {
		var authCookieValue, csrfCookieValue string
		for _, cookie := range req.Cookies() {
			switch cookie.Name {
			case COOKIE_TOKEN:
				authCookieValue = cookie.Value
			case COOKIE_CSRF_TOKEN:
				csrfCookieValue = cookie.Value
			}
		}

		if authCookieValue != "" {
			data.Headers["Authorization"] = "Bearer " + authCookieValue

			// Verify CSRF token
			csrfHeader := req.Header.Get(HTTP_HEADER_KEY_X_CSRF_TOKEN)
			if csrfHeader == "" || csrfCookieValue == "" || csrfCookieValue != csrfHeader || !cloud.HMAC.VerifyHMAC(authCookieValue, csrfCookieValue) {
				logger.Warnf("CSRF validation failed - RequestID: %s, Path: %s, Cookie: %s, Header: %s",
					data.Uuid, data.RequestUri, csrfCookieValue, csrfHeader)
				return nil, errors.New("invalid CSRF token")
			}
		}
	}

	return data, nil
}
