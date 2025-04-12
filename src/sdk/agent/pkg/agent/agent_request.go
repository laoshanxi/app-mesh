package agent

import (
	"bytes"
	"html"
	"io"
	"net/http"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
)

const maxBodySize = 100 * 1024 * 1024 // 100 MB, adjust as needed

// NewAppMeshRequest creates a new AppMesh request from the HTTP request
func NewAppMeshRequest(req *http.Request) *appmesh.Request {
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

	// Copy headers
	for key, values := range req.Header {
		if len(values) > 0 {
			data.Headers[key] = values[0]
		}
	}

	// Copy query parameters
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			data.Queries[key] = values[0]
		}
	}

	// Read body for non-file upload requests
	if !(req.Method == http.MethodPost && req.URL.Path == REST_PATH_UPLOAD) && req.Body != nil {
		bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize))
		if err == nil {
			// Only unescape if the content actually contains HTML entities
			// This avoids unnecessary string conversions
			if bytes.ContainsAny(bodyBytes, "&<>\"'") {
				data.Body = html.UnescapeString(string(bodyBytes))
			} else {
				data.Body = string(bodyBytes)
			}
		}
		// Reset the request body to allow subsequent reads
		// req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Read cookies
	if req.Header.Get("Authorization") == "" {
		// If Authorization header is not present, try to find the token in cookies
		for _, cookie := range req.Cookies() {
			if cookie.Name == COOKIE_TOKEN {
				data.Headers["Authorization"] = "Bearer " + cookie.Value
				break // Exit loop after finding the token cookie
			}
		}
	}

	return data
}
