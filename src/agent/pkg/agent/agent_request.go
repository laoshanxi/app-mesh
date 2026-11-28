// agent_request.go
package agent

import (
	"fmt"
	"io"
	"net/http"

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
	// Process proof is an Engine-injected local secret, never a public proxy
	// credential: strip it here so no external caller smuggles it onto Agent's
	// loopback connection to Engine or into logs; the handler re-attaches it for
	// loopback callers on the local hop only.
	req.Header.Del("X-AppMesh-Process-Key")
	query := req.URL.Query()
	if _, supplied := query["process_key"]; supplied {
		query.Del("process_key")
		req.URL.RawQuery = query.Encode()
	}

	r := &Request{appmesh.NewRequest()}
	r.HTTPMethod = req.Method
	// Keep the percent-encoded wire form: the daemon verifies signatures over
	// the raw path, and EscapedPath preserves the client's original encoding.
	r.RequestURI = req.URL.EscapedPath()
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
	if req.Body != nil && req.URL.Path != RestPathUpload {
		if err := r.loadBodyFromHTTP(req); err != nil {
			return nil, fmt.Errorf("read request body for %s: %w", req.URL.Path, err)
		}
	}

	return r, nil
}

// markFileTransferHeaders arms the daemon's socket file channel for a
// download (X-Recv-File-Socket) or upload (X-Send-File-Socket) request.
func markFileTransferHeaders(request *Request) {
	switch request.RequestURI {
	case RestPathDownload:
		request.Headers[HTTPHeaderKeyXRecvFileSocket] = "true"
	case RestPathUpload:
		request.Headers[HTTPHeaderKeyXSendFileSocket] = "true"
	}
}

// loadBodyFromHTTP reads and processes the HTTP request body
func (r *Request) loadBodyFromHTTP(req *http.Request) error {
	defer req.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize))
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}

	r.Body = bodyBytes

	// Reset the request body to allow subsequent reads
	// req.Body = io.NopCloser(bytes.NewBuffer(buf.Bytes()))

	return nil
}
