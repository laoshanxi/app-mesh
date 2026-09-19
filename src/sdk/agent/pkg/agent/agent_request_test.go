package agent

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNewRequestFromHTTPPassesBodyThrough asserts the proxy forwards request
// bodies byte-for-byte: HTML entities are valid payload data (query strings in
// metadata, literal text) and must reach the daemon unmodified.
func TestNewRequestFromHTTPPassesBodyThrough(t *testing.T) {
	body := `{"command":"echo a&amp;b","metadata":"https://host/path?a=1&b=2","text":"x &#65;&lt; y"}`

	req := httptest.NewRequest(http.MethodPost, "/appmesh/app/run", strings.NewReader(body))
	r, err := newRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("newRequestFromHTTP failed: %v", err)
	}
	if string(r.Body) != body {
		t.Fatalf("request body was rewritten: got %q, want %q", string(r.Body), body)
	}
}
