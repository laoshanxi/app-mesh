package agent

import (
	"net/http"
	"net/http/httptest"
	"net/url"
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

// TestNewRequestFromHTTPKeepsEncodedRequestURI pins the signature-hop
// fidelity: the frame's request_uri must stay byte-identical to the
// percent-encoded path the client put on the wire (a kept %2F, lowercase hex
// untouched, %20 for space), because the daemon verifies request signatures
// over exactly those bytes — the decoded req.URL.Path would 401 every signed
// request carrying escapes.
func TestNewRequestFromHTTPKeepsEncodedRequestURI(t *testing.T) {
	const rawPath = "/appmesh/app/%e4%b8%ad%2Fname%20x"
	req := httptest.NewRequest(http.MethodGet, rawPath+"?k=%2Fv", nil)
	r, err := newRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("newRequestFromHTTP failed: %v", err)
	}
	if r.RequestURI != rawPath {
		t.Fatalf("frame request_uri = %q, want the wire-encoded path %q", r.RequestURI, rawPath)
	}

	// A path without escapes passes through unchanged as well.
	req = httptest.NewRequest(http.MethodGet, "/appmesh/applications", nil)
	r, err = newRequestFromHTTP(req)
	if err != nil {
		t.Fatalf("newRequestFromHTTP failed: %v", err)
	}
	if r.RequestURI != "/appmesh/applications" {
		t.Fatalf("frame request_uri = %q, want %q", r.RequestURI, "/appmesh/applications")
	}
}

// TestForwardAppMeshRequestKeepsEncodedTarget asserts the HTTP forward hop
// rebuilds the target URL from the request's original encoding: the target
// daemon verifies signatures over the encoded path bytes, and no trailing "?"
// is appended when the query is empty.
func TestForwardAppMeshRequestKeepsEncodedTarget(t *testing.T) {
	got := make(chan string, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.RequestURI
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}

	cases := []struct{ name, raw string }{
		{"encoded path and query kept", "/appmesh/app/%e4%b8%ad%2Fa%20b?k=%2Fv&x=1"},
		{"no query adds no trailing question mark", "/appmesh/app/%e4%b8%ad"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.raw, strings.NewReader("{}"))
			ForwardAppMeshRequest(httptest.NewRecorder(), req, targetURL)
			select {
			case forwarded := <-got:
				if forwarded != tc.raw {
					t.Fatalf("forwarded target = %q, want the raw request target %q", forwarded, tc.raw)
				}
			default:
				t.Fatal("the forward never reached the target server")
			}
		})
	}
}

// TestLocalProcessProof pins who may carry worker process proof through the
// agent: only a loopback caller, and never through a forwarded target.
func TestLocalProcessProof(t *testing.T) {
	const key = "  process-key-1  "
	cases := []struct {
		name, remote, want string
	}{
		{"ipv4 loopback", "127.0.0.1:5000", "process-key-1"},
		{"other 127/8 address", "127.9.8.7:5000", "process-key-1"},
		{"ipv6 loopback", "[::1]:5000", "process-key-1"},
		{"v4-mapped loopback", "[::ffff:127.0.0.1]:5000", "process-key-1"},
		{"remote ipv4", "10.1.2.3:5000", ""},
		{"remote ipv6", "[fd00::1]:5000", ""},
		{"unparseable peer", "localhost:5000", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/appmesh/app/wk/task", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set(HTTPHeaderKeyAppmeshProcess, key)
			if got := localProcessProof(req); got != tc.want {
				t.Fatalf("localProcessProof = %q, want %q", got, tc.want)
			}
			stripInternalClientProof(req)
			if got := req.Header.Get(HTTPHeaderKeyAppmeshProcess); got != "" {
				t.Fatalf("client header survived stripInternalClientProof: %q", got)
			}
		})
	}
}

// TestLocalProcessProofDroppedWithoutHeader covers a loopback caller that
// sends no proof: nothing is invented for it.
func TestLocalProcessProofDroppedWithoutHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/appmesh/app/wk/task", nil)
	if got := localProcessProof(req); got != "" {
		t.Fatalf("localProcessProof = %q, want empty", got)
	}
	req.Header.Set(HTTPHeaderKeyAppmeshProcess, "   ")
	if got := localProcessProof(req); got != "" {
		t.Fatalf("blank proof became %q, want empty", got)
	}
}
