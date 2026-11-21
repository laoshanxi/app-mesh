package agent

import (
	"net/http"
	"testing"
)

// TestNewForwardPrecheckRequestCarriesExemptionMarker pins the forwarding
// precheck shape: exactly the bearer plus the X-Appmesh-Agent-Precheck marker
// on GET /appmesh/principal/self, so the daemon exempts the probe from its
// mandatory request signature instead of rejecting it with 401 in enforce
// mode.
func TestNewForwardPrecheckRequestCarriesExemptionMarker(t *testing.T) {
	request := newForwardPrecheckRequest("Bearer test-forward-token")

	if request.HTTPMethod != http.MethodGet {
		t.Fatalf("method = %q, want GET", request.HTTPMethod)
	}
	if request.RequestURI != "/appmesh/principal/self" {
		t.Fatalf("request_uri = %q, want /appmesh/principal/self", request.RequestURI)
	}
	if got := request.Headers[HTTPHeaderKeyAuthorization]; got != "Bearer test-forward-token" {
		t.Fatalf("Authorization = %q, want the caller's bearer", got)
	}
	if got := request.Headers[HTTPHeaderKeyAgentPrecheck]; got != "1" {
		t.Fatalf("%s = %q, want \"1\"", HTTPHeaderKeyAgentPrecheck, got)
	}
	if got := request.Headers[HTTPUserAgentHeaderName]; got != UserAgentAppmeshSDK {
		t.Fatalf("User-Agent = %q, want %q", got, UserAgentAppmeshSDK)
	}
}

func TestForwardPermissionGranted(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		expected bool
	}{
		{"granted", `{"id":"p1","permissions":["app-view","host-forward"]}`, true},
		{"denied", `{"id":"p1","permissions":["app-view","file-download"]}`, false},
		{"no permissions", `{"id":"p1","permissions":[]}`, false},
		{"malformed body", `not json`, false},
		{"empty body", ``, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			response := &Response{}
			response.HTTPStatus = http.StatusOK
			response.Body = []byte(c.body)
			if got := forwardPermissionGranted(response); got != c.expected {
				t.Fatalf("forwardPermissionGranted(%q) = %v, want %v", c.body, got, c.expected)
			}
		})
	}
}
