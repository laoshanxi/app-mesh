package agent

import (
	"net/http"
	"testing"
)

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
