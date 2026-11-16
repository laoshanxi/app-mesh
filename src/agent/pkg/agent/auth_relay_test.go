package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// The browser lands on /oauth/callback on this entry origin after the Dex
// authorization-code flow. The agent must serve the static relay page itself
// (the catch-all would forward the request to the daemon instead). The page
// must decode the web UI origin from the state parameter and redirect only to
// the fixed /oauth/callback path on that origin; an invalid or missing state
// or code must leave the static error message and never redirect. The bytes
// are the daemon copy (OAUTH_CALLBACK_RELAY_HTML in RestHandler.cpp).
func TestAuthRelayRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterAuthRelayRoutes(router)

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback?code=x&state=y", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected %d for /oauth/callback, got %d", http.StatusOK, recorder.Code)
	}
	if contentType := recorder.Header().Get("Content-Type"); contentType != "text/html; charset=utf-8" {
		t.Fatalf("expected text/html content type, got %q", contentType)
	}
	// The relay page is HTML with an inline script: its CSP denies everything
	// except that exact script (pinned by hash, identical on the daemon side)
	// and forbids framing. A tampered page must fail closed in the browser.
	csp := recorder.Header().Get("Content-Security-Policy")
	wantCSP := "default-src 'none'; script-src 'sha256-" + authRelayScriptHash + "'; frame-ancestors 'none'"
	if csp != wantCSP {
		t.Fatalf("expected relay CSP %q, got %q", wantCSP, csp)
	}
	// The hash must keep matching the served bytes — over the full text node
	// between the tags, newlines included, exactly as the browser hashes it —
	// or the browser blocks the (only) script and the page stops working.
	body := recorder.Body.String()
	scriptStart := strings.Index(body, "<script>")
	scriptEnd := strings.Index(body, "</script>")
	if scriptStart < 0 || scriptEnd < scriptStart {
		t.Fatal("relay page script element not found")
	}
	digest := sha256.Sum256([]byte(body[scriptStart+len("<script>") : scriptEnd]))
	if got := base64.StdEncoding.EncodeToString(digest[:]); got != authRelayScriptHash {
		t.Fatalf("authRelayScriptHash is stale: script content hashes to %q, constant says %q", got,
			authRelayScriptHash)
	}
	// The relay is a client-side redirect inside static HTML, never a server
	// redirect: code and state must reach the page untouched.
	if location := recorder.Header().Get("Location"); location != "" {
		t.Fatalf("expected no Location header, got %q", location)
	}
	if !strings.Contains(body, `payload.o`) {
		t.Fatal("the relay page must decode the target origin from the state parameter")
	}
	// Fixed redirect target: only <origin>/oauth/callback is ever used, so the
	// state parameter cannot turn the relay into an open redirect.
	if !strings.Contains(body, `target.origin + "/oauth/callback" + window.location.search`) {
		t.Fatal("the relay page must redirect to the fixed /oauth/callback path with the original query string")
	}
	// Error branch for an invalid or missing state or code: no redirect.
	if !strings.Contains(body, `"The sign-in link is not valid. Start the sign-in again from the App Mesh page."`) {
		t.Fatal("the relay page must render a static error message for an invalid callback")
	}

	// The route is exact: other root paths must stay unmatched here.
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback.bak", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-callback path, got %d", recorder.Code)
	}
}
