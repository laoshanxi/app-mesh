package utils

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// corsTestConfig mirrors the agent wiring: DefaultCORSConfig with a non-empty
// allowlist. DefaultCORSConfig itself keeps the daemon default (empty list =
// no CORS headers at all).
func corsTestConfig() CORSConfig {
	config := DefaultCORSConfig
	config.AllowedOrigins = []string{"https://ui.example.com"}
	return config
}

func corsHeaderNames() []string {
	return []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers",
		"Access-Control-Expose-Headers",
		"Access-Control-Max-Age",
		"Access-Control-Allow-Credentials",
	}
}

func assertNoCORSHeaders(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range corsHeaderNames() {
		if value := recorder.Header().Get(name); value != "" {
			t.Fatalf("expected no %s header, got %q", name, value)
		}
	}
}

func serveThroughCORS(t *testing.T, config CORSConfig, request *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	handler := Cors(config)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// The daemon semantics: with the default empty allowlist no CORS header is
// ever sent, whatever the Origin.
func TestCorsDefaultAllowlistSendsNoHeaders(t *testing.T) {
	for _, origin := range []string{"", "https://ui.example.com", "https://evil.example"} {
		request := httptest.NewRequest(http.MethodGet, "/appmesh/app", nil)
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		recorder := serveThroughCORS(t, DefaultCORSConfig, request)
		if recorder.Code != http.StatusOK {
			t.Fatalf("origin %q: expected passthrough 200, got %d", origin, recorder.Code)
		}
		assertNoCORSHeaders(t, recorder)
	}
}

// A request without an Origin header is not a CORS request: no Allow-* header,
// no preflight answer, the routed handler runs.
func TestCorsNoOriginRequestGetsNoHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/appmesh/app", nil)
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 from the next handler, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)

	// Even OPTIONS without Origin is not a preflight.
	request = httptest.NewRequest(http.MethodOptions, "/appmesh/app", nil)
	recorder = serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected OPTIONS to reach the next handler, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)
}

// An Origin outside the allowlist is never echoed and gets no CORS headers.
func TestCorsUnlistedOriginGetsNoHeaders(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://evil.example")
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 from the next handler, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)
}

// A "*" allowlist entry must not reopen the wildcard: browsers never send an
// Origin of "*", so the configuration fails closed.
func TestCorsWildcardEntryNeverMatches(t *testing.T) {
	config := corsTestConfig()
	config.AllowedOrigins = []string{"*"}
	request := httptest.NewRequest(http.MethodGet, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://anything.example")
	recorder := serveThroughCORS(t, config, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 from the next handler, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)
}

// A simple (actual) request with a listed Origin is answered by echoing that
// origin only; Allow-Methods/Allow-Headers/Max-Age are preflight-only headers.
func TestCorsListedOriginEchoedOnSimpleRequest(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 from the next handler, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example.com" {
		t.Fatalf("expected the listed origin echoed, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); got != "" {
		t.Fatalf("simple request must not carry Allow-Methods, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); got != "" {
		t.Fatalf("simple request must not carry Allow-Headers, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Max-Age"); got != "" {
		t.Fatalf("simple request must not carry Max-Age, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Expose-Headers"); got == "" {
		t.Fatal("configured Expose-Headers must ride on the actual response")
	}
}

// A preflight (OPTIONS + Access-Control-Request-Method) from a listed origin
// is answered 204 with the preflight headers.
func TestCorsPreflightFromListedOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodOptions, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "authorization")
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for a matching preflight, got %d", recorder.Code)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://ui.example.com" {
		t.Fatalf("expected the listed origin echoed, got %q", got)
	}
	if got := recorder.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Fatal("preflight must carry Allow-Methods")
	}
	if got := recorder.Header().Get("Access-Control-Allow-Headers"); got == "" {
		t.Fatal("preflight must carry Allow-Headers")
	}
	if got := recorder.Header().Get("Access-Control-Max-Age"); got == "" {
		t.Fatal("preflight must carry Max-Age")
	}
	// The internal forwarding/file-socket headers must not be advertised.
	for _, forbidden := range []string{"X-Target-Host", "X-Send-File-Socket", "X-Recv-File-Socket"} {
		if got := recorder.Header().Get("Access-Control-Allow-Headers"); containsToken(got, forbidden) {
			t.Fatalf("preflight must not advertise %s: %q", forbidden, got)
		}
	}
}

// A preflight from an unlisted origin is not answered: no CORS header, no 204,
// the request falls through to the routed handler.
func TestCorsPreflightFromUnlistedOriginNotAnswered(t *testing.T) {
	request := httptest.NewRequest(http.MethodOptions, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://evil.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected the next handler to answer an unlisted preflight, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)
}

// The global switch (agent REST.CorsDisabled) turns the middleware into a
// pass-through even for a listed origin.
func TestCorsDisabledPassesThrough(t *testing.T) {
	EnableGlobalCORS(false)
	defer EnableGlobalCORS(true)

	request := httptest.NewRequest(http.MethodOptions, "/appmesh/app", nil)
	request.Header.Set("Origin", "https://ui.example.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	recorder := serveThroughCORS(t, corsTestConfig(), request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected the next handler to answer, got %d", recorder.Code)
	}
	assertNoCORSHeaders(t, recorder)
}

func containsToken(list, token string) bool {
	for _, part := range strings.Split(list, ",") {
		if strings.TrimSpace(part) == token {
			return true
		}
	}
	return false
}
