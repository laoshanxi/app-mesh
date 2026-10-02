package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

// The Dex login page loads its logo from <issuer-path>/logo.svg on whatever
// address the browser used. The agent must claim that exact path before the
// authentication reverse proxy forwards it to Dex (which would 404), and must
// point it at the daemon route that serves the asset.
func TestAuthLogoRoute(t *testing.T) {
	router := mux.NewRouter()
	RegisterAuthLogoRoutes(router, "/auth")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/logo.svg", nil))
	if recorder.Code != http.StatusMovedPermanently {
		t.Fatalf("expected %d for /auth/logo.svg, got %d", http.StatusMovedPermanently, recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/appmesh/logo.svg" {
		t.Fatalf("expected redirect to /appmesh/logo.svg, got %q", location)
	}

	// Dex hardcodes the favicon to <issuer-path>/theme/favicon.png; the agent
	// must claim that exact path too and point it at the daemon asset.
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/theme/favicon.png", nil))
	if recorder.Code != http.StatusMovedPermanently {
		t.Fatalf("expected %d for /auth/theme/favicon.png, got %d", http.StatusMovedPermanently, recorder.Code)
	}
	if location := recorder.Header().Get("Location"); location != "/appmesh/favicon.png" {
		t.Fatalf("expected redirect to /appmesh/favicon.png, got %q", location)
	}

	// The route is exact: other issuer-path requests must stay on the
	// authentication reverse proxy (here: unmatched).
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/logo.svg.bak", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-logo path, got %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/auth/theme/logo.png", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a non-favicon theme path, got %d", recorder.Code)
	}
}
