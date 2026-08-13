package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrometheusRootHandler(t *testing.T) {
	server := NewPrometheusServer(6061)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)

	server.RootHandler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, recorder.Code)
	}
	if got, want := recorder.Body.String(), "Prometheus metrics available at /metrics"; got != want {
		t.Fatalf("expected body %q, got %q", want, got)
	}
}

func TestPrometheusRootHandlerRejectsUnknownPath(t *testing.T) {
	server := NewPrometheusServer(6061)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/unknown", nil)

	server.RootHandler(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected status %d, got %d", http.StatusNotFound, recorder.Code)
	}
}

func TestPrometheusHandlerRoutesMetricsOnlyToBackend(t *testing.T) {
	backendCalls := 0
	server := NewPrometheusServer(6061)
	server.metricsHandler = func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("appmesh_build_info 1\n"))
	}

	metricsRecorder := httptest.NewRecorder()
	server.handler().ServeHTTP(metricsRecorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if metricsRecorder.Code != http.StatusOK {
		t.Fatalf("expected metrics status %d, got %d", http.StatusOK, metricsRecorder.Code)
	}
	if got, want := metricsRecorder.Body.String(), "appmesh_build_info 1\n"; got != want {
		t.Fatalf("expected body %q, got %q", want, got)
	}
	if backendCalls != 1 {
		t.Fatalf("expected one backend call, got %d", backendCalls)
	}

	unknownRecorder := httptest.NewRecorder()
	server.handler().ServeHTTP(unknownRecorder, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if unknownRecorder.Code != http.StatusNotFound {
		t.Fatalf("expected unknown path status %d, got %d", http.StatusNotFound, unknownRecorder.Code)
	}
	if backendCalls != 1 {
		t.Fatalf("unknown path unexpectedly reached metrics backend")
	}

	forwardRecorder := httptest.NewRecorder()
	forwardRequest := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	forwardRequest.Header.Set(HTTP_HEADER_KEY_X_TARGET_HOST, "https://example.invalid")
	server.handler().ServeHTTP(forwardRecorder, forwardRequest)
	if forwardRecorder.Code != http.StatusBadRequest {
		t.Fatalf("expected forwarding rejection status %d, got %d", http.StatusBadRequest, forwardRecorder.Code)
	}

	postRecorder := httptest.NewRecorder()
	server.handler().ServeHTTP(postRecorder, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if postRecorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected method rejection status %d, got %d", http.StatusMethodNotAllowed, postRecorder.Code)
	}
	if backendCalls != 1 {
		t.Fatalf("rejected request unexpectedly reached metrics backend")
	}
}

func TestPrometheusHandlerAllowsHead(t *testing.T) {
	backendCalls := 0
	server := NewPrometheusServer(6061)
	server.metricsHandler = func(w http.ResponseWriter, r *http.Request) {
		backendCalls++
		w.WriteHeader(http.StatusOK)
	}

	recorder := httptest.NewRecorder()
	server.handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if recorder.Code != http.StatusOK || backendCalls != 1 {
		t.Fatalf("expected HEAD to reach local backend once, status=%d calls=%d", recorder.Code, backendCalls)
	}
}
