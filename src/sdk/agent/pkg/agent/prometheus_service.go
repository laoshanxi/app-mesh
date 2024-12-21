package agent

import (
	"fmt"
	"net/http"
)

const (
	prometheusMetricPath = "/metrics"
	appmeshMetricPath    = "/appmesh/metrics"
)

// PrometheusServer represents the Prometheus exporter server
type PrometheusServer struct {
	port int
}

// NewPrometheusServer creates a new PrometheusServer instance
func NewPrometheusServer(port int) *PrometheusServer {
	return &PrometheusServer{port: port}
}

// RootHandler handles the root path request
func (s *PrometheusServer) RootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "Prometheus metrics available at %s", prometheusMetricPath)
}

// MetricsHandler handles the metrics path request
func (s *PrometheusServer) MetricsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Create a new request for the Appmesh metrics
	appmeshReq, err := http.NewRequest(http.MethodGet, appmeshMetricPath, nil)
	if err != nil {
		http.Error(w, "Failed to create Appmesh request", http.StatusInternalServerError)
		return
	}

	// Copy relevant headers from the original request
	appmeshReq.Header = r.Header

	// Call HandleAppMeshRequest with the new request
	HandleAppMeshRequest(w, appmeshReq)
}

// ListenAndServe starts the Prometheus exporter server
func (s *PrometheusServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.RootHandler)
	mux.HandleFunc(prometheusMetricPath, s.MetricsHandler)

	addr := fmt.Sprintf(":%d", s.port)
	logger.Infof("Starting Prometheus exporter server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

// ListenPrometheus creates and starts a PrometheusServer
func ListenPrometheus(port int) error {
	server := NewPrometheusServer(port)
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("http server error: %w", err)
	}
	return nil
}
