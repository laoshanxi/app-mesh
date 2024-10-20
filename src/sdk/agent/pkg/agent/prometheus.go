package agent

import (
	"fmt"
	"log"
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

// rootHandler handles the root path request
func (s *PrometheusServer) rootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "Prometheus metrics available at %s", prometheusMetricPath)
}

// metricsHandler handles the metrics path request
func (s *PrometheusServer) metricsHandler(w http.ResponseWriter, r *http.Request) {
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

	// Call handleAppmeshResquest with the new request
	handleAppmeshResquest(w, appmeshReq)
}

// ListenAndServe starts the Prometheus exporter server
func (s *PrometheusServer) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.rootHandler)
	mux.HandleFunc(prometheusMetricPath, s.metricsHandler)

	addr := fmt.Sprintf(":%d", s.port)
	log.Printf("Starting Prometheus exporter server on %s", addr)
	return http.ListenAndServe(addr, mux)
}

// ListenPrometheus creates and starts a PrometheusServer
func ListenPrometheus(port int) {
	server := NewPrometheusServer(port)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Error in Prometheus exporter server: %s", err)
	}
}
