package agent

import (
	"fmt"
	"net/http"
	"time"
)

const (
	prometheusMetricPath = "/metrics"
)

// PrometheusServer represents the Prometheus exporter server
type PrometheusServer struct {
	port           int
	metricsHandler http.HandlerFunc
}

// NewPrometheusServer creates a new PrometheusServer instance
func NewPrometheusServer(port int) *PrometheusServer {
	return &PrometheusServer{port: port, metricsHandler: HandleAppMeshRequest}
}

func (s *PrometheusServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get(HTTP_HEADER_KEY_X_TARGET_HOST) != "" {
		http.Error(w, "metrics forwarding is not allowed", http.StatusBadRequest)
		return
	}
	s.metricsHandler(w, r)
}

// RootHandler handles the root path request
func (s *PrometheusServer) RootHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	fmt.Fprintf(w, "Prometheus metrics available at %s", prometheusMetricPath)
}

func (s *PrometheusServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.RootHandler)
	mux.HandleFunc(prometheusMetricPath, s.handleMetrics)
	return mux
}

// ListenAndServe starts the Prometheus exporter server
func (s *PrometheusServer) ListenAndServe() error {
	addr := fmt.Sprintf(":%d", s.port)
	logger.Infof("Starting Prometheus exporter server on %s", addr)

	// Bound slow or idle connections.
	server := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	return server.ListenAndServe()
}

// ListenPrometheus creates and starts a PrometheusServer
func ListenPrometheus(port int) error {
	server := NewPrometheusServer(port)
	if err := server.ListenAndServe(); err != nil {
		return fmt.Errorf("http server error: %w", err)
	}
	return nil
}
