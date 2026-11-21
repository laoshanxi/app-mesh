// http_conn.go
package appmesh

import (
	"net/http"
	"time"
)

// HTTPConnection is an HTTP client with App Mesh TLS defaults.
type HTTPConnection struct {
	*http.Client
}

func newHTTPConnection(clientCertFile string, clientCertKeyFile string, caFile string) (*HTTPConnection, error) {
	tlsConfig, err := newClientTLSConfig(caFile, clientCertFile, clientCertKeyFile)
	if err != nil {
		return nil, err
	}

	// Intentionally leave Jar nil. Engine SDK authentication is bearer-only and
	// must not retain or replay Engine/proxy cookies.
	client := &http.Client{
		Timeout: 2 * time.Minute, // Overall timeout for the entire request
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,

			// Connection pooling configuration
			MaxIdleConns:        100,              // Good default for moderate traffic
			MaxIdleConnsPerHost: 20,               // Increased for better connection reuse
			IdleConnTimeout:     90 * time.Second, // Standard timeout for idle connections
			MaxConnsPerHost:     100,              // Balanced limit for concurrent connections

			// Additional optimizations
			ForceAttemptHTTP2:  true,  // Enable HTTP/2 support
			DisableKeepAlives:  false, // Keep connection pooling enabled
			DisableCompression: false, // Allow compression for better performance
		}}

	return &HTTPConnection{Client: client}, nil
}
