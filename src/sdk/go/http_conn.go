// client_http_handler.go
package appmesh

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

type HTTPConnection struct {
	*http.Client
}

func newHTTPConnection(clientCertFile string, clientCertKeyFile string, caFile string) (*HTTPConnection, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}

	// Server verification: a configured but missing/unreadable CA is a hard error;
	// an empty CA path (InsecureSkipVerify or legacy SslTrustedCA = "") disables it.
	switch caFile {
	case caSystemTrust:
		// Verify against the system trust store (RootCAs left nil); see caSystemTrust.
	case "":
		tlsConfig.InsecureSkipVerify = true
	default:
		caCert, err := LoadCA(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server CA: %w", err)
		}
		tlsConfig.RootCAs = caCert
	}

	// Client certificate for mutual TLS (optional)
	if clientCertFile != "" && clientCertKeyFile != "" {
		clientCert, err := LoadCertificatePair(clientCertFile, clientCertKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
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
