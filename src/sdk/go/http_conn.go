// client_http_handler.go
package appmesh

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/juju/persistent-cookiejar"
	"golang.org/x/net/publicsuffix"
)

type HTTPConnection struct {
	*http.Client

	cookieFile string
	jar        *cookiejar.Jar
}

func newHTTPConnection(clientCertFile string, clientCertKeyFile string, caFile string, cookiePath string) *HTTPConnection {
	// Load client certificate and key
	clientCert, err := LoadCertificatePair(clientCertFile, clientCertKeyFile)
	if err != nil {
		fmt.Println(err)
	}
	// Load server CA
	caCert, err := LoadCA(caFile)
	if err != nil {
		fmt.Println(err)
	}

	// Create or load cookie jar (MozillaCookieJar format)
	var jar *cookiejar.Jar
	if _, err := os.Stat(cookiePath); err == nil {
		// Load existing cookie file
		jar, err = cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
			Filename:         cookiePath,
		})
		if err != nil {
			fmt.Println("Error loading cookie jar:", err)
		}
	} else {
		// Create a new cookie jar
		jar, err = cookiejar.New(&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
			Filename:         cookiePath,
		})
		if err != nil {
			fmt.Println("Error creating cookie jar:", err)
		}
	}

	// TODO: use session management for better performance
	client := &http.Client{
		Timeout: 2 * time.Minute, // Overall timeout for the entire request
		Jar:     jar,             // Cookie jar for session management
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCert,                        // Trusted root CAs
				InsecureSkipVerify: (caCert == nil),               // Skip verification if no CA provided
				Certificates:       []tls.Certificate{clientCert}, // Client certificates for mutual TLS
				MinVersion:         tls.VersionTLS12,
			},

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

	return &HTTPConnection{
		Client:     client,
		cookieFile: cookiePath,
		jar:        jar,
	}
}

func (h *HTTPConnection) getCookie(name string, targetURL *url.URL) string {
	if h.Jar == nil {
		return ""
	}

	cookies := h.Jar.Cookies(targetURL)
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
}

// SaveCookies persists cookies to the cookie file
func (h *HTTPConnection) SaveCookies() error {
	if h.jar == nil || h.cookieFile == "" {
		return nil
	}
	if err := h.jar.Save(); err != nil {
		return fmt.Errorf("failed to save cookies: %w", err)
	}
	return nil
}
