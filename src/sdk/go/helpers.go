package appmesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const tcpConnectTimeoutSeconds = 10

// caSystemTrust is an internal CA-path sentinel meaning "verify against the
// system trust store" (tls.Config.RootCAs left nil). Produced when SslTrustedCA
// is nil and the default App Mesh CA is absent. Distinct from "" (skip-verify).
const caSystemTrust = "<system>"

// IsFileExist checks if the file at the given path exists.
func IsFileExist(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// LoadCertificatePair loads a TLS certificate and key from the given PEM and key file paths.
func LoadCertificatePair(pem, key string) (tls.Certificate, error) {
	// Check if both the PEM and key files exist.
	if !IsFileExist(pem) || !IsFileExist(key) {
		return tls.Certificate{}, fmt.Errorf("certificate <%s> or key <%s> file not found", pem, key)
	}

	// Load the X509 certificate and key pair.
	cert, err := tls.LoadX509KeyPair(pem, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load X509KeyPair: %w", err)
	}

	// Return the loaded certificate.
	return cert, nil
}

// LoadCA loads a CA certificate, either from a single file or from a directory of certificates.
// Wire/transport internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
func LoadCA(caPath string) (*x509.CertPool, error) {
	// Check if the CA path exists.
	if !IsFileExist(caPath) {
		return nil, fmt.Errorf("CA path not found: %s", caPath)
	}

	// Get information about the CA path (file or directory).
	info, err := os.Stat(caPath)
	if err != nil {
		return nil, fmt.Errorf("error stating CA path: %v", err)
	}

	// If the path is a file, load a single CA certificate.
	if !info.IsDir() {
		return LoadCACertificate(caPath)
	}

	// If the path is a directory, load all CA certificates in the directory.
	return LoadCACertificates(caPath)
}

// LoadCACertificate loads a single CA certificate from a file and returns a CertPool containing it.
// Wire/transport internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
func LoadCACertificate(certFile string) (*x509.CertPool, error) {
	// Read the certificate file from the provided path.
	caCrt, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Create a new certificate pool.
	certPool := x509.NewCertPool()

	// Append the certificate to the pool. If it fails, return an error.
	if !certPool.AppendCertsFromPEM(caCrt) {
		return nil, fmt.Errorf("failed to append certs from PEM file: %s", certFile)
	}

	// Return the populated certificate pool.
	return certPool, nil
}

// LoadCACertificates loads multiple CA certificates from a directory.
// Wire/transport internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
func LoadCACertificates(certDir string) (*x509.CertPool, error) {
	// Create a new certificate pool.
	caCertPool := x509.NewCertPool()

	// Read the directory contents.
	files, err := os.ReadDir(certDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}

	// Iterate over each file in the directory.
	for _, file := range files {
		// Skip over directories within the cert directory.
		if file.IsDir() {
			continue
		}

		// Build the full certificate path.
		certPath := filepath.Join(certDir, file.Name())

		// Read the certificate file. An unreadable CA file is a hard error:
		// silently skipping it could weaken server verification.
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %s: %w", certPath, err)
		}

		// The directory may hold non-certificate files (README, keys, .DS_Store);
		// skip them so the valid CA certificates still load.
		if ok := caCertPool.AppendCertsFromPEM(certPEM); !ok {
			log.Printf("skipping %s: no PEM certificates found in file", certPath)
			continue
		}
	}

	// Return the populated certificate pool.
	return caCertPool, nil
}

// ParseURL parses the given input string into a URL object.
// It ensures that the URL has a valid scheme and host, adding "https://" as the default scheme if necessary.
func ParseURL(input string) (*url.URL, error) {
	// Trim any whitespace from the input string.
	input = strings.TrimSpace(input)

	// If the input is empty, return an error.
	if input == "" {
		return nil, fmt.Errorf("input is empty")
	}

	// If no scheme (e.g., "http://") is present, add "https://" as a default.
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	// Parse the input string into a URL object.
	parsedURL, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	// Ensure the scheme (e.g., "http" or "https") is lowercase.
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)

	// If no host is present but a path is, assume the path is actually the host.
	if parsedURL.Host == "" && parsedURL.Path != "" {
		parsedURL.Host = parsedURL.Path
		parsedURL.Path = ""
	}

	// Return the parsed URL object.
	return parsedURL, nil
}

// setTCPNoDelay disables Nagle's algorithm for the given net.Conn,
// and supports both TCP and TLS connections.
func setTCPNoDelay(conn net.Conn) error {
	var tcpConn *net.TCPConn

	switch c := conn.(type) {
	case *net.TCPConn:
		tcpConn = c
	case *tls.Conn:
		// Try to unwrap tls.Conn to get the underlying net.TCPConn
		if innerConn, ok := c.NetConn().(*net.TCPConn); ok {
			tcpConn = innerConn
		} else {
			return errors.New("tls.Conn does not wrap *net.TCPConn")
		}
	default:
		return errors.New("unsupported connection type")
	}

	if tcpConn == nil {
		return errors.New("not a TCP connection")
	}

	return tcpConn.SetNoDelay(true)
}

// HtmlUnescapeBytes unescapes HTML entities in b, returning b unchanged when no entities are present.
// Wire/transport internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
func HtmlUnescapeBytes(b []byte) []byte {
	if !bytes.Contains(b, []byte{'&'}) {
		return b
	}
	return []byte(html.UnescapeString(string(b)))
}
