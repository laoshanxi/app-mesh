package appmesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const TCP_CONNECT_TIMEOUT_SECONDS = 30

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

		// Read the certificate file.
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			// Log an error and continue on failure to read a certificate.
			fmt.Printf("failed to read file %s: %v", certPath, err)
			continue
		}

		// Try to append the certificate to the pool. Log a warning if it fails.
		if ok := caCertPool.AppendCertsFromPEM(certPEM); !ok {
			fmt.Printf("failed to append certificate from %s", certPath)
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

	// Regular expression to match IP addresses.
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)

	// Check if the input includes a scheme (e.g., "http://").
	hasScheme := strings.Contains(input, "://")

	// If the input is an IP address without a scheme, prefix it with "https://".
	if ipRegex.MatchString(input) && !hasScheme {
		input = "https://" + input
	} else if !hasScheme {
		// If no scheme is present, add "https://" as a default.
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

// MergeStringMaps merges two string maps, with values from the second map overwriting those in the first.
func MergeStringMaps(map1, map2 map[string]string) {
	// Copy all entries from map2 to map1
	for key, value := range map2 {
		map1[key] = value
	}
}

// SetFileAttributes applies file mode and ownership (UID, GID) to a given file based on HTTP headers.
func SetFileAttributes(filePath string, headers http.Header) error {
	// Apply file mode if provided
	if fileModeStr := headers.Get("X-File-Mode"); fileModeStr != "" {
		mode, err := strconv.ParseUint(fileModeStr, 10, 32)
		if err != nil {
			return fmt.Errorf("invalid file mode: %w", err)
		}
		if err := os.Chmod(filePath, os.FileMode(uint32(mode))); err != nil {
			return fmt.Errorf("failed to change file mode: %w", err)
		}
	}

	// Apply file ownership (UID, GID) if provided
	fileUserStr := headers.Get("X-File-User")
	fileGroupStr := headers.Get("X-File-Group")

	if fileUserStr != "" || fileGroupStr != "" {
		uid := -1 // Default to -1 (no change) unless provided
		gid := -1 // Default to -1 (no change) unless provided

		if fileUserStr != "" {
			parsedUID, err := strconv.Atoi(fileUserStr)
			if err != nil {
				return fmt.Errorf("invalid UID: %w", err)
			}
			uid = parsedUID
		}

		if fileGroupStr != "" {
			parsedGID, err := strconv.Atoi(fileGroupStr)
			if err != nil {
				return fmt.Errorf("invalid GID: %w", err)
			}
			gid = parsedGID
		}

		if err := os.Chown(filePath, uid, gid); err != nil {
			return fmt.Errorf("failed to change file ownership: %w", err)
		}
	}

	return nil
}

// SetTcpNoDelay disables Nagle's algorithm for the given net.Conn,
// and supports both TCP and TLS connections.
func SetTcpNoDelay(conn net.Conn) error {
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

// PrettyJSON takes a JSON string as input and returns a formatted, indented JSON string.
func PrettyJSON(input string) (string, error) {
	// Check if the input string is empty
	if len(input) == 0 {
		return "", errors.New("input JSON string is empty")
	}

	// Create a buffer to store the formatted output
	var out bytes.Buffer

	// Create a new JSON decoder to parse the input string
	decoder := json.NewDecoder(bytes.NewReader([]byte(input)))
	// Create a new JSON encoder to write the formatted output
	encoder := json.NewEncoder(&out)
	// Set the indentation to two spaces
	encoder.SetIndent("", "  ")

	// Create a variable to hold the parsed JSON data
	var jsonData interface{}
	// Attempt to decode the input JSON
	if err := decoder.Decode(&jsonData); err != nil {
		return "", fmt.Errorf("invalid JSON: %v", err)
	}

	// Check if the parsed JSON data is nil (empty object or array)
	if jsonData == nil {
		return "", errors.New("parsed JSON data is empty")
	}

	// Encode the parsed JSON data with proper indentation
	if err := encoder.Encode(jsonData); err != nil {
		return "", fmt.Errorf("failed to format JSON: %v", err)
	}

	// Return the formatted JSON string
	return out.String(), nil
}
