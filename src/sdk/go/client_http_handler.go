package appmesh

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

func newHttpClient(clientCertFile string, clientCertKeyFile string, caFile string) *http.Client {
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

	jar, err := cookiejar.New(
		&cookiejar.Options{
			PublicSuffixList: publicsuffix.List,
		})
	if err != nil {
		fmt.Println("Error creating cookie jar:", err)
	}

	return &http.Client{
		Timeout: 2 * time.Minute, // Overall timeout for the entire request
		Jar:     jar,             // Cookie jar for session management
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCert,                        // Trusted root CAs
				InsecureSkipVerify: (caCert == nil),               // Skip verification if no CA provided
				Certificates:       []tls.Certificate{clientCert}, // Client certificates for mutual TLS
			},

			// Connection pooling configuration
			MaxIdleConns:          100,              // Good default for moderate traffic
			MaxIdleConnsPerHost:   20,               // Increased for better connection reuse
			IdleConnTimeout:       90 * time.Second, // Standard timeout for idle connections
			MaxConnsPerHost:       100,              // Balanced limit for concurrent connections
			ResponseHeaderTimeout: 10 * time.Second, // Reasonable timeout for response headers

			// Additional optimizations
			ForceAttemptHTTP2:  true,  // Enable HTTP/2 support
			DisableKeepAlives:  false, // Keep connection pooling enabled
			DisableCompression: false, // Allow compression for better performance
		}}
}

// REST GET
func (r *AppMeshClient) get(path string, params url.Values, headers map[string]string) (int, []byte, http.Header, error) {
	return r.Proxy.DoRequest("GET", path, params, headers, nil, r.getToken(), r.getForwardTo())
}

// REST PUT
func (r *AppMeshClient) put(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, error) {
	code, raw, _, err := r.Proxy.DoRequest("PUT", path, params, headers, bytes.NewBuffer(body), r.getToken(), r.getForwardTo())
	return code, raw, err
}

// REST POST
func (r *AppMeshClient) post(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	return r.Proxy.DoRequest("POST", path, params, headers, bytes.NewBuffer(body), r.getToken(), r.getForwardTo())
}

// REST DELETE
func (r *AppMeshClient) delete(path string) (int, []byte, error) {
	code, raw, _, err := r.Proxy.DoRequest("DELETE", path, nil, nil, nil, r.getToken(), r.getForwardTo())
	return code, raw, err
}

// HTTP Request executor
type ClientRequesterRest struct {
	baseURL    string
	httpClient *http.Client
}

// REST request
func (r *ClientRequesterRest) DoRequest(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader, token string, forwardingHost string) (int, []byte, http.Header, error) {
	u, _ := url.Parse(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	// Set headers
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if forwardingHost != "" {
		if strings.Contains(forwardingHost, ":") {
			req.Header.Set("X-Target-Host", forwardingHost)
		} else {
			req.Header.Set("X-Target-Host", forwardingHost+":"+u.Port())
		}
	}
	req.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := r.httpClient.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return 0, nil, nil, err
	}
	if resp != nil {
		defer resp.Body.Close()
	}
	data, err := io.ReadAll(resp.Body)
	return resp.StatusCode, data, resp.Header, err
}
