package appmesh

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
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

	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            caCert,
				InsecureSkipVerify: (caCert == nil),
				Certificates:       []tls.Certificate{clientCert},
			}}}
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
	mutex      sync.Mutex
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

	r.mutex.Lock()
	defer r.mutex.Unlock()
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
