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

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

func NewHttpClient(clientCertFile string, clientCertKeyFile string, caFile string) *http.Client {
	// Load client certificate and key
	clientCert := utils.LoadCertificatePair(clientCertFile, clientCertKeyFile)
	// load server CA
	caCert, _ := utils.LoadCA(caFile)

	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:            caCert,
			InsecureSkipVerify: (caCert == nil),
			Certificates:       []tls.Certificate{clientCert},
		}}}
}

// REST GET

func (r *AppMeshClient) get(path string, params url.Values, headers map[string]string) (int, []byte, http.Header, error) {
	return r.doRequest("GET", path, params, headers, nil)
}

// REST PUT
func (r *AppMeshClient) put(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, error) {
	code, raw, _, err := r.doRequest("PUT", path, params, headers, bytes.NewBuffer(body))
	return code, raw, err
}

// REST POST
func (r *AppMeshClient) post(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	return r.doRequest("POST", path, params, headers, bytes.NewBuffer(body))
}

// REST DELETE
func (r *AppMeshClient) delete(path string) (int, []byte, error) {
	code, raw, _, err := r.doRequest("DELETE", path, nil, nil, nil)
	return code, raw, err
}

// REST request
func (r *AppMeshClient) doRequest(method string, apiPath string, params url.Values, headers map[string]string, buf io.Reader) (int, []byte, http.Header, error) {
	u, _ := url.Parse(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return 0, nil, nil, err
	}

	// headers
	if r.getToken() != "" {
		req.Header.Set("Authorization", "Bearer "+r.getToken())
	}
	if r.getDelegateHost() != "" {
		if strings.Contains(r.getDelegateHost(), ":") {
			req.Header.Set("X-Target-Host", r.getDelegateHost())
		} else {
			req.Header.Set("X-Target-Host", r.getDelegateHost()+":"+u.Port())
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
