package appmesh

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

const (
	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	HTTP_USER_AGENT             = "appmeshsdk/go"
)

var (
	defaultHTTPClient           = &http.Client{Transport: &http.Transport{TLSClientConfig: getTlsConf()}}
	SSLClientCertificateFile    = "/opt/appmesh/ssl/client.pem"
	SSLClientCertificateKeyFile = "/opt/appmesh/ssl/client-key.pem"
	SSLTrustedCA                = "/opt/appmesh/ssl/ca.pem"
)

func getRestClient() *http.Client {
	return defaultHTTPClient
}

func getTlsConf() *tls.Config {
	// Load client certificate and key
	cert := utils.LoadCertificatePair(SSLClientCertificateFile, SSLClientCertificateKeyFile)

	// load root CA
	var certPool *x509.CertPool
	if utils.IsFileExist(SSLTrustedCA) {
		if fileInfo, err := os.Stat(SSLTrustedCA); !os.IsNotExist(err) {
			if fileInfo.IsDir() {
				certPool, _ = utils.LoadCACertificates(SSLTrustedCA)
			} else {
				certPool, _ = utils.LoadCACertificate(SSLTrustedCA)
			}
		} else {
			log.Printf("ca file %s does not exist or empty.", SSLTrustedCA)
			panic(err)
		}
	}

	return &tls.Config{
		RootCAs:      certPool,
		Certificates: []tls.Certificate{cert},
	}
}

// REST GET
func (r *AppmeshClient) get(path string, params url.Values) ([]byte, int, http.Header, error) {
	return r.doRequest("GET", path, params, nil, nil)
}

// REST PUT
func (r *AppmeshClient) put(path string, params url.Values, headers map[string]string, body []byte) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("PUT", path, params, headers, bytes.NewBuffer(body))
	return raw, code, err
}

// REST POST
func (r *AppmeshClient) post(path string, params url.Values, headers map[string]string, body []byte) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("POST", path, params, headers, bytes.NewBuffer(body))
	return raw, code, err
}

// REST DELETE
func (r *AppmeshClient) delete(path string) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("DELETE", path, nil, nil, nil)
	return raw, code, err
}

// REST request
func (r *AppmeshClient) doRequest(method string, apiPath string, params url.Values, headers map[string]string, buf io.Reader) ([]byte, int, http.Header, error) {
	u, _ := url.Parse(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, 0, nil, err
	}

	// headers
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT)
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := r.client.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return nil, 0, nil, err
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(string(data))
	}
	// https://www.cnblogs.com/wangjiale1024/p/10979993.html
	return data, resp.StatusCode, resp.Header, err
}
