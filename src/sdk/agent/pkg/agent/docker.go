package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// Test: curl --cert /opt/appmesh/ssl/client.pem --key /opt/appmesh/ssl/client-key.pem --cacert /opt/appmesh/ssl/ca.pem  https://localhost:6058/containers/json | python3 -m json.tool
// TODO: re-use 6060 listen port, enable JWT authentication

var (
	DockerSocketFilePath = "/var/run/docker.sock"
	DockerListenAddress  = ""
)

const (
	ReadTimeout     = 30 * time.Second
	WriteTimeout    = 30 * time.Second
	IdleConnTimeout = 10 * time.Second
	MaxIdleConns    = 100
)

// DockerProxy handles the HTTPS reverse proxy for Docker requests.
type DockerProxy struct {
	transport *http.Transport
}

// NewDockerProxy initializes a DockerProxy with HTTPS configuration.
func NewDockerProxy(certFile, certKeyFile, caFile string) (*DockerProxy, error) {
	clientCert, err := appmesh.LoadCertificatePair(certFile, certKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate and key: %w", err)
	}

	caCert, err := appmesh.LoadCA(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:            caCert,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: caCert == nil,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", DockerSocketFilePath)
		},
		ResponseHeaderTimeout: ReadTimeout,
		IdleConnTimeout:       IdleConnTimeout,
		MaxIdleConns:          MaxIdleConns,
		TLSClientConfig:       tlsConfig,
	}

	return &DockerProxy{transport: transport}, nil
}

// ServeHTTP handles incoming HTTPS requests, forwarding them to Docker.
func (dp *DockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logRequest(r)
	proxy := dp.createReverseProxy()
	proxy.ServeHTTP(w, r)
}

// createReverseProxy creates a reverse proxy for Docker with custom transport and error handling.
func (dp *DockerProxy) createReverseProxy() *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = "http"
			req.URL.Host = DockerSocketFilePath
			req.Header.Del("Connection")
			req.Header.Del("Keep-Alive")
		},
		Transport: dp.transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Connection")
			logResponse(resp)
			return nil
		},
	}
}

// startHTTPSDockerAgentServer initializes and starts an HTTPS server for DockerProxy.
func (dp *DockerProxy) startHTTPSDockerAgentServer(addr, certFile, keyFile string) error {
	server := &http.Server{
		Addr:         addr,
		Handler:      dp,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
	}

	log.Printf("Starting HTTPS server on %s", addr)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ListenDocker initializes and starts the DockerProxy if Docker socket exists.
func ListenDocker(certFile, keyFile, caFile string) error {
	if !appmesh.IsFileExist(DockerSocketFilePath) {
		return fmt.Errorf("docker socket file not found: %s", DockerSocketFilePath)
	}

	addr, err := parseDockerAgentAddress(DockerListenAddress)
	if err != nil {
		return err
	}

	dp, err := NewDockerProxy(certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("failed to create DockerProxy: %w", err)
	}

	return dp.startHTTPSDockerAgentServer(addr, certFile, keyFile)
}

// parseDockerAgentAddress parses and validates the Docker agent address.
func parseDockerAgentAddress(dockerAgentAddr string) (string, error) {
	addr, err := appmesh.ParseURL(dockerAgentAddr)
	if err != nil {
		return "", fmt.Errorf("invalid docker agent address: %w", err)
	}
	return net.JoinHostPort(addr.Hostname(), addr.Port()), nil
}

// logRequest logs details of incoming requests.
func logRequest(r *http.Request) {
	if log.Default().Flags()&log.Lshortfile != 0 {
		log.Printf("Received request: %s %s", r.Method, r.URL)
	}
}

// logResponse logs details of outgoing responses.
func logResponse(resp *http.Response) {
	if log.Default().Flags()&log.Lshortfile != 0 {
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			log.Printf("Response: %s", string(body))
			resp.Body = io.NopCloser(bytes.NewReader(body)) // Rewrap for further handling
		}
	}
}
