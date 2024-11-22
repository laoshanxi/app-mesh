package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

var (
	DockerSocketFilePath = "/var/run/docker.sock"
)

const (
	DockerPathPrefix         = "/appmesh/docker"
	DOCKER_REQUEST_ID_HEADER = "X-Request-ID"

	ReadTimeout     = 30 * time.Second
	WriteTimeout    = 30 * time.Second
	IdleConnTimeout = 30 * time.Second
	MaxIdleConns    = 100
)

// DockerProxy handles the reverse proxy for Docker requests.
type DockerProxy struct {
	transport *http.Transport
}

// NewDockerProxy initializes a DockerProxy.
func NewDockerProxy() *DockerProxy {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial("unix", DockerSocketFilePath)
		},
		ResponseHeaderTimeout: ReadTimeout,
		IdleConnTimeout:       IdleConnTimeout,
		MaxIdleConns:          MaxIdleConns,
	}

	return &DockerProxy{transport: transport}
}

// ServeHTTP handles incoming requests, forwarding them to Docker.
func (dp *DockerProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("Received request: %s %s %s", r.RemoteAddr, r.Method, r.URL)

	// Remove the /appmesh/docker prefix from the path
	r.URL.Path = strings.TrimPrefix(r.URL.Path, DockerPathPrefix)
	if r.URL.Path == "" {
		r.URL.Path = "/"
	}

	// PSK verify
	pskMsg := r.Header.Get(DOCKER_REQUEST_ID_HEADER)
	pskMsgHmac := r.Header.Get(cloud.HTTP_HEADER_MHAC)
	if cloud.HMAC == nil || !cloud.HMAC.VerifyHMAC(pskMsg, pskMsgHmac) {
		http.Error(w, "PSK authentication failed", http.StatusProxyAuthRequired)
		return
	}
	r.Header.Del(DOCKER_REQUEST_ID_HEADER)
	r.Header.Del(cloud.HTTP_HEADER_MHAC)
	logger.Debug("PSK authentication success")

	// Do proxy
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
			logger.Errorf("Proxy error: %v", err)
			http.Error(w, "Bad Gateway: " + err.Error(), http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Connection")
			logger.Debugf("Response: %s %s %s %d", resp.Request.Method, resp.Request.RemoteAddr, resp.Request.RequestURI, resp.StatusCode)
			return nil
		},
	}
}

// RegisterDockerRoutes registers Docker routes with the provided router.
func RegisterDockerRoutes(router *mux.Router) error {
	if !appmesh.IsFileExist(DockerSocketFilePath) {
		return fmt.Errorf("docker socket file not found: %s", DockerSocketFilePath)
	}

	dp := NewDockerProxy()

	// Register all Docker API paths
	router.PathPrefix(DockerPathPrefix).Handler(http.HandlerFunc(dp.ServeHTTP))

	return nil
}
