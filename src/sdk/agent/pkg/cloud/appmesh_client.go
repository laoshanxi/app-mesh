package cloud

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
	"go.uber.org/zap"
)

// AppMesh wraps AppMeshClientTCP with a mutex for thread safety
type AppMesh struct {
	*appmesh.AppMeshClientTCP
	mu sync.Mutex
}

// Request represents the message sent over TCP
type Request struct {
	appmesh.Request
}

var logger *zap.SugaredLogger = utils.GetLogger()

// SetHMACVerify sets the HMAC header for the request if HMAC is initialized
func (r *Request) SetHMACVerify() error {
	if HMAC == nil {
		return fmt.Errorf("HMAC not initialized")
	}
	r.Headers[HTTP_HEADER_HMAC] = HMAC.GenerateHMAC(r.Uuid)
	return nil
}

// NewAppMeshClient creates and returns a new AppMesh client for interacting with a TCP server
func NewAppMeshClient() *AppMesh {
	// Replace '0.0.0.0' with '127.0.0.1' to ensure correct loopback address
	targetHost := strings.Replace(config.ConfigData.REST.RestListenAddress, "0.0.0.0", "127.0.0.1", 1)
	uri := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", targetHost, config.ConfigData.REST.RestTcpPort),
	}

	client := &AppMesh{}
	var err error
	client.AppMeshClientTCP, err = appmesh.NewTcpClient(appmesh.Option{
		AppMeshUri:                  uri.String(),
		SslTrustedCA:                &config.ConfigData.REST.SSL.SSLCaPath,
		SslClientCertificateFile:    config.ConfigData.REST.SSL.SSLClientCertificateFile,
		SslClientCertificateKeyFile: config.ConfigData.REST.SSL.SSLClientCertificateKeyFile,
	})
	if err != nil {
		logger.Fatalf("Failed to establish TCP connection for cloud operator: %v", err)
	}
	return client
}

// GetHostResources retrieves cloud resources via a TCP request
func (r *AppMesh) GetHostResources() (string, error) {
	data := r.generateRequest()
	data.HttpMethod = http.MethodGet
	data.RequestUri = "/appmesh/cloud/resources" // This URI relies on PSK (Pre-Shared Key) check instead of permission check

	resp, err := r.request(data)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("no response received from cloud resource request")
	}
	if resp.HttpStatus != http.StatusOK {
		return "", fmt.Errorf("failed to retrieve cloud resource, status: %d, body: %s", resp.HttpStatus, resp.Body)
	}

	return resp.Body, nil
}

// generateRequest creates and returns a new Request with a unique UUID
func (r *AppMesh) generateRequest() *Request {
	return &Request{
		Request: appmesh.Request{
			Uuid:    xid.New().String(),
			Headers: make(map[string]string),
			Queries: make(map[string]string),
		},
	}
}

// request sends a TCP request and returns the response
func (r *AppMesh) request(data *Request) (*appmesh.Response, error) {
	// Set HMAC verification for the request
	if err := data.SetHMACVerify(); err != nil {
		return nil, err
	}

	// Serialize the request
	buf, err := data.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %v", err)
	}

	// Lock the mutex for thread-safe communication
	r.mu.Lock()
	defer r.mu.Unlock()

	// Send the data over TCP
	if err := r.AppMeshClientTCP.TcpExecutor.SendMessage(buf); err != nil {
		return nil, fmt.Errorf("failed to send data: %v", err)
	}

	// Receive the response over TCP
	respData, err := r.AppMeshClientTCP.TcpExecutor.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("failed to receive data: %v", err)
	}

	// Deserialize the response
	respMsg := &appmesh.Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, fmt.Errorf("failed to deserialize response: %v", err)
	}

	return respMsg, nil
}
