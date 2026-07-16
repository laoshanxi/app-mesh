package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger = utils.GetLogger()

// AppMesh wraps AppMeshClientTCP with a mutex for thread safety
type AppMesh struct {
	*appmesh.AppMeshClientTCP
	mu sync.Mutex
}

// NewAppMeshClient creates and returns a new AppMesh client for interacting with a TCP server.
func NewAppMeshClient() (*AppMesh, error) {
	client := &AppMesh{}
	if err := client.connect(); err != nil {
		return nil, err
	}
	return client, nil
}

// connect dials (or re-dials) the TCP transport, replacing any existing connection.
// Callers that re-dial an in-use client must hold r.mu.
func (r *AppMesh) connect() error {
	// Replace '0.0.0.0' with '127.0.0.1' to ensure correct loopback address
	targetHost := strings.Replace(config.ConfigData.REST.RestListenAddress, "0.0.0.0", "127.0.0.1", 1)
	uri := url.URL{
		Scheme: "https",
		Host:   fmt.Sprintf("%s:%d", targetHost, config.ConfigData.REST.RestTcpPort),
	}

	opt := appmesh.Option{
		AppMeshUri:                  uri.String(),
		SslClientCertificateFile:    config.ConfigData.REST.SSL.SSLClientCertificateFile,
		SslClientCertificateKeyFile: config.ConfigData.REST.SSL.SSLClientCertificateKeyFile,
	}
	// Empty configured CA path = verification disabled; the SDK requires the explicit insecure flag for that.
	if caPath := config.ConfigData.REST.SSL.SSLCaPath; caPath != "" {
		opt.SslTrustedCA = &caPath
	} else {
		opt.InsecureSkipVerify = true
	}
	tcp, err := appmesh.NewTCPClient(opt)
	if err != nil {
		return fmt.Errorf("failed to establish TCP connection for cloud operator: %w", err)
	}
	r.AppMeshClientTCP = tcp
	return nil
}

// GetHostResources retrieves cloud resources via a TCP request
func (r *AppMesh) GetHostResources(ctx context.Context) (map[string]interface{}, error) {
	data := r.newRequest()
	data.HttpMethod = http.MethodGet
	data.RequestUri = "/appmesh/cloud/resources" // This URI relies on PSK (Pre-Shared Key) check instead of permission check

	resp, err := r.request(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp == nil {
		return nil, fmt.Errorf("no response received from cloud resource request")
	}
	if resp.HttpStatus != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve cloud resource, status: %d", resp.HttpStatus)
	}
	if len(resp.Body) == 0 {
		return nil, fmt.Errorf("empty response body from cloud resource request")
	}

	var m map[string]interface{}
	if err := json.Unmarshal(resp.Body, &m); err != nil {
		return nil, fmt.Errorf("failed to parse cloud resource response: %w", err)
	}
	return m, nil
}

// request sends a TCP request and returns the response
func (r *AppMesh) request(ctx context.Context, data *Request) (*appmesh.Response, error) {
	// Set HMAC verification for the request
	if err := data.setHMACVerify(); err != nil {
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

	resp, err := r.roundTrip(ctx, buf)
	// Don't reconnect on caller cancellation/timeout — the failure isn't a stale
	// connection, and re-dialing would waste a handshake (and retry idempotently
	// only because this RPC is a GET; see roundTrip).
	if err != nil && ctx.Err() == nil {
		// The long-lived TCP connection may be stale (daemon restart / dropped peer),
		// which would otherwise fail every future report until agent restart. Re-dial
		// once and retry so periodic resource reporting self-heals.
		logger.Warnf("cloud TCP request failed (%v); reconnecting and retrying once", err)
		if r.AppMeshClientTCP != nil {
			r.AppMeshClientTCP.CloseConnection()
		}
		if cerr := r.connect(); cerr != nil {
			return nil, fmt.Errorf("reconnect after error %q failed: %w", err, cerr)
		}
		resp, err = r.roundTrip(ctx, buf)
	}
	return resp, err
}

// roundTrip sends one request and reads its response over the current connection.
// The caller must hold r.mu.
func (r *AppMesh) roundTrip(ctx context.Context, buf []byte) (*appmesh.Response, error) {
	// Send the data over TCP
	if err := r.AppMeshClientTCP.SendMessage(ctx, buf); err != nil {
		return nil, fmt.Errorf("failed to send data: %v", err)
	}

	// Receive the response over TCP
	respData, err := r.AppMeshClientTCP.ReadMessage()
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

// Request represents the message sent over TCP
type Request struct {
	*appmesh.Request
}

// newRequest creates and returns a new Request with a unique UUID
func (r *AppMesh) newRequest() *Request {
	return &Request{appmesh.NewRequest()}
}

// setHMACVerify sets the HMAC header for the request if HMAC is initialized
func (r *Request) setHMACVerify() error {
	if HMAC_AgentToCPP == nil {
		return fmt.Errorf("HMAC not initialized")
	}
	r.Headers[HTTP_HEADER_HMAC] = HMAC_AgentToCPP.GenerateHMAC(r.UUID)
	return nil
}
