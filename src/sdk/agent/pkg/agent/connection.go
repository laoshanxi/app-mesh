// connection.go
package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

var (
	remoteConnections      sync.Map
	remoteConnectionsMutex sync.Mutex
)

type Connection struct {
	addr net.Addr
	*appmesh.TCPConnection

	pending      map[string]chan *Response
	pendingMu    sync.Mutex // Protects pending map
	atomicSendMu sync.Mutex // Protects TCP message send

	closed    chan struct{}
	closeOnce sync.Once
}

// GetOrCreateConnection returns an existing connection or creates a new one.
func GetOrCreateConnection(tcpAddress net.Addr, verifyServer, allowError bool) (*Connection, error) {
	// Check if connection already exists (without holding lock during creation)
	if conn, ok := remoteConnections.Load(tcpAddress); ok {
		return conn.(*Connection), nil
	}

	remoteConnectionsMutex.Lock()
	defer remoteConnectionsMutex.Unlock()

	// Double-check after acquiring lock
	if conn, ok := remoteConnections.Load(tcpAddress); ok {
		return conn.(*Connection), nil
	}

	sConn := &Connection{
		addr:          tcpAddress,
		TCPConnection: appmesh.NewTCPConnection(),
		pending:       make(map[string]chan *Response),
		closed:        make(chan struct{}),
	}

	clientCert := config.ConfigData.REST.SSL.SSLClientCertificateFile
	clientCertKey := config.ConfigData.REST.SSL.SSLClientCertificateKeyFile
	caPath := config.ConfigData.REST.SSL.SSLCaPath
	if !verifyServer {
		caPath = ""
	}

	logger.Infof("Connecting to %s (CA: %q, Cert: %q, Key: %q)", tcpAddress, caPath, clientCert, clientCertKey)
	if err := sConn.Connect(tcpAddress, clientCert, clientCertKey, caPath); err != nil {
		logger.Errorf("Failed to connect to %s: %v", tcpAddress, err)
		return nil, fmt.Errorf("connect to %s: %w", tcpAddress, err)
	}

	remoteConnections.Store(sConn.addr, sConn)

	go func() {
		logger.Infof("Monitoring response from: %s", tcpAddress)
		MonitorConnectionResponse(sConn, allowError)
	}()

	return sConn, nil
}

func (c *Connection) String() string {
	return c.addr.String()
}

// SendRequestDataWithContext serializes and sends request data.
func (c *Connection) SendRequestDataWithContext(ctx context.Context, request *appmesh.Request) (*Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled before sending: %w", err)
	}

	// Check if connection is closed
	select {
	case <-c.closed:
		return nil, fmt.Errorf("connection closed")
	default:
	}

	bodyData, err := request.Serialize()
	if err != nil {
		return nil, fmt.Errorf("serialize request %s: %w", request.UUID, err)
	}

	logger.Debugf("Sending request: %s %s %s %s", request.ClientAddress, request.HttpMethod, request.RequestUri, request.UUID)

	respCh := c.registerPendingResp(request.UUID)
	defer c.unregisterPendingResp(request.UUID)

	// Protect send to ensure thread-safety
	c.atomicSendMu.Lock()
	err = c.SendMessage(ctx, bodyData)
	c.atomicSendMu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("send request %s: %w", request.UUID, err)
	}

	return c.waitForResponse(ctx, request.UUID, respCh)
}

func (c *Connection) waitForResponse(ctx context.Context, uuid string, respCh <-chan *Response) (*Response, error) {
	select {
	case <-c.closed:
		return nil, fmt.Errorf("connection closed (UUID: %s)", uuid)

	case <-ctx.Done():
		// Handle timeout or cancellation
		switch ctx.Err() {
		case context.DeadlineExceeded:
			logger.Warnf("Request timeout for UUID: %s", uuid)
		case context.Canceled:
			logger.Warnf("Request canceled for UUID: %s", uuid)
		}
		return nil, fmt.Errorf("request %s: %w", uuid, ctx.Err())

	case resp, ok := <-respCh:
		if !ok {
			return nil, fmt.Errorf("response channel closed (UUID: %s)", uuid)
		}
		return resp, nil
	}
}

// registerPendingResp registers a response channel for a request.
func (c *Connection) registerPendingResp(uuid string) chan *Response {
	ch := make(chan *Response, 1) // Buffered to avoid blocking sender
	c.pendingMu.Lock()
	c.pending[uuid] = ch
	c.pendingMu.Unlock()
	return ch
}

// unregisterPendingResp removes a pending response and closes its channel.
func (c *Connection) unregisterPendingResp(uuid string) {
	c.pendingMu.Lock()
	ch, exists := c.pending[uuid]
	if exists {
		delete(c.pending, uuid)
	}
	c.pendingMu.Unlock()

	if exists {
		close(ch)
	}
}

// loadAndDeletePendingResp safely retrieves and removes a pending response.
func (c *Connection) loadAndDeletePendingResp(uuid string) (chan *Response, bool) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	ch, ok := c.pending[uuid]
	if ok {
		delete(c.pending, uuid)
	}
	return ch, ok
}

// onResponse delivers a received response to its waiting request.
func (c *Connection) onResponse(response *Response) {
	uuid := response.UUID
	ch, ok := c.loadAndDeletePendingResp(uuid)
	if !ok {
		logger.Warnf("Request ID <%s> not found for response (likely timed out or canceled)", uuid)
		return
	}

	// Non-blocking send to avoid deadlock if receiver already closed
	select {
	case ch <- response:
	default:
		logger.Warnf("Failed to send response for request <%s> (channel closed/full)", uuid)
	}
}

// SendFileDataWithContext uploads a file in chunks with context support.
func (c *Connection) SendFileDataWithContext(ctx context.Context, localFile string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("open file %q: %w", localFile, err)
	}

	defer file.Close()

	reader := bufio.NewReaderSize(file, TCP_CHUNK_BLOCK_SIZE)
	buf := make([]byte, TCP_CHUNK_BLOCK_SIZE)

	c.atomicSendMu.Lock()
	defer c.atomicSendMu.Unlock()

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("file upload cancelled: %w", err)
		}

		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read file %q: %w", localFile, err)
		}
		if n == 0 {
			break
		}
		if err := c.SendMessage(ctx, buf[:n]); err != nil {
			return fmt.Errorf("send file chunk: %w", err)
		}
	}

	// Send EOF marker
	return c.SendMessage(ctx, []byte{})
}

// DeleteConnection closes and removes a connection from the pool.
func DeleteConnection(target *Connection) {
	if value, ok := remoteConnections.LoadAndDelete(target.addr); ok {
		if conn, ok := value.(*Connection); ok {
			conn.Close()
			logger.Infof("Removed connection: %s", target)
		}
	}
}

// Close closes the connection and cleans up all pending responses.
func (c *Connection) Close() {
	c.closeOnce.Do(func() {
		close(c.closed) // Signal that connection is closing

		if c.TCPConnection != nil {
			c.TCPConnection.Close() // Close underlying TCP connection
		}

		c.pendingMu.Lock()
		pendings := c.pending
		c.pending = make(map[string]chan *Response)
		c.pendingMu.Unlock()

		for uuid, ch := range pendings {
			close(ch)
			logger.Debugf("Closed pending response channel for UUID: %s", uuid)
		}

		logger.Debugf("Connection closed and cleaned up: %s", c.addr)
	})
}
