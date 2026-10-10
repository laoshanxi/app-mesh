// connection.go
package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

var (
	remoteConnections      sync.Map
	remoteConnectionsMutex sync.Mutex

	// Unix-nano time of the last warned TCP dial failure (throttles the WSS fallback log).
	lastTCPDialWarnNs atomic.Int64
)

type Connection struct {
	key string // pool key, also identifies the transport ("tcp://..." or "wss://...")
	messageConnection

	pending      map[string]chan *Response
	pendingMu    sync.Mutex // Protects pending map
	atomicSendMu sync.Mutex // Protects TCP message send

	closed    chan struct{}
	closeOnce sync.Once
}

// messageConnection abstracts the msgpack frame transport to the daemon.
// *appmesh.TCPConnection (length-prefixed TCP/TLS frames) and
// *appmesh.WSSConnection (binary WebSocket frames) both satisfy it.
type messageConnection interface {
	ReadMessage() ([]byte, error)
	SendMessage(ctx context.Context, buffer []byte) error
	Close()
	ClientAddress() string
}

// getOrCreateConnection returns an existing connection or creates a new one.
func getOrCreateConnection(tcpAddress net.Addr, verifyServer, allowError bool) (*Connection, error) {
	key := "tcp://" + tcpAddress.String()

	// Check if connection already exists (without holding lock during creation)
	if conn, ok := remoteConnections.Load(key); ok {
		return conn.(*Connection), nil
	}

	remoteConnectionsMutex.Lock()
	defer remoteConnectionsMutex.Unlock()

	// Double-check after acquiring lock
	if conn, ok := remoteConnections.Load(key); ok {
		return conn.(*Connection), nil
	}

	sConn := &Connection{
		key:               key,
		messageConnection: appmesh.NewTCPConnection(),
		pending:           make(map[string]chan *Response),
		closed:            make(chan struct{}),
	}

	clientCert := config.ConfigData.REST.SSL.SSLClientCertificateFile
	clientCertKey := config.ConfigData.REST.SSL.SSLClientCertificateKeyFile
	caPath := config.ConfigData.REST.SSL.SSLCaPath
	if !verifyServer {
		caPath = ""
	}

	logger.Infof("Connecting to %s (CA: %q, Cert: %q, Key: %q)", tcpAddress, caPath, clientCert, clientCertKey)
	if err := sConn.messageConnection.(*appmesh.TCPConnection).Connect(tcpAddress, clientCert, clientCertKey, caPath); err != nil {
		logger.Errorf("Failed to connect to %s: %v", tcpAddress, err)
		return nil, fmt.Errorf("connect to %s: %w", tcpAddress, err)
	}

	remoteConnections.Store(key, sConn)

	go func() {
		logger.Infof("Monitoring response from: %s", tcpAddress)
		MonitorConnectionResponse(sConn, allowError)
	}()

	return sConn, nil
}

// wssPoolKey is the pool key of the WSS fallback entry for a host:port.
func wssPoolKey(wssHostPort string) string {
	return "wss://" + wssHostPort
}

// wssPingInterval is the WSS keepalive period; a variable so tests can shorten it.
var wssPingInterval = 60 * time.Second

// keepWSSAlive pings conn until it closes, so a long-poll request is not dropped by the server's idle timeout.
// A failed ping evicts the pooled connection: nobody keeps it alive any more, and the
// server would drop it after its idle timeout.
func keepWSSAlive(conn *Connection, wssURL *url.URL, poolKey string, interval time.Duration, ping func() error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-conn.closed:
			return
		case <-ticker.C:
			if err := ping(); err != nil {
				logger.Warnf("WSS ping to %s failed, dropping the connection: %v", wssURL, err)
				deleteConnectionByKey(poolKey)
				return
			}
		}
	}
}

// reclaimGracePeriod bounds how long a reclaimed connection waits for its
// in-flight requests before it is closed anyway.
const reclaimGracePeriod = 30 * time.Second

// reclaimWSSFallback retires the pooled WSS fallback once TCP works again.
// The entry leaves the pool at once, but the socket stays usable until its
// in-flight requests finish, so the recovery itself does not fail them.
func reclaimWSSFallback(wssHostPort string) {
	quiesceConnection(wssPoolKey(wssHostPort))
}

// quiesceConnection removes the pooled connection and closes it once the last
// in-flight request finishes, bounded by reclaimGracePeriod.
func quiesceConnection(key string) {
	value, ok := remoteConnections.LoadAndDelete(key)
	if !ok {
		return
	}
	conn, ok := value.(*Connection)
	if !ok {
		return
	}
	go func() {
		deadline := time.Now().Add(reclaimGracePeriod)
		for time.Now().Before(deadline) {
			conn.pendingMu.Lock()
			pending := len(conn.pending)
			conn.pendingMu.Unlock()
			if pending == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		conn.close()
	}()
}

// getOrCreateWSSConnection returns a pooled WSS connection to the daemon. It is
// used on platforms where the daemon does not listen on the TCP API port
// (libwebsockets builds serve the msgpack pipeline over WSS only).
func getOrCreateWSSConnection(wssHostPort string, verifyServer bool) (*Connection, error) {
	key := wssPoolKey(wssHostPort)

	if conn, ok := remoteConnections.Load(key); ok {
		return conn.(*Connection), nil
	}

	remoteConnectionsMutex.Lock()
	defer remoteConnectionsMutex.Unlock()

	if conn, ok := remoteConnections.Load(key); ok {
		return conn.(*Connection), nil
	}

	sConn := &Connection{
		key:               key,
		messageConnection: appmesh.NewWSSConnection(),
		pending:           make(map[string]chan *Response),
		closed:            make(chan struct{}),
	}

	clientCert := config.ConfigData.REST.SSL.SSLClientCertificateFile
	clientCertKey := config.ConfigData.REST.SSL.SSLClientCertificateKeyFile
	caPath := config.ConfigData.REST.SSL.SSLCaPath
	if !verifyServer {
		caPath = ""
	}

	wssURL := &url.URL{Scheme: "wss", Host: wssHostPort, Path: "/"}
	logger.Infof("Connecting to %s (CA: %q, Cert: %q, Key: %q)", wssURL, caPath, clientCert, clientCertKey)
	if err := sConn.messageConnection.(*appmesh.WSSConnection).Connect(wssURL, clientCert, clientCertKey, caPath, ""); err != nil {
		logger.Errorf("Failed to connect to %s: %v", wssURL, err)
		return nil, fmt.Errorf("connect to %s: %w", wssURL, err)
	}

	remoteConnections.Store(key, sConn)

	go func() {
		logger.Infof("Monitoring response from: %s", wssURL)
		MonitorConnectionResponse(sConn, false)
	}()

	wss := sConn.messageConnection.(*appmesh.WSSConnection)
	go keepWSSAlive(sConn, wssURL, key, wssPingInterval, wss.Ping)

	return sConn, nil
}

func (c *Connection) String() string {
	return c.key
}

// sendRequestDataWithContext serializes and sends request data.
func (c *Connection) sendRequestDataWithContext(ctx context.Context, request *Request) (*Response, error) {
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

// sendFileDataWithContext uploads a file in chunks with context support.
func (c *Connection) sendFileDataWithContext(ctx context.Context, localFile string) error {
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

// deleteConnection closes and removes a connection from the pool.
func deleteConnection(target *Connection) {
	deleteConnectionByKey(target.key)
}

// deleteConnectionByKey closes and removes the pooled connection stored under key.
func deleteConnectionByKey(key string) {
	if value, ok := remoteConnections.LoadAndDelete(key); ok {
		if conn, ok := value.(*Connection); ok {
			conn.close()
			logger.Infof("Removed connection: %s", conn)
		}
	}
}

// close closes the connection and cleans up all pending responses.
func (c *Connection) close() {
	c.closeOnce.Do(func() {
		close(c.closed) // Signal that connection is closing

		if c.messageConnection != nil {
			c.messageConnection.Close() // Close underlying transport connection
		}

		c.pendingMu.Lock()
		pendings := c.pending
		c.pending = make(map[string]chan *Response)
		c.pendingMu.Unlock()

		for uuid, ch := range pendings {
			close(ch)
			logger.Debugf("Closed pending response channel for UUID: %s", uuid)
		}

		logger.Debugf("Connection closed and cleaned up: %s", c.key)
	})
}
