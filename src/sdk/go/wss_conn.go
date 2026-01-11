package appmesh

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSSConnection wraps a websocket connection for binary message exchange.
type WSSConnection struct {
	conn   *websocket.Conn
	muSend sync.Mutex
	muRead sync.Mutex
}

// NewWSSConnection returns an empty connection wrapper.
func NewWSSConnection() *WSSConnection {
	return &WSSConnection{}
}

// Connect establishes a WSS connection to the given address (url.URL expected).
// sslClientCert and sslClientCertKey may be empty. sslCAPath may be empty to skip verification.
func (w *WSSConnection) Connect(u *url.URL, sslClientCert, sslClientCertKey, sslCAPath string) error {
	tlsConf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if sslCAPath == "" {
		tlsConf.InsecureSkipVerify = true
	} else {
		caPool, err := LoadCA(sslCAPath)
		if err != nil {
			return fmt.Errorf("failed to load CA: %w", err)
		}
		tlsConf.RootCAs = caPool
	}

	if sslClientCert != "" && sslClientCertKey != "" {
		cert, err := LoadCertificatePair(sslClientCert, sslClientCertKey)
		if err != nil {
			return fmt.Errorf("failed to load client cert: %w", err)
		}
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		HandshakeTimeout: 30 * time.Second,
	}

	// copy the tlsConf into dialer.TLSClientConfig
	dialer.TLSClientConfig = tlsConf
	// Request sub-protocol used by the server
	dialer.Subprotocols = []string{"appmesh-ws"}

	// Ensure scheme is wss:// or ws:// depending on tls config
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	}

	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to dial wss %s: %w", u.String(), err)
	}

	w.conn = conn
	return nil
}

// ReadMessage reads a single binary message from the websocket. Empty message returns nil slice.
func (w *WSSConnection) ReadMessage() ([]byte, error) {
	w.muRead.Lock()
	defer w.muRead.Unlock()

	if w.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// ReadMessage returns messageType and payload
	mt, data, err := w.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	// Treat text frames as UTF-8 bytes, binary frames as-is
	if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
		if len(data) == 0 {
			return []byte{}, nil
		}
		return data, nil
	}
	return nil, fmt.Errorf("unsupported message type: %d", mt)
}

// SendMessage sends a single binary message. Empty buffer is used as EOF marker.
func (w *WSSConnection) SendMessage(ctx context.Context, buffer []byte) error {
	w.muSend.Lock()
	defer w.muSend.Unlock()

	if w.conn == nil {
		return fmt.Errorf("not connected")
	}

	// Respect context deadline if set
	if dl, ok := ctx.Deadline(); ok {
		_ = w.conn.SetWriteDeadline(dl)
		defer w.conn.SetWriteDeadline(time.Time{})
	}

	// Use BinaryMessage for bytes
	var dataToSend []byte
	if buffer != nil {
		dataToSend = buffer
	} else {
		dataToSend = []byte{}
	}

	if err := w.conn.WriteMessage(websocket.BinaryMessage, dataToSend); err != nil {
		return err
	}
	return nil
}

// Close closes the websocket connection.
func (w *WSSConnection) Close() {
	if w.conn != nil {
		_ = w.conn.Close()
		w.conn = nil
	}
}

// Connected returns whether the websocket is present.
func (w *WSSConnection) Connected() bool {
	return w.conn != nil
}

// ClientAddress returns local address string if available.
func (w *WSSConnection) ClientAddress() string {
	if w.conn != nil && w.conn.LocalAddr() != nil {
		return w.conn.LocalAddr().String()
	}
	return ""
}
