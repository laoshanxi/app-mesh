// Package appmesh provides TCP communication functionality.
package appmesh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const (
	// 8 bytes TCP message header: 4 bytes Magic number + 4 bytes Body length
	tcpMessageHeaderLength = 8
	tcpMessageMagic        = uint32(0x07C707F8) // 4-byte magic number used to identify and validate TCP messages.
	// Target block size: 16KB, with 256 bytes reserved for protocol overhead or alignment.
	TCPChunkBlockSize = 16*1024 - 256
	tcpMaxBlockSize   = 1024 * 1024 * 1024 // Maximum allowed block size: 1 GB
)

// TCPConnection is a TCP connection wrapper safe for concurrent use:
// sends and reads are serialized by separate mutexes, allowing one
// in-flight send and one in-flight read at a time.
type TCPConnection struct {
	conn   net.Conn
	muConn sync.Mutex
	muSend sync.Mutex
	muRead sync.Mutex
}

// NewTCPConnection initializes and returns a TCPConnection.
func NewTCPConnection() *TCPConnection {
	return &TCPConnection{}
}

// currentConn returns the live connection, or nil when it was never established
// or already closed. Callers must not hold muConn while using the result.
func (r *TCPConnection) currentConn() net.Conn {
	r.muConn.Lock()
	defer r.muConn.Unlock()
	return r.conn
}

// Connect establishes a secure TLS TCP connection to an App Mesh server.
func (r *TCPConnection) Connect(tcpAddr net.Addr, sslClientCert string, sslClientCertKey string,
	sslCAPath string) error {
	// TLS configuration with secure defaults
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Configure server verification
	switch sslCAPath {
	case caSystemTrust:
		// Verify against the system trust store (RootCAs left nil); see caSystemTrust.
	case "":
		conf.InsecureSkipVerify = true
	default:
		serverCA, err := LoadCA(sslCAPath)
		if err != nil {
			return fmt.Errorf("failed to load server CA: %w", err)
		}
		conf.RootCAs = serverCA
	}

	// Configure client certificate
	if sslClientCert != "" && sslClientCertKey != "" {
		clientCert, err := LoadCertificatePair(sslClientCert, sslClientCertKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		conf.Certificates = []tls.Certificate{clientCert}
	}

	// Establish connection
	// KeepAlive so a half-open peer (host crash / partition) is detected, not hung on forever.
	dialer := net.Dialer{Timeout: tcpConnectTimeoutSeconds * time.Second, KeepAlive: 30 * time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", tcpAddr.String(), conf)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return fmt.Errorf("failed to establish TLS connection to %s: %w", tcpAddr, err)
	}

	// Set TCP_NODELAY for low-latency communication.
	if err := setTCPNoDelay(conn); err != nil {
		logf("warning: failed to set TCP_NODELAY: %v", err)
	}

	r.muConn.Lock()
	r.conn = conn
	r.muConn.Unlock()
	return nil
}

// ReadMessage reads and returns a complete message from the TCP connection.
func (r *TCPConnection) ReadMessage() ([]byte, error) {
	r.muRead.Lock()
	defer r.muRead.Unlock()

	// Read the message header to get the body length.
	bodySize, err := r.readHeader()
	if err != nil {
		// A framing or hard IO error leaves the stream desynchronized; close so
		// later sends fail fast instead of writing into a garbage stream (the
		// Python SDK closes on any receive error too). A read-deadline expiry
		// (ReadMessageContext) is not fatal — the connection is still healthy.
		r.closeOnFatalRead(err)
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Check for an empty message.
	if bodySize == 0 {
		return nil, nil
	}

	// Read the message body based on the length from the header.
	body, err := r.readBytes(bodySize)
	if err != nil {
		r.closeOnFatalRead(err)
		return nil, err
	}
	return body, nil
}

// closeOnFatalRead closes the underlying connection after a read error unless
// the error is a deadline expiry (a bounded wait, not a broken stream).
func (r *TCPConnection) closeOnFatalRead(err error) {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return
	}
	r.Close()
}

// readHeader reads and parses the 8-byte message header.
func (r *TCPConnection) readHeader() (uint32, error) {
	headerBuf, err := r.readBytes(tcpMessageHeaderLength)
	if err != nil {
		return 0, err
	}

	// Extract and validate the magic number (first 4 bytes).
	magic := binary.BigEndian.Uint32(headerBuf[:4])
	if magic != tcpMessageMagic {
		return 0, fmt.Errorf("invalid message: incorrect magic number")
	}

	// Extract the body length (next 4 bytes).
	return binary.BigEndian.Uint32(headerBuf[4:]), nil
}

// ReadMessageContext is ReadMessage bounded by ctx's deadline. Without it a lost reply
// blocks until TCP keepalive tears the connection down, which is minutes.
func (r *TCPConnection) ReadMessageContext(ctx context.Context) ([]byte, error) {
	if conn := r.currentConn(); conn != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetReadDeadline(deadline); err != nil {
				return nil, err
			}
			defer conn.SetReadDeadline(time.Time{})
		}
	}
	return r.ReadMessage()
}

// readBytes reads the specified number of bytes from the TCP connection.
// The caller must hold muRead.
func (r *TCPConnection) readBytes(msgLength uint32) ([]byte, error) {
	if msgLength == 0 {
		return []byte{}, nil
	}

	if msgLength > tcpMaxBlockSize {
		return nil, fmt.Errorf("read message size %d exceeds maximum allowed size %d", msgLength, tcpMaxBlockSize)
	}

	conn := r.currentConn()
	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	data := make([]byte, msgLength)

	// Use io.ReadFull for simpler, more robust reading
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, fmt.Errorf("failed to read %d bytes: %w", msgLength, err)
	}

	return data, nil
}

// SendMessage sends a complete message over the TCP connection.
func (r *TCPConnection) SendMessage(ctx context.Context, buffer []byte) error {
	r.muSend.Lock()
	defer r.muSend.Unlock()

	// Fast-fail on canceled context.
	if err := ctx.Err(); err != nil {
		return err
	}

	conn := r.currentConn()
	if conn == nil {
		return fmt.Errorf("cannot send message: not connected")
	}

	// Apply context deadline once for the entire send.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set write deadline: %w", err)
		}
		defer conn.SetWriteDeadline(time.Time{}) // Clear after full message send
	}

	// --- Prepare header (stack allocated) ---
	var header [tcpMessageHeaderLength]byte
	// Write the magic number to the first 4 bytes in network byte order.
	binary.BigEndian.PutUint32(header[:4], tcpMessageMagic)
	// Write the body length to the next 4 bytes in network byte order.
	binary.BigEndian.PutUint32(header[4:], uint32(len(buffer)))

	// --- Send header and body atomically ---
	// A failure part-way through leaves a truncated frame on the wire, and the peer would
	// read the next request's bytes as the tail of this one. Close so callers are forced
	// through a reconnect instead of silently desynchronising the stream.
	if err := sendBytes(conn, header[:]); err != nil {
		r.Close()
		return fmt.Errorf("failed to send header: %w", err)
	}
	if err := sendBytes(conn, buffer); err != nil {
		r.Close()
		return fmt.Errorf("failed to send body: %w", err)
	}

	return nil
}

// sendBytes sends the specified bytes over the connection.
func sendBytes(conn net.Conn, buffer []byte) error {
	var totalSentSize int = 0
	var bufferSize = len(buffer)
	for totalSentSize < bufferSize {
		byteSent, err := conn.Write(buffer[totalSentSize:])
		if err != nil {
			return fmt.Errorf("write failed after %d/%d bytes: %w", totalSentSize, bufferSize, err)
		}
		totalSentSize += byteSent
	}
	return nil
}

// Close closes the underlying TCP connection.
func (r *TCPConnection) Close() {
	r.muConn.Lock()
	defer r.muConn.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
}

// Connected reports whether the underlying connection is present (local state
// only — a server-dropped connection may still report true until I/O fails).
func (r *TCPConnection) Connected() bool {
	return r.currentConn() != nil
}

// ClientAddress returns the socket client address.
func (r *TCPConnection) ClientAddress() string {
	if conn := r.currentConn(); conn != nil {
		return conn.LocalAddr().String()
	}
	return ""
}
