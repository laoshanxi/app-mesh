// Package appmesh provides TCP communication functionality.
package appmesh

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	TCP_MESSAGE_HEADER_LENGTH = 8                  // 8 bytes TCP message header: 4 bytes Magic number + 4 bytes Body length
	TCP_MESSAGE_MAGIC         = uint32(0x07C707F8) // 4-byte magic number used to identify and validate TCP messages.
	TCP_CHUNK_BLOCK_SIZE      = 16*1024 - 256      // Target block size: 16KB, with 256 bytes reserved for protocol overhead or alignment.
	TCP_MAX_BLOCK_SIZE        = 1024 * 1024 * 100  // Maximum allowed block size: 100 MB
)

// TCPConnection represents a non-thread-safe TCP connection wrapper.
type TCPConnection struct {
	conn   net.Conn
	muSend sync.Mutex
	muRead sync.Mutex
}

// NewTCPConnection initializes and returns a TCPConnection.
func NewTCPConnection() *TCPConnection {
	return &TCPConnection{}
}

// Connect establishes a secure TLS TCP connection to an App Mesh server.
func (r *TCPConnection) Connect(tcpAddr net.Addr, sslClientCert string, sslClientCertKey string, sslCAPath string) error {
	// TLS configuration with secure defaults
	conf := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Configure server verification
	if sslCAPath != "" {
		serverCA, err := LoadCA(sslCAPath)
		if err != nil {
			return fmt.Errorf("failed to load server CA: %w", err)
		}
		conf.RootCAs = serverCA
	} else {
		conf.InsecureSkipVerify = true
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
	dialer := net.Dialer{Timeout: TCP_CONNECT_TIMEOUT_SECONDS * time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", tcpAddr.String(), conf)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return fmt.Errorf("failed to establish TLS connection to %s: %w", tcpAddr, err)
	}

	// Set TCP_NODELAY for low-latency communication.
	if err := SetTcpNoDelay(conn); err != nil {
		fmt.Printf("warning: failed to set TCP_NODELAY: %v\n", err)
	}

	r.conn = conn
	return nil
}

// ReadMessage reads and returns a complete message from the TCP connection.
func (r *TCPConnection) ReadMessage() ([]byte, error) {
	r.muRead.Lock()
	defer r.muRead.Unlock()

	// Read the message header to get the body length.
	bodySize, err := r.readHeader()
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Check for an empty message.
	if bodySize == 0 {
		return nil, nil
	}

	// Read the message body based on the length from the header.
	return r.readBytes(bodySize)
}

// readHeader reads and parses the 8-byte message header.
func (r *TCPConnection) readHeader() (uint32, error) {
	headerBuf, err := r.readBytes(TCP_MESSAGE_HEADER_LENGTH)
	if err != nil {
		return 0, err
	}

	// Extract and validate the magic number (first 4 bytes).
	magic := binary.BigEndian.Uint32(headerBuf[:4])
	if magic != TCP_MESSAGE_MAGIC {
		return 0, fmt.Errorf("invalid message: incorrect magic number")
	}

	// Extract the body length (next 4 bytes).
	return binary.BigEndian.Uint32(headerBuf[4:]), nil
}

// readBytes reads the specified number of bytes from the TCP connection.
func (r *TCPConnection) readBytes(msgLength uint32) ([]byte, error) {
	if msgLength == 0 {
		return []byte{}, nil
	}

	if msgLength > TCP_MAX_BLOCK_SIZE {
		return nil, fmt.Errorf("read message size %d exceeds maximum allowed size %d", msgLength, TCP_MAX_BLOCK_SIZE)
	}

	data := make([]byte, msgLength)

	// Use io.ReadFull for simpler, more robust reading
	if _, err := io.ReadFull(r.conn, data); err != nil {
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

	// Apply context deadline once for the entire send.
	if deadline, ok := ctx.Deadline(); ok {
		if err := r.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set write deadline: %w", err)
		}
		defer r.conn.SetWriteDeadline(time.Time{}) // Clear after full message send
	}

	// --- Prepare header (stack allocated) ---
	var header [TCP_MESSAGE_HEADER_LENGTH]byte
	// Write the magic number to the first 4 bytes in network byte order.
	binary.BigEndian.PutUint32(header[:4], TCP_MESSAGE_MAGIC)
	// Write the body length to the next 4 bytes in network byte order.
	binary.BigEndian.PutUint32(header[4:], uint32(len(buffer)))

	// --- Send header and body atomically ---
	if err := r.sendBytes(header[:]); err != nil {
		return fmt.Errorf("failed to send header: %w", err)
	}
	if err := r.sendBytes(buffer); err != nil {
		return fmt.Errorf("failed to send body: %w", err)
	}

	return nil
}

// sendBytes sends the specified bytes over the TCP connection.
func (r *TCPConnection) sendBytes(buffer []byte) error {
	var totalSentSize int = 0
	var bufferSize = len(buffer)
	for totalSentSize < bufferSize {
		byteSent, err := r.conn.Write(buffer[totalSentSize:])
		if err != nil {
			return fmt.Errorf("write failed after %d/%d bytes: %w", totalSentSize, bufferSize, err)
		}
		totalSentSize += byteSent
	}
	return nil
}

// Close closes the underlying TCP connection.
func (r *TCPConnection) Close() {
	if r.conn != nil {
		_ = r.conn.Close()
	}
}

// ClientAddress returns the socket client address.
func (r *TCPConnection) ClientAddress() string {
	if r.conn != nil {
		return r.conn.LocalAddr().String()
	}
	return ""
}
