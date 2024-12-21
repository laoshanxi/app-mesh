// Package appmesh provides TCP communication functionality.
package appmesh

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
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
	conn       net.Conn
	readBuffer sync.Pool // Buffer pool for better memory management.
}

// NewTCPConnection initializes and returns a TCPConnection.
func NewTCPConnection() *TCPConnection {
	return &TCPConnection{
		readBuffer: sync.Pool{
			New: func() interface{} {
				return make([]byte, TCP_CHUNK_BLOCK_SIZE)
			},
		}}
}

// Connect establishes a secure TLS TCP connection to an App Mesh server.
func (r *TCPConnection) Connect(url string, sslClientCert string, sslClientCertKey string, sslCAPath string) error {
	// Prepare socket URI.
	u, err := ParseURL(url)
	if err != nil {
		return err
	}
	tcpAddr := net.JoinHostPort(u.Hostname(), u.Port())

	// Load server CA if server verification is enabled.
	verifyServer := (sslCAPath != "")
	var serverCA *x509.CertPool
	if verifyServer {
		serverCA, err = LoadCA(sslCAPath)
		if err != nil {
			return fmt.Errorf("failed to load server CA: %w", err)
		}
	}

	// TLS configuration.
	conf := &tls.Config{
		InsecureSkipVerify: !verifyServer,
		RootCAs:            serverCA,
	}

	// Load client certificate if client verification is enabled.
	verifyClient := (sslClientCert != "" && sslClientCertKey != "")
	if verifyClient {
		clientCert, err := LoadCertificatePair(sslClientCert, sslClientCertKey)
		if err != nil {
			return fmt.Errorf("failed to load client certificate: %w", err)
		}
		conf.Certificates = []tls.Certificate{clientCert}
	}

	// Dialer with timeout.
	dialer := net.Dialer{Timeout: TCP_CONNECT_TIMEOUT_SECONDS * time.Second}

	// Establish a TLS connection.
	conn, err := tls.DialWithDialer(&dialer, "tcp", tcpAddr, conf)
	if err != nil {
		return fmt.Errorf("failed to establish TLS connection: %w", err)
	}

	// Set TCP_NODELAY for low-latency communication.
	if err := SetTcpNoDelay(conn); err != nil {
		fmt.Printf("warning: failed to set TCP_NODELAY: %v", err)
	}
	r.conn = conn
	return nil
}

// ReadMessage reads and returns a complete message from the TCP connection.
func (r *TCPConnection) ReadMessage() ([]byte, error) {
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
	if msgLength > TCP_MAX_BLOCK_SIZE {
		return nil, fmt.Errorf("read message size exceeds the maximum allowed size")
	}

	buffer := make([]byte, 0, msgLength)
	remaining := msgLength

	for remaining > 0 {
		chunkSize := min(remaining, TCP_CHUNK_BLOCK_SIZE)

		// Get a buffer from the pool.
		chunk := r.readBuffer.Get().([]byte)

		n, err := r.conn.Read(chunk[:chunkSize])
		if err != nil {
			// Explicitly return the buffer to the pool.
			r.readBuffer.Put(chunk)
			return nil, fmt.Errorf("read error after %d bytes: %w", msgLength-remaining, err)
		}

		if n > 0 {
			buffer = append(buffer, chunk[:n]...)
			remaining -= uint32(n)
		}
		// Explicitly return the buffer to the pool.
		r.readBuffer.Put(chunk)
	}

	return buffer, nil
}

// SendMessage sends a complete message over the TCP connection.
func (r *TCPConnection) SendMessage(buffer []byte) error {
	if err := r.sendHeader(len(buffer)); err != nil {
		return fmt.Errorf("failed to send header: %w", err)
	}
	return r.sendBytes(buffer)
}

// sendHeader sends the length of the data as an 8-byte header.
func (r *TCPConnection) sendHeader(length int) error {
	headerBuf := make([]byte, TCP_MESSAGE_HEADER_LENGTH)
	// Write the magic number to the first 4 bytes in network byte order.
	binary.BigEndian.PutUint32(headerBuf[:4], TCP_MESSAGE_MAGIC)
	// Write the body length to the next 4 bytes in network byte order.
	binary.BigEndian.PutUint32(headerBuf[4:], uint32(length))
	return r.sendBytes(headerBuf)
}

// sendBytes sends the specified bytes over the TCP connection.
func (r *TCPConnection) sendBytes(buffer []byte) error {
	var totalSentSize int = 0
	var bufferSize = len(buffer)
	for totalSentSize < bufferSize {
		byteSent, err := r.conn.Write(buffer[totalSentSize:])
		if err != nil {
			return fmt.Errorf("write error after %d/%d bytes: %w", totalSentSize, bufferSize, err)
		}
		totalSentSize += byteSent
	}
	return nil
}

// Close closes the underlying TCP connection.
func (r *TCPConnection) Close() {
	if r.conn != nil {
		r.conn.Close()
	}
}

// ClientAddress returns the socket client address.
func (r *TCPConnection) ClientAddress() string {
	if r.conn != nil {
		return r.conn.LocalAddr().String()
	}
	return ""
}
