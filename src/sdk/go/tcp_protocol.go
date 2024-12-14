package appmesh

import (
	"encoding/binary"
	"net"
	"sync"

	"github.com/pkg/errors"
)

const TCP_MESSAGE_HEADER_LENGTH = 8          // 8 bytes TCP message header: 4 bytes Magic number + 4 bytes Body length
const TCP_MESSAGE_MAGIC = uint32(0x07C707F8) // 4-byte magic number used to identify and validate TCP messages.
const TCP_CHUNK_BLOCK_SIZE = 16*1024 - 256   //Target block size: 16KB, with 256 bytes reserved for protocol overhead or alignment.
const TCP_MAX_BLOCK_SIZE = 1024 * 1024 * 100 // Maximum allowed block size: 100 MB

type TCPConnection struct {
	Conn  net.Conn
	Mutex sync.Mutex
}

// NewTCPConnection initializes and returns a TCPConnection
func NewTCPConnection(conn net.Conn) TCPConnection {
	return TCPConnection{
		Conn: conn,
	}
}

// ReadMessage reads and returns a complete message from the TCP connection.
func (r *TCPConnection) ReadMessage() ([]byte, error) {
	// Step 1: Read the message header to get the body length.
	bodySize, err := r.readHeader()
	if err != nil {
		return nil, err
	}
	// Step 2: Read the message body based on the length from the header.
	if bodySize > 0 {
		return r.readBytes(bodySize)
	}

	return nil, nil
}

// readHeader reads and parses the 8-byte message header.
func (r *TCPConnection) readHeader() (uint32, error) {
	headerBuf, err := r.readBytes(TCP_MESSAGE_HEADER_LENGTH)
	if err != nil {
		return 0, err
	}

	// Step 1: Extract and validate the magic number (first 4 bytes).
	magic := binary.BigEndian.Uint32(headerBuf[:4])
	if magic != TCP_MESSAGE_MAGIC {
		return 0, errors.New("invalid message: incorrect magic number")
	}

	// Step 2: Extract the body length (next 4 bytes).
	bodyLength := binary.BigEndian.Uint32(headerBuf[4:])
	return bodyLength, nil
}

func (r *TCPConnection) readBytes(msgLength uint32) ([]byte, error) {
	if msgLength > TCP_MAX_BLOCK_SIZE {
		return nil, errors.New("read message size exceeds the maximum allowed size")
	}
	// make 0 length data bytes (since we'll be appending)
	var bodyBuf = make([]byte, 0)
	var totalReadSize uint32 = 0
	var chunkSize uint32 = min(msgLength, TCP_CHUNK_BLOCK_SIZE)
	for totalReadSize < msgLength {
		// https://stackoverflow.com/questions/24339660/read-whole-data-with-golang-net-conn-read
		oneTimeRead := msgLength - totalReadSize
		if oneTimeRead > chunkSize {
			oneTimeRead = chunkSize
		}
		data := make([]byte, oneTimeRead) //TODO: use global buffer avoid garbage
		n, err := r.Conn.Read(data)
		if n > 0 {
			bodyBuf = append(bodyBuf, data[:n]...)
			totalReadSize += uint32(n)
			//logger.Infof("expect: %d, read: %d, left: %d", oneTimeRead, n, msgLength-totalReadSize)
			continue
		} else if err != nil {
			return nil, err
		}
	}

	return bodyBuf, nil
}

func (r *TCPConnection) SendMessage(buf []byte) error {
	r.Mutex.Lock()
	defer r.Mutex.Unlock()

	bodySize := len(buf)
	if err := r.sendHeader(bodySize); err != nil {
		return err
	}
	return r.sendBytes(buf)
}

// sendHeader sends the length of the data as a 8-byte header
func (r *TCPConnection) sendHeader(length int) error {
	headerBuf := make([]byte, TCP_MESSAGE_HEADER_LENGTH)
	// Write the magic number to the first 4 bytes in network byte order
	binary.BigEndian.PutUint32(headerBuf[:4], TCP_MESSAGE_MAGIC)
	// Write the body length to the next 4 bytes in network byte order
	binary.BigEndian.PutUint32(headerBuf[4:], uint32(length))
	return r.sendBytes(headerBuf)
}

func (r *TCPConnection) sendBytes(buf []byte) error {
	var totalSentSize int = 0
	var err error = nil
	for totalSentSize < len(buf) {
		byteSent := 0

		if byteSent, err = r.Conn.Write(buf[totalSentSize:]); err != nil {
			return err
		}
		totalSentSize += byteSent
		//logger.Infof("total send size %d bytes", totalSentSize)
	}
	return err
}
