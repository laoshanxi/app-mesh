package http

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"os"
	"sync"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

type Connection struct {
	conn net.Conn
	mu   sync.Mutex
}

type tcpConnections struct {
	mu          sync.Mutex
	connections map[string]*Connection
}

func NewConnection(targetHost string, verifyServer bool, allowError bool) (*Connection, error) {
	remoteConnections.mu.Lock()
	defer remoteConnections.mu.Unlock()

	// Check for existing connection
	if conn, ok := remoteConnections.connections[targetHost]; ok {
		return conn, nil
	}

	// No available connection, create a new one
	conn, err := appmesh.ConnectAppMeshServer(targetHost, verifyServer, &config.ConfigData.REST.SSL)
	if err != nil {
		return nil, err
	}
	// Store the new connection
	sConn := &Connection{conn: conn}
	remoteConnections.connections[targetHost] = sConn

	// start thread to monitor response
	go monitorResponse(sConn, targetHost, allowError)

	return sConn, nil
}

func (r *Connection) sendRequestData(request *Request) error {
	bodyData, err := request.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize request: %v", err)
		return err
	}

	// header buffer
	headerData := make([]byte, PROTOBUF_HEADER_LENGTH)
	binary.BigEndian.PutUint32(headerData, uint32(len(bodyData)))
	log.Printf("Requesting: %s with msg length: %d", request.Uuid, len(bodyData))

	// send header and body to app mesh server
	r.mu.Lock()
	defer r.mu.Unlock()
	if err = r.sendTcpData(headerData); err == nil {
		err = r.sendTcpData(bodyData)
	}
	return err
}

func (r *Connection) sendUploadFileData(localFile string) error {
	var err error
	var file *os.File
	if file, err = os.Open(localFile); err == nil {
		log.Printf("sending file: %s", localFile)
		defer os.Remove(localFile)
		defer file.Close()
		// Create a buffered reader for the file
		reader := bufio.NewReader(file)
		chunkSize := 1024 * 8 // 8 KB chunks
		// Create a buffer to store chunks
		bodyData := make([]byte, chunkSize)

		// header buffer
		headerData := make([]byte, PROTOBUF_HEADER_LENGTH)

		r.mu.Lock()
		defer r.mu.Unlock()
		// Read the file in chunks and send each chunk over the TCP connection
		for {
			// Read a chunk from the file
			n, err := reader.Read(bodyData)

			if err != nil && err != io.EOF {
				log.Printf("Error reading file: %v", err)
				break
			}

			// If we've reached the end of the file, break out of the loop
			if n == 0 {
				break
			}

			binary.BigEndian.PutUint32(headerData, uint32(n))
			if err = r.sendTcpData(headerData); err == nil {
				err = r.sendTcpData(bodyData[:n])
			}

			if err != nil {
				break
			}
		}

		binary.BigEndian.PutUint32(headerData, uint32(0))
		err = r.sendTcpData(headerData)

		log.Printf("upload socket file %s finished", localFile)
	} else {
		log.Printf("Error opening file: %v", err)
	}
	return err
}

func deleteConnection(targetHost string) {
	remoteConnections.mu.Lock()
	defer remoteConnections.mu.Unlock()

	if conn, ok := remoteConnections.connections[targetHost]; ok {
		conn.conn.Close()                                 // Close the connection
		delete(remoteConnections.connections, targetHost) // Remove it from the map
		log.Printf("remove connection: %s", targetHost)
	}
}

func readTcpData(conn net.Conn, msgLength uint32) ([]byte, error) {
	// read body buffer
	var chunkSize uint32 = TCP_CHUNK_READ_BLOCK_SIZE
	if msgLength < chunkSize {
		chunkSize = msgLength
	}
	// make 0 length data bytes (since we'll be appending)
	bodyBuf := make([]byte, 0)
	var totalReadSize uint32 = 0
	for totalReadSize < msgLength {
		// https://stackoverflow.com/questions/24339660/read-whole-data-with-golang-net-conn-read
		oneTimeRead := msgLength - totalReadSize
		if oneTimeRead > chunkSize {
			oneTimeRead = chunkSize
		}
		data := make([]byte, oneTimeRead) //TODO: use global buffer avoid garbage
		n, err := conn.Read(data)
		if n > 0 {
			bodyBuf = append(bodyBuf, data[:n]...)
			totalReadSize += uint32(n)
			//log.Printf("expect: %d, read: %d, left: %d", oneTimeRead, n, msgLength-totalReadSize)
			continue
		} else if err != nil {
			return nil, err
		}
	}

	return bodyBuf, nil
}

func (r *Connection) sendTcpData(buf []byte) error {
	var totalSentSize int = 0
	var err error = nil
	for totalSentSize < len(buf) {
		byteSent := 0

		if byteSent, err = r.conn.Write(buf[totalSentSize:]); err != nil {
			return err
		}
		totalSentSize += byteSent
		//log.Printf("total send size %d bytes", totalSentSize)
	}
	return err
}
