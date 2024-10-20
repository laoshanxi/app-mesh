package agent

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

func NewConnection(targetHost string, verifyServer bool, allowError bool) (*Connection, error) {
	// Acquire a lock to prevent race conditions when checking/creating connections
	remoteConnectionsMutex.Lock()
	defer remoteConnectionsMutex.Unlock()

	if conn, ok := remoteConnections.Load(targetHost); ok {
		return conn.(*Connection), nil
	}

	conn, err := appmesh.ConnectAppMeshServer(targetHost, verifyServer, &config.ConfigData.REST.SSL)
	if err != nil {
		return nil, err
	}

	sConn := &Connection{conn: conn}
	remoteConnections.Store(targetHost, sConn)
	go monitorResponse(sConn, targetHost, allowError)
	return sConn, nil
}

func (r *Connection) sendRequestData(request *appmesh.Request) error {
	bodyData, err := request.Serialize()
	if err != nil {
		log.Fatalf("Failed to serialize request: %v", err)
		return err
	}

	// header buffer
	headerData := make([]byte, TCP_MESSAGE_HEADER_LENGTH)
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
	file, err := os.Open(localFile)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return err
	}
	defer os.Remove(localFile)
	defer file.Close()

	reader := bufio.NewReader(file)
	buf := make([]byte, TCP_CHUNK_BLOCK_SIZE)
	headerData := make([]byte, TCP_MESSAGE_HEADER_LENGTH)

	r.mu.Lock()
	defer r.mu.Unlock()

	for {
		// Read a chunk from the file
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			log.Printf("Error reading file: %v", err)
			return err
		}
		if n == 0 {
			// If we've reached the end of the file, break out of the loop
			break
		}

		binary.BigEndian.PutUint32(headerData, uint32(n))
		if err = r.sendTcpData(headerData); err == nil {
			err = r.sendTcpData(buf[:n])
		}

		if err != nil {
			return err
		}
	}

	binary.BigEndian.PutUint32(headerData, uint32(0)) // End of file indicator
	return r.sendTcpData(headerData)
}

func deleteConnection(targetHost string) {
	// Atomically load and delete the connection
	if value, ok := remoteConnections.LoadAndDelete(targetHost); ok {
		if conn, ok := value.(*Connection); ok {
			conn.conn.Close() // Close the connection
			log.Printf("Removed connection: %s", targetHost)
		}
	}
}

func readTcpData(conn net.Conn, msgLength uint32) ([]byte, error) {
	// read body buffer
	var chunkSize uint32 = TCP_CHUNK_BLOCK_SIZE
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
