package agent

import (
	"bufio"
	"io"
	"os"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

type Connection struct {
	*appmesh.TCPConnection
}

func NewConnection(targetHost string, verifyServer bool, allowError bool) (*Connection, error) {
	// Acquire a lock to prevent race conditions when checking/creating connections
	remoteConnectionsMutex.Lock()
	defer remoteConnectionsMutex.Unlock()

	if conn, ok := remoteConnections.Load(targetHost); ok {
		return conn.(*Connection), nil
	}

	// Logging the connection attempt
	logger.Infof("Attempting to connect to: %s", targetHost)

	// Initialize the connection and SSL configuration
	sConn := &Connection{TCPConnection: appmesh.NewTCPConnection()}
	clientCert := config.ConfigData.REST.SSL.SSLClientCertificateFile
	clientCertKey := config.ConfigData.REST.SSL.SSLClientCertificateKeyFile
	caPath := config.ConfigData.REST.SSL.SSLCaPath
	if !verifyServer {
		caPath = ""
	}

	// Try to establish the connection
	if err := sConn.Connect(targetHost, clientCert, clientCertKey, caPath); err != nil {
		logger.Errorf("Failed to connect to %s: %v", targetHost, err)
		return nil, err
	}

	// Store the connection
	remoteConnections.Store(targetHost, sConn)

	// Monitor the connection in a separate goroutine
	go func() {
		logger.Infof("Monitoring response from: %s", targetHost)
		monitorResponse(sConn, targetHost, allowError)
	}()

	return sConn, nil
}

func (r *Connection) sendRequestData(request *appmesh.Request) error {
	bodyData, err := request.Serialize()
	if err != nil {
		logger.Fatalf("Failed to serialize request: %v", err)
		return err
	}

	logger.Debugf("Received request: %s %s %s %s", request.ClientAddress, request.HttpMethod, request.RequestUri, request.Uuid)

	// send header and body to app mesh server
	return r.SendMessage(bodyData)
}

func (r *Connection) sendUploadFileData(localFile string) error {
	file, err := os.Open(localFile)
	if err != nil {
		logger.Errorf("Error opening file: %v", err)
		return err
	}
	defer os.Remove(localFile)
	defer file.Close()

	reader := bufio.NewReader(file)
	buf := make([]byte, TCP_CHUNK_BLOCK_SIZE)

	for {
		// Read a chunk from the file
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			logger.Errorf("Error reading file: %v", err)
			return err
		}
		if n == 0 {
			// If we've reached the end of the file, break out of the loop
			break
		}

		err = r.SendMessage(buf[:n])

		if err != nil {
			return err
		}
	}

	return r.SendMessage([]byte{}) // End of file indicator
}

func deleteConnection(targetHost string) {
	// Atomically load and delete the connection
	if value, ok := remoteConnections.LoadAndDelete(targetHost); ok {
		if c, ok := value.(*Connection); ok {
			c.Close()
			logger.Infof("Removed connection: %s", targetHost)
		}
	}
}
