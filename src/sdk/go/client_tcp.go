// client_tcp.go
package appmesh

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
)

const (
	REST_PATH_UPLOAD   = "/appmesh/file/upload"
	REST_PATH_DOWNLOAD = "/appmesh/file/download"
)

// AppMeshClientTCP interacts with the TCP server using REST API requests via a socket.
type AppMeshClientTCP struct {
	*AppMeshClient
	tcpReq *TCPRequester // Used for file operations.
}

// NewTCPClient creates a new AppMeshClientTCP instance for interacting with a TCP server.
func NewTCPClient(options Option) (*AppMeshClientTCP, error) {
	// Determine the connection URL, defaulting to DEFAULT_TCP_URI if not provided.
	uri := options.AppMeshUri
	if uri == "" {
		uri = DEFAULT_TCP_URI
	}
	parsed, err := ParseURL(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	connectAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(parsed.Hostname(), parsed.Port()))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address %s: %v", uri, err)
	}

	// Set up TCP requester and client.
	tcpRequester := &TCPRequester{
		TCPConnection: NewTCPConnection(),
		baseURL:       *parsed,
	}

	// Create the AppMeshClientTCP.
	httpClient, err := newHTTPClientWithRequester(options, tcpRequester)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP Client: %v", err)
	}
	value := true
	options.tcpOnly = &value
	tcpClient := &AppMeshClientTCP{
		AppMeshClient: httpClient,
		tcpReq:        tcpRequester,
	}

	if err := tcpRequester.Connect(connectAddr, tcpClient.sslClientCert, tcpClient.sslClientCertKey, tcpClient.sslCAFile); err != nil {
		return nil, err
	}
	return tcpClient, nil
}

// CloseConnection closes the TCP connection.
func (c *AppMeshClientTCP) CloseConnection() {
	c.tcpReq.Close()
}

func (c *AppMeshClientTCP) ReadMessage() ([]byte, error) {
	return c.tcpReq.TCPConnection.ReadMessage()
}

func (c *AppMeshClientTCP) SendMessage(ctx context.Context, buffer []byte) error {
	return c.tcpReq.TCPConnection.SendMessage(ctx, buffer)
}

// FileDownload downloads a file from the server to the local file system.
func (c *AppMeshClientTCP) FileDownload(remoteFile, localFile string, applyFileAttributes bool) error {
	if remoteFile == "" {
		return errors.New("remote file path cannot be empty")
	}
	if localFile == "" {
		return errors.New("local file path cannot be empty")
	}

	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path:          remoteFile,
		HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
	}

	status, msg, responseHeaders, err := c.get(REST_PATH_DOWNLOAD, nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to download %q: status=%d msg=%s", remoteFile, status, msg)
	}
	if err := requireHeader(responseHeaders, HTTP_HEADER_KEY_X_RECV_FILE_SOCKET); err != nil {
		return err
	}

	return c.receiveFile(localFile, responseHeaders, applyFileAttributes)
}

// receiveFile receives file data and writes it to the local file system.
func (c *AppMeshClientTCP) receiveFile(localFile string, headers http.Header, applyFileAttributes bool) error {
	file, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("create local file %q failed: %w", localFile, err)
	}
	defer file.Close()

	for {
		chunkData, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("read chunk failed: %w", err)
		}
		if len(chunkData) == 0 {
			break
		}
		if _, err := file.Write(chunkData); err != nil {
			return fmt.Errorf("write chunk failed: %w", err)
		}
	}

	if applyFileAttributes {
		_ = ApplyFileAttributes(localFile, headers)
	}
	return nil
}

// FileUpload uploads a local file to the server.
func (c *AppMeshClientTCP) FileUpload(ctx context.Context, localFile, remoteFile string, applyFileAttributes bool) error {
	if localFile == "" {
		return errors.New("local file path cannot be empty")
	}
	if remoteFile == "" {
		return errors.New("remote file path cannot be empty")
	}

	file, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("open local file %q failed: %w", localFile, err)
	}
	defer file.Close()

	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path:          remoteFile,
		HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: "true",
	}

	// Get the file attributes.
	if applyFileAttributes {
		headers, _ = GetFileAttributes(localFile, headers)
	}

	status, msg, responseHeaders, err := c.post(REST_PATH_UPLOAD, nil, headers, nil)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to upload %q: status=%d msg=%s", localFile, status, msg)
	}
	if err := requireHeader(responseHeaders, HTTP_HEADER_KEY_X_SEND_FILE_SOCKET); err != nil {
		return err
	}

	return c.uploadFileChunks(ctx, file)
}

// uploadFileChunks uploads a file in chunks.
func (c *AppMeshClientTCP) uploadFileChunks(ctx context.Context, file *os.File) error {
	reader := bufio.NewReader(file)
	buffer := make([]byte, TCP_CHUNK_BLOCK_SIZE)

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read chunk failed: %w", err)
		}
		if n == 0 {
			break
		}
		if err := c.SendMessage(ctx, buffer[:n]); err != nil {
			return fmt.Errorf("send chunk failed: %w", err)
		}
	}
	return c.SendMessage(ctx, []byte{}) // EOF marker
}

// requireHeader ensures a required header exists.
func requireHeader(headers http.Header, key string) error {
	if headers.Get(key) == "" {
		return fmt.Errorf("missing required header %q", key)
	}
	return nil
}
