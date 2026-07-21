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
	"path/filepath"
)

const (
	restPathUpload   = "/appmesh/file/upload"
	restPathDownload = "/appmesh/file/download"
)

// AppMeshClientTCP interacts with the TCP server using REST API requests via a socket.
type AppMeshClientTCP struct {
	*AppMeshClient
	tcpReq *TCPRequester // Used for file operations.
}

// NewTCPClient creates a TCP transport client that reuses the standard App Mesh client API.
func NewTCPClient(options Option) (*AppMeshClientTCP, error) {
	// Determine the connection URL, defaulting to DefaultTCPURI if not provided.
	uri := options.AppMeshUri
	if uri == "" {
		uri = DefaultTCPURI
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
	tcpClient := &AppMeshClientTCP{
		AppMeshClient: httpClient,
		tcpReq:        tcpRequester,
	}

	if err := tcpRequester.Connect(connectAddr, tcpClient.sslClientCert, tcpClient.sslClientCertKey, tcpClient.sslCAFile); err != nil {
		return nil, err
	}
	return tcpClient, nil
}

// CloseConnection closes only the underlying TCP transport connection.
func (c *AppMeshClientTCP) CloseConnection() {
	c.tcpReq.Close()
}

func (c *AppMeshClientTCP) ReadMessage() ([]byte, error) {
	return c.tcpReq.TCPConnection.ReadMessage()
}

func (c *AppMeshClientTCP) SendMessage(ctx context.Context, buffer []byte) error {
	return c.tcpReq.TCPConnection.SendMessage(ctx, buffer)
}

// DownloadFileContext downloads a file through the TCP file-socket side channel.
// When applyFileAttributes is true, returned POSIX metadata is applied locally best-effort.
func (c *AppMeshClientTCP) DownloadFileContext(ctx context.Context, remoteFile, localFile string, applyFileAttributes bool) error {
	if remoteFile == "" {
		return errors.New("remote file path cannot be empty")
	}
	// Default the local filename to the remote file's base name when omitted.
	if localFile == "" {
		localFile = filepath.Base(remoteFile)
	}

	headers := map[string]string{
		headerFilePath:       remoteFile,
		headerRecvFileSocket: "true",
	}

	status, msg, responseHeaders, err := c.get(restPathDownload, nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if status != http.StatusOK {
		return newAPIErrorText("download file", status, string(msg), fmt.Sprintf("failed to download %q: status=%d msg=%s", remoteFile, status, msg))
	}
	if err := requireHeader(responseHeaders, headerRecvFileSocket); err != nil {
		return err
	}

	return c.receiveFile(ctx, localFile, responseHeaders, applyFileAttributes)
}

// receiveFile receives file data and writes it to the local file system.
func (c *AppMeshClientTCP) receiveFile(ctx context.Context, localFile string, headers http.Header, applyFileAttributes bool) error {
	file, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("create local file %q failed: %w", localFile, err)
	}
	defer file.Close()

	for {
		// Fast-fail on canceled context (ReadMessage itself takes no context).
		if err := ctx.Err(); err != nil {
			return err
		}
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

// DownloadFile downloads a file via the TCP file-socket side channel.
func (c *AppMeshClientTCP) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	return c.DownloadFileContext(context.Background(), remoteFile, localFile, applyFileAttributes)
}

// UploadFileContext uploads a file through the TCP file-socket side channel.
// When applyFileAttributes is true, local POSIX metadata is sent so the server can recreate it.
func (c *AppMeshClientTCP) UploadFileContext(ctx context.Context, localFile, remoteFile string, applyFileAttributes bool) error {
	if localFile == "" {
		return errors.New("local file path cannot be empty")
	}
	// Default the remote filename to the local file's base name when omitted.
	if remoteFile == "" {
		remoteFile = filepath.Base(localFile)
	}

	file, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("open local file %q failed: %w", localFile, err)
	}
	defer file.Close()

	headers := map[string]string{
		headerFilePath:       remoteFile,
		headerSendFileSocket: "true",
	}

	// Get the file attributes.
	if applyFileAttributes {
		attrs, err := fileAttributes(localFile)
		if err != nil {
			return fmt.Errorf("failed to read file attributes of %q: %w", localFile, err)
		}
		for key, value := range attrs {
			headers[key] = value
		}
	}

	status, msg, responseHeaders, err := c.post(restPathUpload, nil, headers, nil)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	if status != http.StatusOK {
		return newAPIErrorText("upload file", status, string(msg), fmt.Sprintf("failed to upload %q: status=%d msg=%s", localFile, status, msg))
	}
	if err := requireHeader(responseHeaders, headerSendFileSocket); err != nil {
		return err
	}

	return c.uploadFileChunks(ctx, file)
}

// uploadFileChunks uploads a file in chunks.
func (c *AppMeshClientTCP) uploadFileChunks(ctx context.Context, file *os.File) error {
	reader := bufio.NewReader(file)
	buffer := make([]byte, TCPChunkBlockSize)

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

// UploadFile uploads a local file via the TCP file-socket side channel.
func (c *AppMeshClientTCP) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	return c.UploadFileContext(context.Background(), localFile, remoteFile, applyFileAttributes)
}

// requireHeader ensures a required header exists.
func requireHeader(headers http.Header, key string) error {
	if headers.Get(key) == "" {
		return fmt.Errorf("missing required header %q", key)
	}
	return nil
}
