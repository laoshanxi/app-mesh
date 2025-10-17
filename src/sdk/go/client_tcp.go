// client_tcp.go
package appmesh

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

const (
	REST_PATH_UPLOAD   = "/appmesh/file/upload"
	REST_PATH_DOWNLOAD = "/appmesh/file/download"
)

// AppMeshClientTCP interacts with the TCP server using REST API requests via a socket.
type AppMeshClientTCP struct {
	*AppMeshClient
	TcpExecutor *RequesterTcp // Used for file operations.
}

// NewTcpClient creates a new AppMeshClientTCP instance for interacting with a TCP server.
func NewTcpClient(options Option) (*AppMeshClientTCP, error) {
	// Determine the connection URL, defaulting to DEFAULT_TCP_URI if not provided.
	uri := options.AppMeshUri
	if uri == "" {
		uri = DEFAULT_TCP_URI
	}

	// Set up TCP requester and client.
	tcpRequester := &RequesterTcp{
		TCPConnection: NewTCPConnection(),
		BaseURL:       uri,
	}

	// Create the AppMeshClientTCP.
	value := true
	options.tcpOnly = &value
	client := &AppMeshClientTCP{
		AppMeshClient: NewHttpClient(options),
		TcpExecutor:   tcpRequester,
	}
	client.AppMeshClient.Proxy = tcpRequester

	if err := tcpRequester.Connect(uri, client.sslClientCert, client.sslClientCertKey, client.sslCAFile); err != nil {
		return nil, err
	}
	return client, nil
}

// CloseConnection closes the TCP connection.
func (client *AppMeshClientTCP) CloseConnection() {
	if client.TcpExecutor != nil {
		client.TcpExecutor.Close()
		client.TcpExecutor = nil
	}
}

// FileDownload downloads a file from the server to the local file system.
func (r *AppMeshClientTCP) FileDownload(remoteFile, localFile string, applyFileAttributes bool) error {
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

	status, msg, responseHeaders, err := r.get(REST_PATH_DOWNLOAD, nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to download %q: status=%d msg=%s", remoteFile, status, msg)
	}
	if err := requireHeader(responseHeaders, HTTP_HEADER_KEY_X_RECV_FILE_SOCKET); err != nil {
		return err
	}

	return r.receiveFile(localFile, responseHeaders, applyFileAttributes)
}

// receiveFile receives file data and writes it to the local file system.
func (r *AppMeshClientTCP) receiveFile(localFile string, headers http.Header, applyFileAttributes bool) error {
	file, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("create local file %q failed: %w", localFile, err)
	}
	defer file.Close()

	for {
		chunkData, err := r.TcpExecutor.ReadMessage()
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
		_ = SetFileAttributes(localFile, headers)
	}
	return nil
}

// FileUpload uploads a local file to the server.
func (client *AppMeshClientTCP) FileUpload(localFile, remoteFile string, applyFileAttributes bool) error {
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
		attrs, err := GetFileAttributes(localFile)
		if err != nil {
			return err
		}
		MergeStringMaps(headers, attrs)
	}

	status, msg, responseHeaders, err := client.post(REST_PATH_UPLOAD, nil, headers, nil)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to upload %q: status=%d msg=%s", localFile, status, msg)
	}
	if err := requireHeader(responseHeaders, HTTP_HEADER_KEY_X_SEND_FILE_SOCKET); err != nil {
		return err
	}

	return client.uploadFileChunks(file)
}

// uploadFileChunks uploads a file in chunks.
func (client *AppMeshClientTCP) uploadFileChunks(file *os.File) error {
	buffer := make([]byte, TCP_CHUNK_BLOCK_SIZE)

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("read chunk failed: %w", err)
		}
		if n == 0 {
			break
		}
		if err := client.TcpExecutor.SendMessage(buffer[:n]); err != nil {
			return fmt.Errorf("send chunk failed: %w", err)
		}
	}
	return client.TcpExecutor.SendMessage([]byte{}) // EOF marker
}

// RequesterTcp handles TCP requests.
type RequesterTcp struct {
	*TCPConnection
	BaseURL string
}

// Request performs a REST-like request over TCP.
func (r *RequesterTcp) Request(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader, token string, forwardingHost string) (int, []byte, http.Header, error) {
	u, err := ParseURL(r.BaseURL)
	if err != nil {
		return 0, nil, nil, err
	}
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if forwardingHost != "" {
		if strings.Contains(forwardingHost, ":") {
			req.Header.Set("X-Target-Host", forwardingHost)
		} else {
			req.Header.Set("X-Target-Host", forwardingHost+":"+u.Port())
		}
	}
	req.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT_TCP)
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := r.request(req)
	if err != nil {
		return 0, nil, nil, err
	}

	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	return resp.HttpStatus, []byte(resp.Body), respHeaders, nil
}

// Close closes the TCP connection.
func (r *RequesterTcp) Close() {
	if r.TCPConnection != nil {
		r.TCPConnection.Close()
	}
}

// request sends a request over TCP.
func (r *RequesterTcp) request(req *http.Request) (*Response, error) {
	data := NewRequest()
	data.RequestUri = req.URL.Path
	data.HttpMethod = req.Method
	data.ClientAddress = r.ClientAddress()
	for key, values := range req.Header {
		if len(values) > 0 {
			data.Headers[key] = values[0] // only first value
		}
	}
	for key, values := range req.URL.Query() {
		if len(values) > 0 {
			data.Query[key] = values[0]
		}
	}

	if data.RequestUri != REST_PATH_UPLOAD && req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if len(bodyBytes) > 0 {
			if strings.HasSuffix(data.RequestUri, "/task") {
				data.Body = bodyBytes // pass raw data for task request
			} else {
				data.Body = HtmlUnescapeBytes(bodyBytes)
			}
		}
	}

	data.Headers[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT_TCP

	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	// TODO: A lock will block the second request send while the first request is waiting for response

	// Send the data over TCP.
	if err := r.SendMessage(buf); err != nil {
		return nil, err
	}

	// Receive the response.
	respData, err := r.ReadMessage()
	if err != nil {
		return nil, err
	}

	// Deserialize the response.
	respMsg := &Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}

// requireHeader ensures a required header exists.
func requireHeader(headers http.Header, key string) error {
	if headers.Get(key) == "" {
		return fmt.Errorf("missing required header %q", key)
	}
	return nil
}
