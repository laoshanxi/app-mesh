package appmesh

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/rs/xid"
)

// AppMeshClientTCP interacts with the TCP server using REST API requests via a socket.
type AppMeshClientTCP struct {
	*AppMeshClient
	TcpExecutor *ClientRequesterTcp // Used for file operations.
}

// NewTcpClient creates a new AppMeshClientTCP instance for interacting with a TCP server.
func NewTcpClient(options Option) (*AppMeshClientTCP, error) {
	// Determine the connection URL, defaulting to DEFAULT_TCP_URI if not provided.
	url := options.AppMeshUri
	if url == "" {
		url = DEFAULT_TCP_URI
	}

	// Set up TCP requester and client.
	tcpRequester := &ClientRequesterTcp{TCPConnection: NewTCPConnection(), BaseURL: url}

	// Create the AppMeshClientTCP.
	value := true
	options.tcpOnly = &value
	client := &AppMeshClientTCP{AppMeshClient: NewHttpClient(options), TcpExecutor: tcpRequester}
	client.AppMeshClient.Proxy = tcpRequester

	// Attempt to connect.
	if err := tcpRequester.Connect(url, client.sslClientCert, client.sslClientCertKey, client.sslCAFile); err != nil {
		return nil, err
	}
	return client, nil
}

// CloseConnection closes the TCP connection.
func (client *AppMeshClientTCP) CloseConnection() {
	if client.TcpExecutor != nil {
		client.TcpExecutor.Close()
	}
}

// FileDownload downloads a file from the server to the local file system.
func (r *AppMeshClientTCP) FileDownload(remoteFile, localFile string, applyFileAttributes bool) error {
	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path:          remoteFile,
		HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
	}

	status, msg, responseHeaders, err := r.get("/appmesh/file/download", nil, headers)
	if err != nil || status != http.StatusOK {
		return errors.New("failed to download file: " + string(msg))
	}

	if _, ok := responseHeaders[HTTP_HEADER_KEY_X_RECV_FILE_SOCKET]; !ok {
		return errors.New("HTTP_HEADER_KEY_X_RECV_FILE_SOCKET header missing")
	}

	return r.receiveFile(localFile, responseHeaders, applyFileAttributes)
}

// receiveFile receives file data and writes it to the local file system.
func (r *AppMeshClientTCP) receiveFile(localFile string, headers http.Header, applyFileAttributes bool) error {
	file, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for {
		chunkData, err := r.TcpExecutor.ReadMessage()
		if err != nil {
			return err
		}

		if chunkData == nil {
			break
		}

		if _, err := file.Write(chunkData); err != nil {
			return err
		}
	}

	if applyFileAttributes {
		SetFileAttributes(localFile, headers)
	}
	return nil
}

// FileUpload uploads a local file to the server.
func (client *AppMeshClientTCP) FileUpload(localFile, remoteFile string, applyFileAttributes bool) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path:          remoteFile,
		"Content-Type":                     "text/plain",
		HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: "true",
	}

	// Get the file attributes.
	if applyFileAttributes {
		attrs, err := GetFileAttributes(localFile)
		MergeStringMaps(headers, attrs)
		if err != nil {
			return err
		}
	}

	status, _, responseHeaders, err := client.post("/appmesh/file/upload", nil, headers, nil)
	if err != nil || status != http.StatusOK {
		return errors.New("failed to upload file")
	}

	if responseHeaders.Get(HTTP_HEADER_KEY_X_SEND_FILE_SOCKET) == "" {
		return errors.New("HTTP_HEADER_KEY_X_SEND_FILE_SOCKET header missing")
	}
	return client.uploadFileChunks(file)
}

// uploadFileChunks uploads a file in chunks.
func (client *AppMeshClientTCP) uploadFileChunks(file *os.File) error {
	chunkSize := TCP_CHUNK_BLOCK_SIZE
	buffer := make([]byte, chunkSize)

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if err := client.TcpExecutor.SendMessage(buffer[:n]); err != nil {
			return err
		}
	}

	// Send end-of-file marker.
	return client.TcpExecutor.SendMessage([]byte{})
}

// ClientRequesterTcp handles TCP requests.
type ClientRequesterTcp struct {
	*TCPConnection
	BaseURL string
}

// DoRequest performs a REST-like request over TCP.
func (r *ClientRequesterTcp) DoRequest(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader, token string, forwardingHost string) (int, []byte, http.Header, error) {
	u, _ := ParseURL(r.BaseURL)
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	// Set headers.
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
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	// Execute the TCP request.
	resp, err := r.request(req)

	// Format the response headers.
	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	return resp.HttpStatus, []byte(resp.Body), respHeaders, err
}

// Close closes the TCP connection.
func (r *ClientRequesterTcp) Close() {
	if r.TCPConnection != nil {
		r.TCPConnection.Close()
	}
}

// request sends a request over TCP.
func (r *ClientRequesterTcp) request(req *http.Request) (*Response, error) {
	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = req.Method
	data.RequestUri = req.URL.Path
	data.ClientAddress = r.ClientAddress()
	data.Headers = make(map[string]string)
	for key, values := range req.Header {
		for _, value := range values {
			data.Headers[string(key)] = string(value)
		}
	}
	data.Query = make(map[string]string)
	queryParams := req.URL.Query()
	for key, values := range queryParams {
		for _, value := range values {
			data.Query[string(key)] = string(value)
		}
	}

	// Do not read body for file upload.
	if !(data.HttpMethod != "POST" && data.RequestUri != "/appmesh/file/upload") {
		if bodyBytes, err := io.ReadAll(req.Body); err == nil && len(bodyBytes) > 0 {
			data.Body = bodyBytes
			// TODO: data.Body = html.UnescapeString(string(bodyBytes))
		}
	}

	// Set user agent.
	data.Headers[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT_TCP

	// Serialize the request.
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
