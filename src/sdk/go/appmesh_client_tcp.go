package appmesh

import (
	"encoding/binary"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/rs/xid"
)

const PROTOBUF_HEADER_LENGTH = 4
const TCP_CHUNK_READ_BLOCK_SIZE = 8192

// AppMeshClientTCP interacts with the TCP server using REST API requests via a socket.
type AppMeshClientTCP struct {
	*AppMeshClient
	tcpExecutor *ClientRequesterTcp
}

// NewTcpClient creates a new AppMeshClientTCP instance for interacting with a TCP server.
func NewTcpClient(options Option) (*AppMeshClientTCP, error) {
	tcpRequester := &ClientRequesterTcp{
		baseURL: func() string {
			if options.AppMeshUri != "" {
				return options.AppMeshUri
			}
			return DEFAULT_TCP_URI
		}(),
	}

	client := &AppMeshClientTCP{AppMeshClient: NewHttpClient(options), tcpExecutor: tcpRequester}

	client.AppMeshClient.proxy = tcpRequester

	return client, tcpRequester.connectSocket(
		client.sslClientCert,
		client.sslClientCertKey,
		client.sslCAFile,
	)
}

// CloseConnection closes the TCP connection
func (client *AppMeshClientTCP) CloseConnection() {
	if client.tcpExecutor != nil && client.tcpExecutor.socketConn != nil {
		client.tcpExecutor.socketConn.Close()
		client.tcpExecutor.socketConn = nil
	}
}

// FileDownload downloads a file from the server to the local file system
func (r *AppMeshClientTCP) FileDownload(filePath, localFile string) error {
	headers := map[string]string{
		"File-Path":                        filePath,
		HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
	}

	status, msg, responseHeaders, err := r.get("/appmesh/file/download", nil, headers)
	if err != nil || status != http.StatusOK {
		return errors.New("failed to download file: " + string(msg))
	}

	if _, ok := responseHeaders[HTTP_HEADER_KEY_X_RECV_FILE_SOCKET]; !ok {
		return errors.New("HTTP_HEADER_KEY_X_RECV_FILE_SOCKET header missing")
	}

	return r.receiveFile(localFile, responseHeaders)
}

// Helper function to receive file data
func (r *AppMeshClientTCP) receiveFile(localFile string, headers http.Header) error {
	file, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	for {
		chunkSizeBuf, err := r.tcpExecutor.readTcpData(PROTOBUF_HEADER_LENGTH)
		if err != nil {
			return err
		}

		chunkSize := binary.BigEndian.Uint32(chunkSizeBuf)
		if chunkSize == 0 {
			break
		}

		chunkData, err := r.tcpExecutor.readTcpData((chunkSize))
		if err != nil {
			return err
		}

		if _, err := file.Write(chunkData); err != nil {
			return err
		}
	}

	SetFileAttributes(localFile, headers)
	return nil
}

// FileUpload uploads a local file to the server
func (client *AppMeshClientTCP) FileUpload(localFile, filePath string) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	headers := map[string]string{
		"File-Path":                        filePath,
		"Content-Type":                     "text/plain",
		HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: "true",
	}

	// Get the file attributes
	attrs, err := GetFileAttributes(localFile)
	MergeStringMaps(headers, attrs)
	if err != nil {
		return err
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

// Helper function to upload file in chunks
func (client *AppMeshClientTCP) uploadFileChunks(file *os.File) error {
	chunkSize := 8 * 1024
	buffer := make([]byte, chunkSize)

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		if err := client.tcpExecutor.sendData(buffer[:n]); err != nil {
			return err
		}
	}

	// Send end-of-file marker
	return client.tcpExecutor.sendEOFMarker()
}

// TCP Request executor
type ClientRequesterTcp struct {
	baseURL    string
	socketConn net.Conn
	mutex      sync.Mutex
}

// doRequest performs a REST-like request over TCP
func (r *ClientRequesterTcp) doRequest(method, apiPath string, queries url.Values, headers map[string]string, body io.Reader, token string, forwardingHost string) (int, []byte, http.Header, error) {
	u, _ := ParseURL(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if queries != nil {
		u.RawQuery = queries.Encode()
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return 0, nil, nil, err
	}

	// Set headers
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

	// Execute the TCP request
	resp, err := r.request(req)

	// Format the response headers
	respHeaders := make(http.Header)
	for key, value := range resp.Headers {
		respHeaders.Add(key, value)
	}

	return resp.HttpStatus, []byte(resp.Body), respHeaders, err
}

// connectSocket establishes a secure TCP connection
func (r *ClientRequesterTcp) connectSocket(sslClientCert string, sslClientCertKey string, sslCAFile string) error {
	u, err := ParseURL(r.baseURL)
	if err != nil {
		return err
	}
	address := net.JoinHostPort(u.Hostname(), u.Port())

	ssl := &SSLConfig{
		VerifyClient:                sslClientCert != "" && sslClientCertKey != "",
		SSLClientCertificateFile:    sslClientCert,
		SSLClientCertificateKeyFile: sslClientCertKey,
		VerifyServer:                sslCAFile != "",
		SSLCaPath:                   sslCAFile,
	}

	r.socketConn, err = ConnectAppMeshServer(address, ssl.VerifyServer, ssl)
	return err
}

// request sends a request over TCP
func (r *ClientRequesterTcp) request(req *http.Request) (*Response, error) {

	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = req.Method
	data.RequestUri = req.URL.Path
	data.ClientAddress = r.socketConn.LocalAddr().String()
	data.Headers = make(map[string]string)
	for key, values := range req.Header {
		for _, value := range values {
			data.Headers[string(key)] = string(value)
		}
	}
	data.Queries = make(map[string]string)
	queryParams := req.URL.Query()
	for key, values := range queryParams {
		for _, value := range values {
			data.Queries[string(key)] = string(value)
		}
	}

	// do not read body for file upload
	if !(data.HttpMethod != "POST" && data.RequestUri != "/appmesh/file/upload") {
		if bodyBytes, err := io.ReadAll(req.Body); err == nil && len(bodyBytes) > 0 {
			data.Body = html.UnescapeString(string(bodyBytes))
		}
	}

	// Set user agent
	data.Headers[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT_TCP

	// Serialize the request
	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	// Send the data over TCP
	if err := r.sendData(buf); err != nil {
		return nil, err
	}

	// Receive the response
	respData, err := r.recvData()
	if err != nil {
		return nil, err
	}

	// Deserialize the response
	respMsg := &Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}

// sendData sends the message length and the actual message data over TCP
func (r *ClientRequesterTcp) sendData(data []byte) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Send length header
	if err := r.sendLength(len(data)); err != nil {
		return err
	}

	// Send message data
	return r.sendTcpData(data)
}

// sendLength sends the length of the data as a 4-byte header
func (r *ClientRequesterTcp) sendLength(length int) error {
	lenBuf := make([]byte, PROTOBUF_HEADER_LENGTH)
	binary.BigEndian.PutUint32(lenBuf, uint32(length))
	return r.sendTcpData(lenBuf)
}

func (r *ClientRequesterTcp) sendTcpData(buf []byte) error {
	var totalSentSize int = 0
	var err error = nil
	for totalSentSize < len(buf) {
		byteSent := 0

		if byteSent, err = r.socketConn.Write(buf[totalSentSize:]); err != nil {
			return err
		}
		totalSentSize += byteSent
		//log.Printf("total send size %d bytes", totalSentSize)
	}
	return err
}

// sendEOFMarker sends an end-of-file marker
func (r *ClientRequesterTcp) sendEOFMarker() error {
	return r.sendLength(0)
}

// recvData receives a length-prefixed message from the TCP connection
func (r *ClientRequesterTcp) recvData() ([]byte, error) {
	lenBuf, err := r.readTcpData(PROTOBUF_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}

	msgLen := binary.BigEndian.Uint32(lenBuf)
	return r.readTcpData((msgLen))
}

// readTcpData reads a specific number of bytes from the TCP connection
func (r *ClientRequesterTcp) readTcpData(msgLength uint32) ([]byte, error) {
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
		n, err := r.socketConn.Read(data)
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
