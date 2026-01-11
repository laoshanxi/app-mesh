package appmesh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

// AppMeshClientWSS interacts with the server over WSS transport.
type AppMeshClientWSS struct {
	*AppMeshClient
	wssReq *WSSRequester
}

// NewWSSClient creates a new AppMeshClientWSS.
func NewWSSClient(options Option) (*AppMeshClientWSS, error) {
	uri := options.AppMeshUri
	if uri == "" {
		uri = "https://127.0.0.1:6058"
	}
	parsed, err := ParseURL(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// ensure scheme is wss/ws
	switch parsed.Scheme {
	case "https":
		parsed.Scheme = "wss"
	case "http":
		parsed.Scheme = "ws"
	}

	wssRequester := &WSSRequester{
		WSSConnection: NewWSSConnection(),
		baseURL:       *parsed,
	}

	httpClient, err := newHTTPClientWithRequester(options, wssRequester)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP Client: %v", err)
	}
	value := true
	options.tcpOnly = &value

	wssClient := &AppMeshClientWSS{
		AppMeshClient: httpClient,
		wssReq:        wssRequester,
	}

	if err := wssRequester.WSSConnection.Connect(&wssRequester.baseURL, wssClient.sslClientCert, wssClient.sslClientCertKey, wssClient.sslCAFile); err != nil {
		return nil, err
	}
	return wssClient, nil
}

// CloseConnection closes the WSS connection.
func (c *AppMeshClientWSS) CloseConnection() {
	if c.wssReq != nil {
		c.wssReq.Close()
	}
}

func (c *AppMeshClientWSS) ReadMessage() ([]byte, error) {
	return c.wssReq.WSSConnection.ReadMessage()
}

func (c *AppMeshClientWSS) SendMessage(ctx context.Context, buffer []byte) error {
	return c.wssReq.WSSConnection.SendMessage(ctx, buffer)
}

// FileDownload downloads a file via an HTTP streaming endpoint after obtaining
// an authorization header through the WSS control channel.
func (c *AppMeshClientWSS) FileDownload(remoteFile, localFile string, applyFileAttributes bool) error {
	if remoteFile == "" {
		return fmt.Errorf("remote file path cannot be empty")
	}
	if localFile == "" {
		return fmt.Errorf("local file path cannot be empty")
	}

	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path: remoteFile,
	}

	status, msg, responseHeaders, err := c.get(REST_PATH_DOWNLOAD, nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to download %q: status=%d msg=%s", remoteFile, status, msg)
	}

	auth := responseHeaders.Get("Authorization")
	if auth == "" {
		return fmt.Errorf("server did not respond with file transfer authentication: Authorization")
	}

	// Prepare HTTP URL for streaming endpoint
	base := c.wssReq.baseURL
	scheme := "https"
	if base.Scheme == "ws" {
		scheme = "http"
	}
	fullURL := fmt.Sprintf("%s://%s/appmesh/file/download/ws", scheme, base.Host)

	httpConn := newHTTPConnection(c.sslClientCert, c.sslClientCertKey, c.sslCAFile, c.cookieFile)
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set(HTTP_HEADER_KEY_File_Path, remoteFile)

	resp, err := httpConn.Do(req)
	if err != nil {
		return fmt.Errorf("http download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("download failed: status=%d msg=%s", resp.StatusCode, string(body))
	}

	f, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("create local file %q failed: %w", localFile, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write file failed: %w", err)
	}

	if applyFileAttributes {
		_ = SetFileAttributes(localFile, resp.Header)
	}
	return nil
}

// FileUpload uploads a local file via HTTP streaming endpoint after obtaining
// an authorization header through the WSS control channel.
func (c *AppMeshClientWSS) FileUpload(ctx context.Context, localFile, remoteFile string, applyFileAttributes bool) error {
	if localFile == "" {
		return fmt.Errorf("local file path cannot be empty")
	}
	if remoteFile == "" {
		return fmt.Errorf("remote file path cannot be empty")
	}

	f, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("open local file %q failed: %w", localFile, err)
	}
	defer f.Close()

	headers := map[string]string{
		HTTP_HEADER_KEY_File_Path: remoteFile,
	}

	if applyFileAttributes {
		attrs, err := GetFileAttributes(localFile)
		if err != nil {
			return err
		}
		MergeStringMaps(headers, attrs)
	}

	status, msg, responseHeaders, err := c.post(REST_PATH_UPLOAD, nil, headers, nil)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("failed to upload %q: status=%d msg=%s", localFile, status, msg)
	}

	auth := responseHeaders.Get("Authorization")
	if auth == "" {
		return fmt.Errorf("server did not respond with file transfer authentication: Authorization")
	}

	base := c.wssReq.baseURL
	scheme := "https"
	if base.Scheme == "ws" {
		scheme = "http"
	}
	fullURL := fmt.Sprintf("%s://%s/appmesh/file/upload/ws", scheme, base.Host)

	httpConn := newHTTPConnection(c.sslClientCert, c.sslClientCertKey, c.sslCAFile, c.cookieFile)
	req, err := http.NewRequest(http.MethodPost, fullURL, f)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", auth)
	req.Header.Set(HTTP_HEADER_KEY_File_Path, remoteFile)
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpConn.Do(req)
	if err != nil {
		return fmt.Errorf("http upload failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: status=%d msg=%s", resp.StatusCode, string(body))
	}
	return nil
}
