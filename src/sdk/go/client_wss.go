package appmesh

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

// AppMeshClientWSS interacts with the server over WSS transport.
type AppMeshClientWSS struct {
	*AppMeshClient
	wssReq *WSSRequester
}

// NewWSSClient creates a WSS transport client that reuses the standard App Mesh client API.
func NewWSSClient(options Option) (*AppMeshClientWSS, error) {
	uri := options.AppMeshURI
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
		psk:           options.PSK,
	}

	httpClient, err := newHTTPClientWithRequester(options, wssRequester)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP Client: %v", err)
	}
	wssClient := &AppMeshClientWSS{
		AppMeshClient: httpClient,
		wssReq:        wssRequester,
	}

	if err := wssRequester.WSSConnection.Connect(&wssRequester.baseURL, wssClient.sslClientCert,
		wssClient.sslClientCertKey, wssClient.sslCAFile, wssRequester.getAccessToken()); err != nil {
		return nil, err
	}
	wssRequester.sslClientCert = wssClient.sslClientCert
	wssRequester.sslClientKey = wssClient.sslClientCertKey
	wssRequester.sslCAFile = wssClient.sslCAFile
	wssRequester.connectedToken = wssRequester.getAccessToken()
	return wssClient, nil
}

// CloseConnection closes only the underlying WebSocket connection.
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

// forwardTarget is the X-Target-Host value for the HTTP(S) data side channel,
// the same value as the WSS control request (a bare host is resolved server-side).
func (c *AppMeshClientWSS) forwardTarget() string {
	return c.wssReq.getForwardTo()
}

// sseRequest opens an SSE stream over a direct HTTPS connection to the same
// REST listener the WSS control channel runs on: the framed transport cannot
// carry a chunked stream, so streams bypass it like the file data channel.
func (w *WSSRequester) sseRequest(ctx context.Context, method string, apiPath string, queries url.Values,
	headers map[string]string, body []byte) (int, io.ReadCloser, http.Header, error) {
	base := w.baseURL
	switch base.Scheme {
	case "wss":
		base.Scheme = "https"
	case "ws":
		base.Scheme = "http"
	}
	return sseSideChannel{base: base, token: w.getAccessToken(), agent: userAgentWSS, signer: w.getRequestSigner(),
		clientCert: w.sslClientCert, clientKey: w.sslClientKey, caFile: w.sslCAFile}.open(ctx, method, apiPath,
		queries, headers, body)
}

// DownloadFileContext downloads a file through the WSS control channel plus HTTP(S) streaming data path.
// When applyFileAttributes is true, returned POSIX metadata is applied locally best-effort.
func (c *AppMeshClientWSS) DownloadFileContext(ctx context.Context, remoteFile, localFile string,
	applyFileAttributes bool) error {
	if remoteFile == "" {
		return fmt.Errorf("remote file path cannot be empty")
	}
	// Default the local filename to the remote file's base name when omitted.
	if localFile == "" {
		localFile = filepath.Base(remoteFile)
	}

	// No control-channel preflight: the /ws side channel runs the identical daemon
	// handler, so a preflight only re-read the whole file into a discarded WS message.
	accessToken := c.wssReq.getAccessToken()
	if accessToken == "" {
		return fmt.Errorf("file transfer requires a bearer token")
	}
	auth := "Bearer " + accessToken

	// Prepare HTTP URL for streaming endpoint
	base := c.wssReq.baseURL
	scheme := "https"
	if base.Scheme == "ws" {
		scheme = "http"
	}
	fullURL := fmt.Sprintf("%s://%s/appmesh/file/download/ws", scheme, base.Host)

	httpConn, err := newHTTPConnection(c.sslClientCert, c.sslClientCertKey, c.sslCAFile)
	if err != nil {
		return fmt.Errorf("failed to create HTTP connection: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", auth)
	req.Header.Set(headerFilePath, escapeRemoteFilePath(remoteFile))
	if target := c.forwardTarget(); target != "" {
		req.Header.Set(headerTargetHost, target)
	}
	// The /ws file endpoints enforce the same request-signature hardening as
	// every other route; sign the side-channel request too (empty-body hash,
	// the streamed file content is exempt by design).
	if err := signHTTPRequest(req, nil, c.wssReq.getRequestSigner()); err != nil {
		return err
	}

	resp, err := httpConn.Do(req)
	if err != nil {
		return fmt.Errorf("http download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return newAPIErrorText("download file", resp.StatusCode, string(body),
			fmt.Sprintf("download failed: status=%d msg=%s", resp.StatusCode, string(body)))
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
		_ = ApplyFileAttributes(localFile, resp.Header)
	}
	return nil
}

// DownloadFile downloads a file via the WSS control channel plus HTTP(S) streaming
// data path.
func (c *AppMeshClientWSS) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	return c.DownloadFileContext(context.Background(), remoteFile, localFile, applyFileAttributes)
}

// UploadFileContext uploads a file through the WSS control channel plus HTTP(S) streaming data path.
// When applyFileAttributes is true, local POSIX metadata is sent so the server can recreate it.
func (c *AppMeshClientWSS) UploadFileContext(ctx context.Context, localFile, remoteFile string,
	applyFileAttributes bool) error {
	if localFile == "" {
		return fmt.Errorf("local file path cannot be empty")
	}
	// Default the remote filename to the local file's base name when omitted.
	if remoteFile == "" {
		remoteFile = filepath.Base(localFile)
	}

	f, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("open local file %q failed: %w", localFile, err)
	}
	defer f.Close()

	headers := map[string]string{
		headerFilePath: escapeRemoteFilePath(remoteFile),
	}

	if applyFileAttributes {
		attrs, err := fileAttributes(localFile)
		if err != nil {
			return fmt.Errorf("failed to read file attributes of %q: %w", localFile, err)
		}
		for key, value := range attrs {
			headers[key] = value
		}
	}

	status, msg, _, err := c.post(restPathUpload, nil, headers, nil)
	if err != nil {
		return fmt.Errorf("upload request failed: %w", err)
	}
	// The WS upload surface answers 201 Created with a success JSON body.
	if status != http.StatusOK && status != http.StatusCreated {
		return newAPIErrorText("upload file", status, string(msg), fmt.Sprintf("failed to upload %q: status=%d msg=%s",
			localFile, status, msg))
	}

	accessToken := c.wssReq.getAccessToken()
	if accessToken == "" {
		return fmt.Errorf("file transfer requires a bearer token")
	}
	auth := "Bearer " + accessToken

	base := c.wssReq.baseURL
	scheme := "https"
	if base.Scheme == "ws" {
		scheme = "http"
	}
	fullURL := fmt.Sprintf("%s://%s/appmesh/file/upload/ws", scheme, base.Host)

	httpConn, err := newHTTPConnection(c.sslClientCert, c.sslClientCertKey, c.sslCAFile)
	if err != nil {
		return fmt.Errorf("failed to create HTTP connection: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, fullURL, f)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	req.Header.Set("Authorization", auth)
	req.Header.Set(headerFilePath, escapeRemoteFilePath(remoteFile))
	req.Header.Set("Content-Type", "application/octet-stream")
	if target := c.forwardTarget(); target != "" {
		req.Header.Set(headerTargetHost, target)
	}
	// Same request-signature hardening as the download side channel; the
	// streamed file content is exempt (empty-body hash) by design.
	if err := signHTTPRequest(req, nil, c.wssReq.getRequestSigner()); err != nil {
		return err
	}

	resp, err := httpConn.Do(req)
	if err != nil {
		return fmt.Errorf("http upload failed: %w", err)
	}
	defer resp.Body.Close()

	// The daemon's streaming upload surface answers 201 Created on success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return newAPIErrorText("upload file", resp.StatusCode, string(body),
			fmt.Sprintf("upload failed: status=%d msg=%s", resp.StatusCode, string(body)))
	}
	return nil
}

// UploadFile uploads a local file via the WSS control channel plus HTTP(S) streaming
// data path.
func (c *AppMeshClientWSS) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	return c.UploadFileContext(context.Background(), localFile, remoteFile, applyFileAttributes)
}
