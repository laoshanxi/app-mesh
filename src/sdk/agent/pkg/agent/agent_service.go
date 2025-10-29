package agent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/grafana"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/pkg/errors"
)

// Constants for REST paths and headers
const (
	COOKIE_TOKEN                = "appmesh_auth_token"
	COOKIE_CSRF_TOKEN           = "appmesh_csrf_token"
	REST_PATH_LOGIN             = "/appmesh/login"
	REST_PATH_AUTH              = "/appmesh/auth"
	REST_PATH_TOTP_VALIDATE     = "/appmesh/totp/validate"
	REST_PATH_LOGOFF            = "/appmesh/self/logoff"
	REST_PATH_TOKEN_RENEW       = "/appmesh/token/renew"
	REST_PATH_TOTP_SETUP        = "/appmesh/totp/setup"
	REST_PATH_UPLOAD            = "/appmesh/file/upload"
	REST_PATH_DOWNLOAD          = "/appmesh/file/download"
	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	USER_AGENT_APPMESH_SDK      = "appmesh/sdk"
	USER_AGENT_APPMESH_TCP      = "appmesh/sdk/tcp"

	HTTP_HEADER_KEY_X_SET_COOKIE       = "X-Set-Cookie"
	HTTP_HEADER_KEY_X_CSRF_TOKEN       = "X-CSRF-Token"
	HTTP_HEADER_KEY_X_TARGET_HOST      = "X-Target-Host"
	HTTP_HEADER_KEY_X_Send_File_Socket = "X-Send-File-Socket"
	HTTP_HEADER_KEY_X_Recv_File_Socket = "X-Recv-File-Socket"
	HTTP_HEADER_KEY_File_Path          = "X-File-Path"

	TCP_CHUNK_BLOCK_SIZE = appmesh.TCP_CHUNK_BLOCK_SIZE
)

var (
	logger          = utils.GetLogger()
	REST_PATH_TASK  = regexp.MustCompile(`/appmesh/app/([^/*]+)/task`)
	localConnection *Connection // TCP connection to the local server

	delegatePool sync.Pool
)

// Initialize the delegate pool using net/http.Client
func init() {
	delegatePool = sync.Pool{
		New: func() interface{} {
			// Load custom CA if server verification is enabled
			var serverCA *x509.CertPool
			if config.ConfigData.REST.SSL.VerifyServerDelegate {
				serverCA, _ = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
			}

			// Return the new *http.Client with the TLS config
			return &http.Client{
				Timeout: 2 * time.Minute,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: !(config.ConfigData.REST.SSL.VerifyServerDelegate),
						RootCAs:            serverCA, // Use the custom CA if available
					},
				},
			}
		},
	}
}

// MonitorConnectionResponse continuously reads messages from a connection and forwards responses
// to their corresponding channels. It handles connection cleanup on errors.
func MonitorConnectionResponse(conn *Connection, allowError bool) {
	defer DeleteConnection(conn)

	// Helper function to handle errors consistently
	handleError := func(msg string, args ...interface{}) {
		logMsg := fmt.Sprintf(msg, args...)
		if allowError {
			logger.Error(logMsg)
			return
		}
		logger.Fatal(logMsg)
	}

	for {
		response, err := ReadAppMeshResponse(conn)
		if err != nil {
			handleError("Failed to parse response from host %s: %v", conn, err)
			return
		}

		conn.onResponse(response)
	}
}

// ListenAndServeREST starts the REST API server
func ListenAndServeREST() error {
	var listenAddr = config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestListenPort)
	var hostPort = config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestTcpPort)

	hostPort = strings.Replace(hostPort, "0.0.0.0", "127.0.0.1", 1)
	connectAddr, err := net.ResolveTCPAddr("tcp", hostPort)
	if err != nil {
		log.Fatalf("Failed to resolve address %s: %v", hostPort, err)
	}

	localConnection, err = GetOrCreateConnection(connectAddr, config.ConfigData.REST.SSL.VerifyServer, false)
	if err != nil {
		logger.Fatalf("Failed to connect to TCP server <%s> with error: %v", connectAddr, err)
	}
	logger.Infof("Established REST connection to TCP server <%s>", connectAddr)

	// Check env "APPMESH_CORS_DISABLE"
	corsDisabled := os.Getenv("APPMESH_CORS_DISABLE") != ""
	if corsDisabled {
		corsDisabled, _ = strconv.ParseBool(os.Getenv("APPMESH_CORS_DISABLE"))
	}
	utils.EnableGlobalCORS(!corsDisabled)
	logger.Infof("CORS enabled: %v (from env APPMESH_CORS_DISABLE=%s)", !corsDisabled, os.Getenv("APPMESH_CORS_DISABLE"))

	// HTTP router using gorilla/mux
	router := mux.NewRouter()

	// OpenAPI Swagger
	RegisterOpenAPIRoutes(router)

	// Grafana
	grafana.RegGrafanaRestHandler(router)

	// docker.sock proxy
	RegisterDockerRoutes(router)

	// AppMesh endpoints
	router.HandleFunc("/appmesh/{path:.*}", utils.Cors(utils.DefaultCORSConfig)(HandleAppMeshRequest)).Methods("GET", "PUT", "POST", "DELETE")
	// Forward /metrics to /appmesh/metrics
	router.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = "/appmesh/metrics" // Change the URL path to /appmesh/metrics
		router.ServeHTTP(w, r)
	}).Methods(http.MethodGet)

	// Index & OPTIONS & HEAD
	router.HandleFunc("/", utils.Cors(utils.DefaultCORSConfig)(HandleIndex)).Methods(http.MethodGet)
	router.HandleFunc("/{path:.*}", utils.Cors(utils.DefaultCORSConfig)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // Options handler
	})).Methods("OPTIONS", "HEAD")

	return StartHTTPSServer(listenAddr, router)
}

// StartHTTPSServer starts the HTTPS server with the provided router
func StartHTTPSServer(restAgentAddr string, router *mux.Router) error {
	// Load server certificate and key
	serverCA, err := appmesh.LoadCertificatePair(
		config.ConfigData.REST.SSL.SSLCertificateFile,
		config.ConfigData.REST.SSL.SSLCertificateKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	// Client authentication
	clientAuth := tls.NoClientCert
	var clientCA *x509.CertPool
	if config.ConfigData.REST.SSL.VerifyClient {
		clientAuth = tls.RequireAndVerifyClientCert
		clientCA, err = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
		if err != nil {
			return fmt.Errorf("failed to load client CA: %w", err)
		}
	}

	// TLS configuration
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		InsecureSkipVerify:       !config.ConfigData.REST.SSL.VerifyServer, // Client verifies the server certificate chain
		Certificates:             []tls.Certificate{serverCA},
		CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.CurveP384}, // Remove P521 for performance
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// TLS 1.3 ciphers
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,

			// TLS 1.2 (fallback and broader compatibility)
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},

		// Client authentication
		ClientAuth: clientAuth,
		ClientCAs:  clientCA,

		// Optimize session resumption
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),

		// Enable HTTP/2 and HTTP/1.1
		// NextProtos: []string{"h2", "http/1.1"},
		// NOTE:HTTP/2 protocol requires all headers to be in lowercase
	}

	// HTTP server configuration
	server := &http.Server{
		Addr:              restAgentAddr,
		Handler:           router,
		TLSConfig:         tlsConfig,
		ReadTimeout:       5 * time.Minute, // Increase to handle slow uploads
		WriteTimeout:      5 * time.Minute, // Increase to handle large file downloads
		IdleTimeout:       2 * time.Minute, // Keep-alive timeout for idle connections
		ReadHeaderTimeout: 1 * time.Minute, // Limit time to read headers for security
		MaxHeaderBytes:    64 << 10,        // 64 KB (max header size)
	}

	// Start HTTPS server
	return ListenAndServeTLS(restAgentAddr, server)
}

// ListenAndServeTLS starts the TLS server
func ListenAndServeTLS(address string, server *http.Server) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", address, err)
	}

	logger.Infof("<App Mesh Agent> Listening on %s", address)
	tlsListener := tls.NewListener(ln, server.TLSConfig)
	if err := server.Serve(tlsListener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

// HandleIndex serves the index page
func HandleIndex(w http.ResponseWriter, r *http.Request) {
	htmlContent := `
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>App Mesh</title>
	<style>
		body {
			display: flex;
			flex-direction: column;
			min-height: 100vh;
			margin: 0;
			font-family: Arial, sans-serif;
		}
		.content {
			flex: 1;
		}
		.footer {
			text-align: center;
			padding: 1em;
			background-color: #f1f1f1;
		}
	</style>
</head>
<body>
	<div class="content">
		<p>Welcome to App Mesh!</p>
	</div>
	<div class="footer">
		<a id="swagger-link" href="#">View Swagger Documentation</a> | <a href="/openapi.yaml">OpenAPI definition</a>
	</div>
	<script>
		document.addEventListener("DOMContentLoaded", function() {
			var swaggerLink = document.getElementById("swagger-link");
			swaggerLink.addEventListener("click", function(event) {
				event.preventDefault();
				var currentDomain = window.location.origin;
				var swaggerURL = "https://petstore.swagger.io/?url=" + encodeURIComponent(currentDomain + "/openapi.yaml");
				window.location.href = swaggerURL;
			});
		});
	</script>
</body>
</html>
`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(htmlContent))
}

// HandleAppMeshRequest processes AppMesh requests
func HandleAppMeshRequest(w http.ResponseWriter, r *http.Request) {
	var targetConnection = localConnection

	// Handle forward request
	forwardingHost := string(r.Header.Get(HTTP_HEADER_KEY_X_TARGET_HOST))
	if forwardingHost != "" {
		logger.Debugf("Forward request to %s", forwardingHost)

		forwardingURL, err := appmesh.ParseURL(forwardingHost)
		if err != nil {
			utils.HttpError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		forwardingAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(forwardingURL.Hostname(), forwardingURL.Port()))
		if err != nil {
			utils.HttpError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// If no port is provided, use HTTP forwarding
		if forwardingURL.Port() == "" || forwardingURL.Port() == strconv.Itoa(config.ConfigData.REST.RestListenPort) {
			// Forward with HTTP protocol
			r.Header.Del(HTTP_HEADER_KEY_X_TARGET_HOST)
			ForwardAppMeshRequest(w, r, forwardingURL)
			return
		} else {
			// Forward with TCP protocol
			targetConnection, err = GetOrCreateConnection(forwardingAddr, config.ConfigData.REST.SSL.VerifyServerDelegate, true)
			if err != nil {
				logger.Errorf("Failed to connect TCP to target host %s with error: %v", forwardingHost, err)
				utils.HttpError(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	// Handle X-File-Path URI decode
	if filePath := r.Header.Get(HTTP_HEADER_KEY_File_Path); filePath != "" {
		r.Header.Set(HTTP_HEADER_KEY_File_Path, utils.DecodeURIComponent(filePath))
	}

	// Body buffer
	request, err := NewAppMeshRequest(r)
	if err != nil {
		utils.HttpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	request.Headers[HTTP_USER_AGENT_HEADER_NAME] = USER_AGENT_APPMESH_SDK
	if targetConnection != localConnection {
		request.Headers[HTTP_USER_AGENT_HEADER_NAME] = USER_AGENT_APPMESH_TCP
		// File download & upload
		switch request.RequestUri {
		case REST_PATH_DOWNLOAD:
			request.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket] = "true"
		case REST_PATH_UPLOAD:
			request.Headers[HTTP_HEADER_KEY_X_Send_File_Socket] = "true"
		}
	}

	resp, sendErr := targetConnection.SendRequestDataWithContext(r.Context(), request)
	if sendErr != nil {
		logger.Errorf("Failed to send request to server with error: %v", sendErr)

		// Only delete remote connections on error, not local connection
		if targetConnection != localConnection {
			DeleteConnection(targetConnection)
		}

		utils.HttpError(w, sendErr.Error(), http.StatusInternalServerError)
		return
	}

	// Reply to client
	resp.ApplyResponse(w, r, request)

	// Handle file upload after response to client
	if resp.TempUploadFilePath != "" {
		sendErr = targetConnection.SendFileDataWithContext(r.Context(), resp.TempUploadFilePath)
		if sendErr != nil {
			logger.Errorf("Failed to send file data: %v", sendErr)
			// Only delete connection on file send error
			if targetConnection != localConnection {
				DeleteConnection(targetConnection)
			}
			// Don't return error to client since response was already sent
		}
	}
}

// ForwardAppMeshRequest forwards the incoming request to another host and copies the response back.
func ForwardAppMeshRequest(w http.ResponseWriter, r *http.Request, forwardingHost *url.URL) {
	// Create a new request to be sent to the target server
	targetURL := fmt.Sprintf("%s://%s%s?%s", forwardingHost.Scheme, forwardingHost.Host, r.URL.Path, r.URL.RawQuery)
	logger.Debugf("Forwarding request: %s %s", r.Method, targetURL)
	req, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, r.Body)
	if err != nil {
		logger.Errorf("Failed to create forward request: %v", err)
		utils.HttpError(w, "Failed to create forward request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone() // Copy headers from the original request

	// Forward the request to the target server
	delegateClient := delegatePool.Get().(*http.Client)
	defer delegatePool.Put(delegateClient)
	resp, err := delegateClient.Do(req)
	if err != nil {
		logger.Errorf("Forward request failed with error: %v", err)
		utils.HttpError(w, "Failed to forward request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close() // Ensure the response body is closed after use

	// Copy response headers from the forwarded response
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Set(key, value)
		}
	}

	// Copy the status code from the forwarded response
	w.WriteHeader(resp.StatusCode)

	// Copy the response body to the original response
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		utils.HttpError(w, "Failed to copy response body", http.StatusInternalServerError)
	}
}

// HandleRESTFile processes file upload and download requests
func HandleRESTFile(w http.ResponseWriter, r *http.Request, data *Response) error {
	logger.Debugf("Requesting path: %s", r.URL.Path)

	filePath := r.Header.Get(HTTP_HEADER_KEY_File_Path)

	switch {
	case r.Method == http.MethodGet && r.URL.Path == REST_PATH_DOWNLOAD && data.HttpStatus == http.StatusOK:
		return HandleDownload(w, r, data, filePath)
	case r.Method == http.MethodPost && r.URL.Path == REST_PATH_UPLOAD && data.HttpStatus == http.StatusOK:
		return HandleUpload(w, r, data, filePath)
	default:
		return errors.New(string(data.Body))
	}
}

// HandleDownload processes file download requests
func HandleDownload(w http.ResponseWriter, r *http.Request, data *Response, filePath string) error {
	if data.TempDownloadFilePath != "" {
		filePath = data.TempDownloadFilePath
		defer os.Remove(data.TempDownloadFilePath)
	}

	if !utils.IsValidFileName(filePath) {
		return fmt.Errorf("invalid file name")
	}

	_, fileName := filepath.Split(filePath)
	SetDownloadHeaders(w, fileName)

	logger.Debugf("Serving file: %s", fileName)
	http.ServeFile(w, r, filePath)
	logger.Infof("Download file %s finished", filePath)
	return nil
}

// HandleUpload processes file upload requests
func HandleUpload(w http.ResponseWriter, r *http.Request, data *Response, filePath string) error {
	if data.TempUploadFilePath != "" {
		filePath = data.TempUploadFilePath
	}
	logger.Debugf("Uploading file: %s", filePath)

	if !utils.IsValidFileName(filePath) {
		return fmt.Errorf("invalid file name")
	}

	if err := SaveUploadedFile(w, r, filePath); err != nil {
		return fmt.Errorf("save file failed with error: %w", err)
	}

	if data.TempUploadFilePath == "" {
		logger.Infof("File saved: %s", filePath)
		err := appmesh.SetFileAttributes(filePath, r.Header)
		if err != nil {
			logger.Warnf("Failed to set file attributes for %s: %v", filePath, err)
		}
	}

	return nil
}

// SetDownloadHeaders sets the headers for file download responses
func SetDownloadHeaders(w http.ResponseWriter, fileName string) {
	w.Header().Set("Content-Disposition", "attachment; filename="+url.QueryEscape(fileName))
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Header().Set("Pragma", "public")
}

// SaveUploadedFile saves an uploaded file directly to the specified path without creating temp files.
// It supports both multipart/form-data and direct body uploads.
func SaveUploadedFile(w http.ResponseWriter, r *http.Request, filePath string) error {
	if filePath == "" {
		return errors.New("file path cannot be empty")
	}

	maxFileSize := int64(2) << 30 // 2GB in bytes
	bufferSize := 32 * 1024       // 32KB chunks for buffered copying

	// Create the destination file with proper permissions
	dst, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	// Limit the size of the incoming request body
	r.Body = http.MaxBytesReader(w, r.Body, maxFileSize)

	var src io.ReadCloser

	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		// Handle multipart upload without creating a temp file
		mr, err := r.MultipartReader()
		if err != nil {
			return fmt.Errorf("failed to create multipart reader: %w", err)
		}

		// Find the file part
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return errors.New("file part not found in multipart form")
			}
			if err != nil {
				return fmt.Errorf("failed to read multipart form: %w", err)
			}

			if part.FormName() == "file" {
				src = part
				break
			}
			part.Close()
		}
	} else {
		// Handle direct body upload
		src = r.Body
	}
	defer src.Close()

	// Use io.CopyBuffer for efficient streaming with a fixed-size buffer
	buf := make([]byte, bufferSize)
	if _, err := io.CopyBuffer(dst, src, buf); err != nil {
		// In case of error, attempt to remove the partially written file
		dst.Close()
		os.Remove(filePath)
		return fmt.Errorf("failed to copy file data: %w", err)
	}

	return nil
}
