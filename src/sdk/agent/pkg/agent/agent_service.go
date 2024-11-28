package agent

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	"go.uber.org/zap"
)

const (
	REST_PATH_UPLOAD            = "/appmesh/file/upload"
	REST_PATH_DOWNLOAD          = "/appmesh/file/download"
	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	USER_AGENT_APPMESH_SDK      = "appmesh/sdk"
	USER_AGENT_APPMESH_TCP      = "appmesh/sdk/tcp"

	TCP_CHUNK_BLOCK_SIZE               = 16*1024 - 256 // target to 16KB
	TCP_MESSAGE_HEADER_LENGTH          = 4
	HTTP_HEADER_KEY_X_TARGET_HOST      = "X-Target-Host"
	HTTP_HEADER_KEY_X_Send_File_Socket = "X-Send-File-Socket"
	HTTP_HEADER_KEY_X_Recv_File_Socket = "X-Recv-File-Socket"
)

var (
	logger         *zap.SugaredLogger = utils.GetLogger()
	httpRequestMap sync.Map           // request map cache for asyncrized response

	localConnection        *Connection // tcp connection to the local server
	remoteConnections      sync.Map    // tcp connections to remote servers
	remoteConnectionsMutex sync.Mutex
	delegatePool           sync.Pool
)

// init function to initialize the delegate pool using net/http.Client
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

func monitorResponse(conn *Connection, targetHost string, allowError bool) {
	for {
		// read response from server
		response, err := ReadNewResponse(conn.conn)
		if err != nil {
			if !allowError {
				logger.Fatalf("Failed read response from host %s: %v", targetHost, err)
			} else {
				logger.Errorf("Failed read response from host %s: %v", targetHost, err)
				deleteConnection(targetHost)
				return
			}
		}

		// forward to channel and release map
		if t, ok := httpRequestMap.LoadAndDelete(response.Uuid); !ok {
			logger.Fatalf("Not found request ID <%s> for Response", response.Uuid)
		} else {
			// notify
			ch, _ := t.(chan *Response)
			ch <- response
		}
	}
}

func ListenRest() error {
	listenAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestListenPort)
	connectAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestTcpPort)
	// connect to TCP rest server
	targetHost := strings.Replace(connectAddr, "0.0.0.0", "127.0.0.1", 1)

	var err error
	localConnection, err = NewConnection(targetHost, config.ConfigData.REST.SSL.VerifyServer, false)
	if err != nil {
		logger.Fatalf("Failed to connected to TCP server <%s> with error: %v", connectAddr, err)
	}
	logger.Infof("Establish REST connection to TCP server <%s>", connectAddr)

	// HTTP router using gorilla/mux
	router := mux.NewRouter()

	// OpenAPI Swagger
	RegOpenapiRestHandler(router)

	// Grafana
	grafana.RegGrafanaRestHandler(router)

	// docker.sock proxy
	RegisterDockerRoutes(router)

	// AppMesh endpoints
	router.HandleFunc("/appmesh/{path:.*}", utils.Cors(utils.DefaultCORSConfig)(handleAppmeshResquest)).Methods("GET", "PUT", "POST", "DELETE")

	// Index & OPTIONS & HEAD
	router.HandleFunc("/", utils.Cors(utils.DefaultCORSConfig)(handleIndex)).Methods("GET")
	router.HandleFunc("/{path:.*}", utils.Cors(utils.DefaultCORSConfig)(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // Options handler
	})).Methods("OPTIONS", "HEAD")

	return startHttpsServer(listenAddr, router)
}

func startHttpsServer(restAgentAddr string, router *mux.Router) error {
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
			// TLS 1.2 ciphers
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// TLS 1.3 ciphers
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
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
		MaxHeaderBytes:    1 << 20,         // 1 MB (max header size)
	}

	// Start HTTPS server
	return listenAndServeTLS(restAgentAddr, server)
}

func listenAndServeTLS(address string, server *http.Server) error {
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

func handleIndex(w http.ResponseWriter, r *http.Request) {
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

func handleAppmeshResquest(w http.ResponseWriter, r *http.Request) {
	var targetConnection = localConnection

	// handle forward request
	// in order to share JWT token in cluster, share JWTSalt & Issuer JWT configuration
	forwardingHost := string(r.Header.Get(HTTP_HEADER_KEY_X_TARGET_HOST))
	if forwardingHost != "" {
		logger.Debugf("Forward request to %s", forwardingHost)

		parsedURL, _ := appmesh.ParseURL(forwardingHost)
		if parsedURL.Port() == strconv.Itoa(config.ConfigData.REST.RestListenPort) {
			// forward with HTTP protocal
			r.Header.Del(HTTP_HEADER_KEY_X_TARGET_HOST)
			forwardAppmeshRest(w, r, forwardingHost)
			return
		} else {
			// forward with TCP protocal
			var err error
			targetConnection, err = NewConnection(parsedURL.Host, config.ConfigData.REST.SSL.VerifyServerDelegate, true)
			if err != nil {
				logger.Errorf("Failed to connect TCP to target host %s with error: %v", forwardingHost, err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	// body buffer
	request := NewRequest(r)
	request.Headers[HTTP_USER_AGENT_HEADER_NAME] = USER_AGENT_APPMESH_SDK
	if targetConnection != localConnection {
		request.Headers[HTTP_USER_AGENT_HEADER_NAME] = USER_AGENT_APPMESH_TCP
		// file download & upload
		if request.RequestUri == REST_PATH_DOWNLOAD {
			request.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket] = "true"
		} else if request.RequestUri == REST_PATH_UPLOAD {
			request.Headers[HTTP_HEADER_KEY_X_Send_File_Socket] = "true"
		}
	}

	// create a chan for accept Response
	ch := make(chan *Response)
	httpRequestMap.Store(request.Uuid, ch)

	sendErr := targetConnection.sendRequestData(request)
	if sendErr == nil {
		// wait chan to get response
		resp := <-ch
		// reply to client
		resp.applyResponse(w, r)

		// handle file upload after response to client
		if resp.TempUploadFilePath != "" {
			sendErr = targetConnection.sendUploadFileData(resp.TempUploadFilePath)
		}
	}

	if sendErr != nil {
		logger.Errorf("Failed to send request to server with error: %v", sendErr)
		defer deleteConnection(forwardingHost)
	}
}

// forwardAppmeshRest forwards the incoming request to another host and copies the response back.
func forwardAppmeshRest(w http.ResponseWriter, r *http.Request, forwardingHost string) {
	// Parse the forwarding host URL
	parsedURL, err := appmesh.ParseURL(forwardingHost)
	if err != nil {
		logger.Warnf("Failed to parse forward URL: %v", err)
		http.Error(w, "Failed to parse forward URL: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new request to be sent to the target server
	targetURL := fmt.Sprintf("%s://%s%s?%s", parsedURL.Scheme, parsedURL.Host, r.URL.Path, r.URL.RawQuery)
	logger.Debugf("Forwarding request: %s %s", r.Method, targetURL)
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		logger.Errorf("Failed to create forward request: %v", err)
		http.Error(w, "Failed to create forward request: "+err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header = r.Header.Clone() // Copy headers from the original request

	// Forward the request to the target server
	delegateClient := delegatePool.Get().(*http.Client)
	defer delegatePool.Put(delegateClient)
	resp, err := delegateClient.Do(req)
	if err != nil {
		logger.Errorf("Forward request failed with error: %v", err)
		http.Error(w, "Failed to forward request: "+err.Error(), http.StatusInternalServerError)
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
		http.Error(w, "Failed to copy response body", http.StatusInternalServerError)
	}
}

func handleRestFile(w http.ResponseWriter, r *http.Request, data *Response) error {
	logger.Debugf("Requesting path: %s", r.URL.Path)

	filePath := r.Header.Get("File-Path")

	switch {
	case r.Method == http.MethodGet && r.URL.Path == REST_PATH_DOWNLOAD && data.HttpStatus == http.StatusOK:
		return handleDownload(w, r, data, filePath)
	case r.Method == http.MethodPost && r.URL.Path == REST_PATH_UPLOAD && data.HttpStatus == http.StatusOK:
		return handleUpload(w, r, data, filePath)
	default:
		return fmt.Errorf(data.Body)
	}
}

func handleDownload(w http.ResponseWriter, r *http.Request, data *Response, filePath string) error {
	if data.TempDownloadFilePath != "" {
		filePath = data.TempDownloadFilePath
		defer os.Remove(data.TempDownloadFilePath)
	}

	if !utils.IsValidFileName(filePath) {
		return fmt.Errorf("invalid file name")
	}

	_, fileName := filepath.Split(filePath)
	setDownloadHeaders(w, fileName)

	logger.Debugf("Serving file: %s", fileName)
	http.ServeFile(w, r, filePath)
	logger.Infof("Download file %s finished", filePath)
	return nil
}

func handleUpload(w http.ResponseWriter, r *http.Request, data *Response, filePath string) error {
	if data.TempUploadFilePath != "" {
		filePath = data.TempUploadFilePath
	}
	logger.Debugf("Uploading file: %s", filePath)

	if !utils.IsValidFileName(filePath) {
		return fmt.Errorf("invalid file name")
	}

	if err := saveUploadedFile(w, r, filePath); err != nil {
		return fmt.Errorf("save file failed with error: %w", err)
	}

	if data.TempUploadFilePath == "" {
		logger.Infof("File saved: %s", filePath)
		appmesh.SetFileAttributes(filePath, r.Header)
	}

	return nil
}

func setDownloadHeaders(w http.ResponseWriter, fileName string) {
	w.Header().Set("Content-Disposition", "attachment; filename="+url.QueryEscape(fileName))
	w.Header().Set("Content-Description", "File Transfer")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Transfer-Encoding", "binary")
	w.Header().Set("Expires", "0")
	w.Header().Set("Cache-Control", "must-revalidate")
	w.Header().Set("Pragma", "public")
}

// saveUploadedFile saves an uploaded file directly to the specified path without creating temp files.
// It supports both multipart/form-data and direct body uploads.
func saveUploadedFile(w http.ResponseWriter, r *http.Request, filePath string) error {
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