package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/buaazp/fasthttprouter"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/grafana"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"github.com/valyala/fasthttp"
)

const (
	REST_PATH_UPLOAD            = "/appmesh/file/upload"
	REST_PATH_DOWNLOAD          = "/appmesh/file/download"
	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	USER_AGENT_APPMESH_SDK      = "appmesh/sdk"
	USER_AGENT_APPMESH_TCP      = "appmesh/sdk/tcp"
)

type safeConn struct {
	conn net.Conn
	mu   sync.Mutex
}

type tcpConnections struct {
	mu          sync.Mutex
	connections map[string]*safeConn
}

var (
	localConnection *safeConn // tcp connection to the server
	requestMap      sync.Map  // request map cache for asyncrized response

	clientPoolHttp sync.Pool
	clientPoolTcp  = &tcpConnections{connections: make(map[string]*safeConn)}
)

func init() {
	clientPoolHttp = sync.Pool{
		New: func() interface{} {
			var serverCA *x509.CertPool
			if config.ConfigData.REST.SSL.VerifyServer {
				serverCA, _ = utils.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
			}
			return &fasthttp.Client{
				TLSConfig: &tls.Config{
					InsecureSkipVerify: !(config.ConfigData.REST.SSL.VerifyServer),
					RootCAs:            serverCA,
				},
			}
		},
	}
}

// https://www.jianshu.com/p/dce19fb167f4
func connectServer(tcpAddr string) (net.Conn, error) {
	log.Printf("Connecting to: %s", tcpAddr)
	// client: for internal connection, use server side certificate file for client
	clientCA := tls.Certificate{}
	if config.ConfigData.REST.SSL.VerifyClient {
		clientCA = utils.LoadCertificatePair(
			config.ConfigData.REST.SSL.SSLCertificateFile,
			config.ConfigData.REST.SSL.SSLCertificateKeyFile)
	}

	// server
	var serverCA *x509.CertPool
	if config.ConfigData.REST.SSL.VerifyServer {
		var err error
		serverCA, err = utils.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
		if err != nil {
			panic(err)
		}
	}

	conf := &tls.Config{
		// verify server
		InsecureSkipVerify: !(config.ConfigData.REST.SSL.VerifyServer),
		RootCAs:            serverCA,

		// verify client
		Certificates: []tls.Certificate{clientCA},
	}

	return tls.Dial("tcp", tcpAddr, conf)
}

func readResponseLoop(conn *safeConn, targetHost string, allowError bool) {
	for {
		// read response from server
		response := new(Response)
		err := response.readResponse(conn.conn)
		if err != nil {
			if !allowError {
				log.Fatalf("Failed read response from host %s: %v", targetHost, err)
			} else {
				log.Printf("Failed read response from host %s: %v", targetHost, err)
				deleteConnection(targetHost)
				return
			}
		}

		// forward to channel and release map
		if t, ok := requestMap.LoadAndDelete(response.Uuid); !ok {
			log.Fatalf("Not found request ID <%s> for Response", response.Uuid)
		} else {
			// notify
			ch, _ := t.(chan *Response)
			ch <- response
		}
	}
}

// Disable Nagle's algorithm on both sides if you're sending small, frequent messages.
func setNoDelay(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		rawConn, err := tcpConn.SyscallConn()
		if err != nil {
			log.Fatalf("Error getting syscall connection: %v", err)
		}
		rawConn.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1)
		})
	}
}

func ListenRest() {
	listenAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestListenPort)
	connectAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestTcpPort)
	// connect to TCP rest server
	targetHost := strings.Replace(connectAddr, "0.0.0.0", "127.0.0.1", 1)
	conn, err := connectServer(targetHost)
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%s> with error: %v", connectAddr, err)
		os.Exit(-1)
	}
	localConnection = &safeConn{conn: conn}
	setNoDelay(localConnection.conn)
	go readResponseLoop(localConnection, targetHost, false)

	// http router
	router := fasthttprouter.New()
	router.HandleOPTIONS = false
	router.HandleMethodNotAllowed = false
	// openapi swagger
	RegOpenapiRestHandler(router)
	// grafana
	grafana.RegGrafanaRestHandler(router)
	// appmesh
	router.GET("/appmesh/*path", utils.Cors(handleAppmeshRest))
	router.PUT("/appmesh/*path", utils.Cors(handleAppmeshRest))
	router.POST("/appmesh/*path", utils.Cors(handleAppmeshRest))
	router.DELETE("/appmesh/*path", utils.Cors(handleAppmeshRest))
	// OPTIONS & HEAD
	router.OPTIONS("/*path", utils.Cors(func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(fasthttp.StatusOK) }))
	router.HEAD("/*path", utils.Cors(func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(fasthttp.StatusOK) }))
	router.GET("/", utils.Cors(handleIndex))
	// router.NotFound = utils.Cors(handleAppmeshRest)

	listenAgentTls(listenAddr, router)
}

func listenAgentTls(restAgentAddr string, router *fasthttprouter.Router) {
	// Load server certificate and key
	serverCA := utils.LoadCertificatePair(
		config.ConfigData.REST.SSL.SSLCertificateFile,
		config.ConfigData.REST.SSL.SSLCertificateKeyFile)
	// client
	clientAuth := tls.NoClientCert
	var clientCA *x509.CertPool
	if config.ConfigData.REST.SSL.VerifyClient {
		clientAuth = tls.RequireAndVerifyClientCert
		var err error
		clientCA, err = utils.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
		if err != nil {
			panic(err)
		}
	}

	conf := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		InsecureSkipVerify:       !(config.ConfigData.REST.SSL.VerifyServer), // whether a client verifies the server's certificate chain
		Certificates:             []tls.Certificate{serverCA},
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			// TLS 1.3 streamlined set of cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},

		// Set clients to authenticate
		ClientAuth: clientAuth,
		ClientCAs:  clientCA,
	}

	// start listen
	server := &fasthttp.Server{
		Handler:            router.Handler,
		MaxRequestBodySize: fasthttp.DefaultMaxRequestBodySize * 1024, // 4G
	}

	listenFunc := func(network string) {
		ln, err := net.Listen(network, restAgentAddr)
		if err != nil {
			log.Printf("Error in Listen %s: %v", network, err)
			return
		}
		log.Printf("<App Mesh Agent> listening %s at %s", network, restAgentAddr)
		if err := server.Serve(tls.NewListener(ln, conf)); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Listen server error: %v", err)
		}
	}

	if addr, err := net.ResolveTCPAddr("tcp", restAgentAddr); err == nil {
		if addr.IP.To4() != nil {
			// IP is an IPv4 address
			listenFunc("tcp4")
		} else if addr.IP.To16() != nil {
			// IP is an IPv6 address
			listenFunc("tcp6")
		} else {
			log.Fatalf("Invalid address %s", restAgentAddr)
		}
	} else {
		log.Fatalf("Failed to resolve address %s: %v", restAgentAddr, err)
	}
}

func handleIndex(ctx *fasthttp.RequestCtx) {
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

	ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
	ctx.Response.SetBodyString(htmlContent)
}

// https://github.com/valyala/fasthttp/blob/master/examples/helloworldserver/helloworldserver.go
func handleAppmeshRest(ctx *fasthttp.RequestCtx) {
	targetConnection := localConnection

	// handle forward request
	// in order to share JWT token in cluster, share JWTSalt & Issuer JWT configuration
	targetHost := string(ctx.Request.Header.Peek(HTTP_HEADER_KEY_X_TARGET_HOST))
	if targetHost != "" {
		ctx.Logger().Printf("Forward request to %s", targetHost)

		parsedURL, _ := utils.ParseURL(targetHost)
		if parsedURL.Port() == strconv.Itoa(config.ConfigData.REST.RestListenPort) {
			// forward with HTTP protocal
			ctx.Request.Header.Del(HTTP_HEADER_KEY_X_TARGET_HOST)
			delegateAppmeshRest(ctx, targetHost)
			return
		} else {
			// forward with TCP protocal
			var err error
			targetConnection, err = getTcpConnection(parsedURL.Host)
			if err != nil {
				ctx.Logger().Printf("Failed to connect TCP to target host %s with error: %v", targetHost, err)
				ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
				return
			}
		}
	}

	// body buffer, read from fasthttp
	request := convertHttpRequest(ctx)
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
	bodyData, err := request.serialize()
	if err != nil {
		log.Fatalf("Failed to serialize request: %v", err)
	}

	// header buffer
	headerData := make([]byte, PROTOBUF_HEADER_LENGTH)
	binary.BigEndian.PutUint32(headerData, uint32(len(bodyData)))
	ctx.Logger().Printf("Requesting: %s with msg length: %d", request.Uuid, len(bodyData))

	// create a chan for accept Response
	ch := make(chan *Response)
	requestMap.Store(request.Uuid, ch)

	var sendErr error
	// send header and body to app mesh server
	{
		targetConnection.mu.Lock()
		if sendErr = sendTcpData(targetConnection.conn, headerData); sendErr == nil {
			sendErr = sendTcpData(targetConnection.conn, bodyData)
		}
		targetConnection.mu.Unlock()
	}

	if sendErr == nil {
		// wait chan to get response
		protocResponse := <-ch
		// reply to client
		applyHttpResponse(ctx, protocResponse)

		// handle file upload after response to client
		if protocResponse.TempUploadFilePath != "" {
			log.Printf("TempUploadFilePath: %s", protocResponse.TempUploadFilePath)
			sendErr = sendUploadFileData(protocResponse.TempUploadFilePath, targetConnection)
		}
	}

	if sendErr != nil {
		ctx.Logger().Printf("Failed to send request to server with error: %v", sendErr)
		defer deleteConnection(targetHost)
	}
}

func getTcpConnection(targetHost string) (*safeConn, error) {
	clientPoolTcp.mu.Lock()
	defer clientPoolTcp.mu.Unlock()

	// Check for existing connection
	if conn, ok := clientPoolTcp.connections[targetHost]; ok {
		return conn, nil
	}

	// No available connection, create a new one
	conn, err := connectServer(targetHost)
	if err != nil {
		return nil, err
	}
	setNoDelay(conn)
	// Store the new connection
	sConn := &safeConn{conn: conn}
	clientPoolTcp.connections[targetHost] = sConn

	// start thread to monitor response
	go readResponseLoop(sConn, targetHost, true)

	return sConn, nil
}

func deleteConnection(targetHost string) {
	clientPoolTcp.mu.Lock()
	defer clientPoolTcp.mu.Unlock()

	if conn, ok := clientPoolTcp.connections[targetHost]; ok {
		conn.conn.Close()                             // Close the connection
		delete(clientPoolTcp.connections, targetHost) // Remove it from the map
		log.Printf("remove connection: %s", targetHost)
	}
}

func delegateAppmeshRest(ctx *fasthttp.RequestCtx, targetHost string) {
	// Create a new request to be sent to the target server
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetBody(ctx.Request.Body())                      // Copy the request body
	ctx.Request.Header.CopyTo(&req.Header)               // Copy the original request headers
	req.Header.SetMethod(string(ctx.Method()))           // Set the request method
	req.Header.SetContentLength(len(ctx.Request.Body())) // Ensure Content-Length is set correctly

	// Set the URL of the target server including the query string
	parsedURL, err := utils.ParseURL(targetHost)
	if err != nil {
		ctx.Logger().Printf("Failed to parse delegate URL: %v", err)
		ctx.Error("Failed to parse delegate URL: "+err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	targetURL := fmt.Sprintf("https://%s%s?%s", parsedURL.Host, ctx.Path(), ctx.QueryArgs().String())
	req.SetRequestURI(targetURL)

	ctx.Logger().Printf("Forwarding request: %s %s", ctx.Method(), targetURL)

	// Create a response object to store the response from the target server
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Perform the request
	delegateClient := clientPoolHttp.Get().(*fasthttp.Client)
	defer clientPoolHttp.Put(delegateClient)
	err = delegateClient.Do(req, resp)
	if err != nil {
		ctx.Logger().Printf("Forward request failed with error: %v", err)
		ctx.Error("Failed to forward request: "+err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	// Copy response
	resp.CopyTo(&ctx.Response)
	ctx.SetStatusCode(resp.StatusCode())
}

func handleRestFile(ctx *fasthttp.RequestCtx, data *Response) bool {
	ctx.Logger().Printf(string(ctx.Request.URI().Path()))

	filePath := string(ctx.Request.Header.Peek("File-Path"))
	if ctx.Request.Header.IsGet() && string(ctx.Request.URI().Path()) == REST_PATH_DOWNLOAD && data.HttpStatus == fasthttp.StatusOK {
		// handle download file
		if data.TempDownloadFilePath != "" {
			// handle file which transfer with delegation
			filePath = data.TempDownloadFilePath
			defer os.Remove(data.TempDownloadFilePath)
		}

		_, fileName := filepath.Split(filePath)
		ctx.Response.Header.Set("Content-Disposition", "attachment; filename="+url.QueryEscape(fileName))
		ctx.Response.Header.Set("Content-Description", "File Transfer")
		ctx.Response.Header.Set("Content-Type", "application/octet-stream")
		ctx.Response.Header.Set("Content-Transfer-Encoding", "binary")
		ctx.Response.Header.Set("Expires", "0")
		ctx.Response.Header.Set("Cache-Control", "must-revalidate")
		ctx.Response.Header.Set("Pragma", "public")
		if utils.IsValidFileName(filePath) {
			ctx.Logger().Printf("ServeFile: %s", fileName)
			fasthttp.ServeFile(ctx, filePath)
			ctx.Logger().Printf("download file %s finished", filePath)
			return true
		} else {
			ctx.Error(string("not invalid file name"), fasthttp.StatusNotAcceptable)
			return false
		}
	} else if ctx.Request.Header.IsPost() && string(ctx.Request.URI().Path()) == REST_PATH_UPLOAD && data.HttpStatus == fasthttp.StatusOK {
		// handle upload file
		if data.TempUploadFilePath != "" {
			// handle file which transfer with delegation
			filePath = data.TempUploadFilePath
		}
		ctx.Logger().Printf("uploading file: %s", filePath)

		if utils.IsValidFileName(filePath) {
			if err := saveFile(ctx, filePath); err != nil {
				ctx.Logger().Printf("saveFile failed with error: %v", err)
				errorJson, _ := json.Marshal(ResponseMessage{Message: err.Error()})
				ctx.Error(string(errorJson), fasthttp.StatusBadRequest)
			} else if data.TempUploadFilePath == "" {
				ctx.Logger().Printf("file saved: %s", filePath)
				// https://www.jianshu.com/p/216cb89c4d81
				mode, err := strconv.Atoi(string(ctx.Request.Header.Peek("File-Mode")))
				if err == nil && mode > 0 && mode < math.MaxInt32 {
					os.Chmod(filePath, os.FileMode(mode))
				}
				fileUserId := string(ctx.Request.Header.Peek("File-User"))
				uid, errUid := strconv.Atoi(fileUserId)
				fileGroupId := string(ctx.Request.Header.Peek("File-Group"))
				gid, errGid := strconv.Atoi(fileGroupId)
				if errUid == nil && errGid == nil {
					os.Chown(filePath, uid, gid)
				}
				return true
			}
		} else {
			ctx.Error(string("not invalid file name"), fasthttp.StatusNotAcceptable)
		}
	}
	return false
}

// https://freshman.tech/file-upload-golang/
func saveFile(ctx *fasthttp.RequestCtx, filePath string) error {
	ctx.Logger().Printf("saveFile: %s", filePath)
	if file, err := ctx.FormFile("file"); err == nil {
		ctx.Logger().Printf("SaveMultipartFile: %s", filePath)
		defer ctx.Request.RemoveMultipartFormFiles()
		return fasthttp.SaveMultipartFile(file, filePath)
	} else {
		// compatibile with none-multipart upload
		ctx.Logger().Printf("SaveFile: %s", filePath)
		return os.WriteFile(filePath, ctx.Request.Body(), 0444)
	}
}
