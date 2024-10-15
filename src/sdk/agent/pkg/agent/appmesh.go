package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/buaazp/fasthttprouter"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/grafana"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/valyala/fasthttp"
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
	httpRequestMap sync.Map // request map cache for asyncrized response

	localConnection   *Connection // tcp connection to the local server
	remoteConnections = &tcpConnections{connections: make(map[string]*Connection)}
	delegatePool      sync.Pool
)

func init() {
	delegatePool = sync.Pool{
		New: func() interface{} {
			var serverCA *x509.CertPool
			if config.ConfigData.REST.SSL.VerifyServerDelegate {
				serverCA, _ = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
			}
			return &fasthttp.Client{
				TLSConfig: &tls.Config{
					InsecureSkipVerify: !(config.ConfigData.REST.SSL.VerifyServerDelegate),
					RootCAs:            serverCA,
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
				log.Fatalf("Failed read response from host %s: %v", targetHost, err)
			} else {
				log.Printf("Failed read response from host %s: %v", targetHost, err)
				deleteConnection(targetHost)
				return
			}
		}

		// forward to channel and release map
		if t, ok := httpRequestMap.LoadAndDelete(response.Uuid); !ok {
			log.Fatalf("Not found request ID <%s> for Response", response.Uuid)
		} else {
			// notify
			ch, _ := t.(chan *Response)
			ch <- response
		}
	}
}

func ListenRest() {
	listenAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestListenPort)
	connectAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestTcpPort)
	// connect to TCP rest server
	targetHost := strings.Replace(connectAddr, "0.0.0.0", "127.0.0.1", 1)

	var err error
	localConnection, err = NewConnection(targetHost, config.ConfigData.REST.SSL.VerifyServer, false)
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%s> with error: %v", connectAddr, err)
		os.Exit(-1)
	}
	log.Printf("Establish REST connection to TCP server <%s>", connectAddr)

	// http router
	router := fasthttprouter.New()
	router.HandleOPTIONS = false
	router.HandleMethodNotAllowed = false
	// openapi swagger
	RegOpenapiRestHandler(router)
	// grafana
	grafana.RegGrafanaRestHandler(router)
	// appmesh
	router.GET("/appmesh/*path", utils.Cors(handleAppmeshResquest))
	router.PUT("/appmesh/*path", utils.Cors(handleAppmeshResquest))
	router.POST("/appmesh/*path", utils.Cors(handleAppmeshResquest))
	router.DELETE("/appmesh/*path", utils.Cors(handleAppmeshResquest))
	// OPTIONS & HEAD
	router.OPTIONS("/*path", utils.Cors(func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(fasthttp.StatusOK) }))
	router.HEAD("/*path", utils.Cors(func(ctx *fasthttp.RequestCtx) { ctx.SetStatusCode(fasthttp.StatusOK) }))
	router.GET("/", utils.Cors(handleIndex))
	// router.NotFound = utils.Cors(handleAppmeshRest)

	startHttpsServer(listenAddr, router)
}

func startHttpsServer(restAgentAddr string, router *fasthttprouter.Router) {
	// Load server certificate and key
	serverCA, err := appmesh.LoadCertificatePair(
		config.ConfigData.REST.SSL.SSLCertificateFile,
		config.ConfigData.REST.SSL.SSLCertificateKeyFile)
	if err != nil {
		log.Fatalln(err)
	}
	// client
	clientAuth := tls.NoClientCert
	var clientCA *x509.CertPool
	if config.ConfigData.REST.SSL.VerifyClient {
		clientAuth = tls.RequireAndVerifyClientCert
		var err error
		clientCA, err = appmesh.LoadCA(config.ConfigData.REST.SSL.SSLCaPath)
		if err != nil {
			panic(err)
		}
	}

	conf := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		InsecureSkipVerify:       !(config.ConfigData.REST.SSL.VerifyServer), // whether a client verifies the server's certificate chain
		Certificates:             []tls.Certificate{serverCA},
		CurvePreferences:         []tls.CurveID{tls.CurveP256, tls.CurveP384}, // Remove P521 for performance
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			// TLS 1.2
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// TLS 1.3 streamlined set of cipher suites
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},

		// Set clients to authenticate
		ClientAuth: clientAuth,
		ClientCAs:  clientCA,

		// Optimize performance
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(128),

		// Enable HTTP/2
		// NextProtos: []string{"h2", "http/1.1"},
	}

	// start listen
	server := &fasthttp.Server{
		Handler:            router.Handler,
		MaxRequestBodySize: fasthttp.DefaultMaxRequestBodySize * 1024, // 4G
		ReadBufferSize:     16 * 1024,                                 // Increase if necessary
		WriteBufferSize:    16 * 1024,                                 // Increase if necessary
		// MaxConnsPerIP:   100,                                       // Example limit on connections per IP
		// Concurrency:     256 * 1024,                                // Adjust based on server resources
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
func handleAppmeshResquest(ctx *fasthttp.RequestCtx) {
	var targetConnection = localConnection

	// handle forward request
	// in order to share JWT token in cluster, share JWTSalt & Issuer JWT configuration
	forwardingHost := string(ctx.Request.Header.Peek(HTTP_HEADER_KEY_X_TARGET_HOST))
	if forwardingHost != "" {
		ctx.Logger().Printf("Forward request to %s", forwardingHost)

		parsedURL, _ := appmesh.ParseURL(forwardingHost)
		if parsedURL.Port() == strconv.Itoa(config.ConfigData.REST.RestListenPort) {
			// forward with HTTP protocal
			ctx.Request.Header.Del(HTTP_HEADER_KEY_X_TARGET_HOST)
			delegateAppmeshRest(ctx, forwardingHost)
			return
		} else {
			// forward with TCP protocal
			var err error
			targetConnection, err = NewConnection(parsedURL.Host, config.ConfigData.REST.SSL.VerifyServerDelegate, true)
			if err != nil {
				ctx.Logger().Printf("Failed to connect TCP to target host %s with error: %v", forwardingHost, err)
				ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
				return
			}
		}
	}

	// body buffer, read from fasthttp
	request := NewRequest(ctx)
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
		resp.applyResponse(ctx)

		// handle file upload after response to client
		if resp.TempUploadFilePath != "" {
			sendErr = targetConnection.sendUploadFileData(resp.TempUploadFilePath)
		}
	}

	if sendErr != nil {
		ctx.Logger().Printf("Failed to send request to server with error: %v", sendErr)
		defer deleteConnection(forwardingHost)
	}
}

func delegateAppmeshRest(ctx *fasthttp.RequestCtx, forwardingHost string) {
	// Create a new request to be sent to the target server
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	req.SetBody(ctx.Request.Body())                      // Copy the request body
	ctx.Request.Header.CopyTo(&req.Header)               // Copy the original request headers
	req.Header.SetMethod(string(ctx.Method()))           // Set the request method
	req.Header.SetContentLength(len(ctx.Request.Body())) // Ensure Content-Length is set correctly

	// Set the URL of the target server including the query string
	parsedURL, err := appmesh.ParseURL(forwardingHost)
	if err != nil {
		ctx.Logger().Printf("Failed to parse forward URL: %v", err)
		ctx.Error("Failed to parse forward URL: "+err.Error(), fasthttp.StatusInternalServerError)
		return
	}
	targetURL := fmt.Sprintf("https://%s%s?%s", parsedURL.Host, ctx.Path(), ctx.QueryArgs().String())
	req.SetRequestURI(targetURL)

	ctx.Logger().Printf("Forwarding request: %s %s", ctx.Method(), targetURL)

	// Create a response object to store the response from the target server
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Perform the request
	delegateClient := delegatePool.Get().(*fasthttp.Client)
	defer delegatePool.Put(delegateClient)
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
			if err := saveHttpFile(ctx, filePath); err != nil {
				ctx.Logger().Printf("saveFile failed with error: %v", err)
				errorJson, _ := json.Marshal(ResponseMessage{Message: err.Error()})
				ctx.Error(string(errorJson), fasthttp.StatusBadRequest)
			} else if data.TempUploadFilePath == "" {
				ctx.Logger().Printf("file saved: %s", filePath)

				httpHeaders := make(http.Header)
				ctx.Request.Header.VisitAll(func(key, value []byte) {
					httpHeaders.Add(string(key), string(value))
				})
				appmesh.SetFileAttributes(filePath, httpHeaders)

				return true
			}
		} else {
			ctx.Error(string("not invalid file name"), fasthttp.StatusNotAcceptable)
		}
	}
	return false
}

// https://freshman.tech/file-upload-golang/
func saveHttpFile(ctx *fasthttp.RequestCtx, filePath string) error {
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
