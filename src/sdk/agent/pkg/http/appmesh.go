package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
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
	REST_PATH_FILE              = "/appmesh/file/"
	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	HTTP_USER_AGENT             = "appmeshsdk"
)

var (
	tcpConnect  net.Conn   // tcp connection to the server
	socketMutex sync.Mutex // tcp connection lock
	requestMap  sync.Map   // request map cache for asyncrized response
)

// https://www.jianshu.com/p/dce19fb167f4
func connectServer(tcpAddr string) (net.Conn, error) {
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

func readMsgLoop() {
	for {
		// read response from server
		response := new(Response)
		if err := response.readResponse(tcpConnect); err != nil {
			log.Fatalf("Failed read response: %v", err)
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
	conn, err := connectServer(strings.Replace(connectAddr, "0.0.0.0", "127.0.0.1", 1))
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%s> with error: %v", connectAddr, err)
		os.Exit(-1)
	}
	tcpConnect = conn
	setNoDelay(tcpConnect)
	go readMsgLoop()

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
	// handle forward request
	targetHost := string(ctx.Request.Header.Peek("X-Target-Host"))
	if len(targetHost) > 0 {
		// in order to share JWT token in cluster, share JWTSalt & Issuer JWT configuration
		ctx.Logger().Printf("Forward request to %s", targetHost)
		ctx.Request.Header.Del("X-Target-Host")
		delegateAppmeshRest(ctx, targetHost)
		return
	}

	// body buffer, read from fasthttp
	request := convertHttpRequestData(&ctx.Request)
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
		socketMutex.Lock()
		if sendErr = blockSend(tcpConnect, headerData); sendErr == nil {
			sendErr = blockSend(tcpConnect, bodyData)
		}
		socketMutex.Unlock()
	}
	if sendErr == nil {
		// wait chan to get response
		protocResponse := <-ch
		// reply to client
		convertResponseToHttp(ctx, protocResponse)
	} else {
		ctx.Logger().Printf("Failed to send request to server with error:: %v", sendErr)
		log.Fatal(sendErr)
	}
}

func delegateAppmeshRest(ctx *fasthttp.RequestCtx, targetHost string) {
	// Create a new request to be sent to the target server
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	// Copy the original request
	ctx.Request.CopyTo(req)

	// Set the URL of the target server including the query string
	req.SetRequestURI("https://" + targetHost + string(ctx.Path()) + "?" + ctx.QueryArgs().String())

	// Create a response object to store the response from the target server
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Perform the request
	insecureClient := &fasthttp.Client{TLSConfig: &tls.Config{InsecureSkipVerify: true}}
	err := insecureClient.Do(req, resp)
	if err != nil {
		ctx.Error("Failed to forward request: "+err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	// Copy response
	resp.CopyTo(&ctx.Response)
	ctx.SetStatusCode(resp.StatusCode())
}

func handleRestFile(ctx *fasthttp.RequestCtx, data *Response) bool {
	ctx.Logger().Printf(string(ctx.Request.URI().Path()))
	if ctx.Request.Header.IsGet() && string(ctx.Request.URI().Path()) == REST_PATH_DOWNLOAD && data.HttpStatus == fasthttp.StatusOK {
		// handle download file
		filePath := string(ctx.Request.Header.Peek("File-Path"))
		ctx.Logger().Printf("download file: %s", filePath)

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
			return true
		} else {
			ctx.Error(string("not invalid file name"), fasthttp.StatusNotAcceptable)
			return false
		}
	} else if ctx.Request.Header.IsPost() && string(ctx.Request.URI().Path()) == REST_PATH_UPLOAD && data.HttpStatus == fasthttp.StatusOK {
		// handle upload file
		filePath := string(ctx.Request.Header.Peek("File-Path"))
		ctx.Logger().Printf("uploading file: %s", filePath)
		if utils.IsValidFileName(filePath) {
			if err := saveFile(ctx, filePath); err != nil {
				errorJson, _ := json.Marshal(ResponseMessage{Message: err.Error()})
				ctx.Error(string(errorJson), fasthttp.StatusBadRequest)
			} else {
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
