package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"html"
	"log"
	"math"
	"net"
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
	"github.com/rs/xid"
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

// https://github.com/valyala/fasthttp/blob/master/examples/helloworldserver/helloworldserver.go
func handleAppmeshRest(ctx *fasthttp.RequestCtx) {
	// body buffer, read from fasthttp
	request := readRequestData(&ctx.Request)
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
		applyResponse(ctx, protocResponse)
	} else {
		ctx.Logger().Printf("Failed to send request to server with error:: %v", sendErr)
		log.Fatal(sendErr)
	}
}

func readRequestData(req *fasthttp.Request) *Request {
	// do not proxy "Connection" header.
	req.Header.Del("Connection")

	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = string(req.Header.Method())
	data.RequestUri = string(req.URI().Path())
	data.ClientAddress = string(req.Host())
	data.Headers = make(map[string]string)
	req.Header.VisitAll(func(key, value []byte) {
		data.Headers[string(key)] = string(value)
	})
	data.Headers[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT
	data.Querys = make(map[string]string)
	req.URI().QueryArgs().VisitAll(func(key, value []byte) {
		data.Querys[string(key)] = string(value)
	})

	// do not read body for file upload
	if !(req.Header.IsPost() && string(req.URI().Path()) == REST_PATH_UPLOAD) {
		data.Body = html.UnescapeString(string(req.Body()))
	}
	return data
}

func applyResponse(ctx *fasthttp.RequestCtx, data *Response) {
	// headers
	for k, v := range data.Headers {
		ctx.Response.Header.Set(k, v)
	}
	// cross site header
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "*")
	// user agent
	ctx.Response.Header.Set(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT)
	// status code
	ctx.Response.SetStatusCode(int(data.HttpStatus))
	// body
	if strings.HasPrefix(string(ctx.Request.URI().Path()), REST_PATH_FILE) && handleRestFile(ctx, data) {
		ctx.Logger().Printf("File REST call Finished  %s", data.Uuid)
	} else {
		ctx.Response.SetBodyRaw([]byte(data.Body))
		ctx.SetContentType(data.BodyMsgType)
		ctx.Logger().Printf("REST call Finished  %s", data.Uuid)
	}
}

func handleRestFile(ctx *fasthttp.RequestCtx, data *Response) bool {
	ctx.Logger().Printf(string(ctx.Request.URI().Path()))
	if ctx.Request.Header.IsGet() && string(ctx.Request.URI().Path()) == REST_PATH_DOWNLOAD && data.HttpStatus == fasthttp.StatusOK {
		// handle download file
		ctx.Logger().Printf("download file")
		filePath := string(ctx.Request.Header.Peek("File-Path"))
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

func listenAgentTls(restAgentAddr string, router *fasthttprouter.Router) error {
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
	ln, err := net.Listen("tcp4", restAgentAddr)
	if err != nil {
		log.Fatalf("Error in Listen tcp4: %v", err)
		panic(err)
	}
	s := &fasthttp.Server{
		Handler:            router.Handler,
		MaxRequestBodySize: fasthttp.DefaultMaxRequestBodySize * 1024, // 4G
	}
	log.Println("<App Mesh Agent> listening at: ", restAgentAddr)
	return s.Serve(tls.NewListener(ln, conf))
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
	go readMsgLoop()

	// setup REST listener
	router := fasthttprouter.New()
	router.NotFound = handleAppmeshRest // set all default router to restProxyHandler
	grafana.RegGrafanaRestHandler(router)
	err = listenAgentTls(listenAddr, router)
	if err != nil {
		log.Fatalf("Error in fasthttp Serve: %v", err)
		os.Exit(-1)
	}
}
