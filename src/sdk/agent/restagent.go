package main

import (
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/buaazp/fasthttprouter"
	grafana "github.com/laoshanxi/app-mesh/src/sdk/agent/grafana"
	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
	"google.golang.org/protobuf/proto"
)

const PROTOBUF_HEADER_LENGTH = 4
const REST_PATH_UPLOAD = "/appmesh/file/upload"
const REST_PATH_DOWNLOAD = "/appmesh/file/download"
const REST_PATH_FILE = "/appmesh/file/"

var tcpConnect net.Conn    // tcp connection
var socketMutex sync.Mutex // tcp connection lock
var requestMap sync.Map    // request cache for asyncrized response

func connectServer(restTcpPort int) (net.Conn, error) {
	return net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(restTcpPort))
}

func readProtobufLoop() {
	for {
		// read header 4 bytes (int)
		buf := make([]byte, PROTOBUF_HEADER_LENGTH)
		_, err := tcpConnect.Read(buf)
		if err != nil {
			log.Fatalf("Failed read header from TCP Server: %v", err)
		}
		bodyLength := binary.BigEndian.Uint32(buf)
		// read body buffer
		buf = make([]byte, bodyLength)
		_, err = tcpConnect.Read(buf)
		if err != nil {
			log.Fatalf("Failed read body from TCP Server: %v", err)
		}
		protocResponse := new(Response)
		err = proto.Unmarshal(buf, protocResponse)
		if err != nil {
			log.Fatalf("Failed de-serialize protoc respon: %v", err)
		}

		// forward to channel and release map
		if t, ok := requestMap.LoadAndDelete(protocResponse.GetUuid()); !ok {
			log.Fatalf("Failed to found request ID <%s> to response", protocResponse.GetUuid())
		} else {
			// notify
			ch, _ := t.(chan *Response)
			ch <- protocResponse
		}

		time.Sleep(time.Duration(10) * time.Millisecond)
	}
}

// http handler function
func restProxyHandler(ctx *fasthttp.RequestCtx) {
	// https://github.com/valyala/fasthttp/blob/master/examples/helloworldserver/helloworldserver.go

	req := &ctx.Request

	// prepare header and body
	protocRequest := serializeRequest(req)
	bodyData, _ := proto.Marshal(protocRequest)
	headerData := make([]byte, PROTOBUF_HEADER_LENGTH)
	binary.BigEndian.PutUint32(headerData, uint32(len(bodyData)))
	ctx.Logger().Printf("Requesting: %s", protocRequest.GetUuid())
	// ctx.Logger().Printf("---Request Protoc:---\n%v\n", protocRequest)

	// create a chan and store in map
	ch := make(chan *Response)
	requestMap.Store(protocRequest.GetUuid(), ch)

	var sendCount int
	var sendErr error
	// send header and body
	{
		socketMutex.Lock()
		defer socketMutex.Unlock()
		sendCount, sendErr = tcpConnect.Write(headerData)
		ctx.Logger().Printf("sent header size %d = %d to TCP, error: %v", uint32(len(headerData)), sendCount, sendErr)
		sendCount, sendErr = tcpConnect.Write(bodyData)
		ctx.Logger().Printf("sent body size %d = %d to TCP, error: %v", uint32(len(bodyData)), sendCount, sendErr)
	}
	if sendErr == nil {
		// wait chan to get response
		protocResponse := <-ch

		// reply to client
		applyResponse(ctx, protocResponse)
		// ctx.Logger().Printf("---Response Protoc:---\n%v\n", protocResponse)
	} else {
		ctx.Logger().Printf("Failed to send request to server with error:: %v", sendErr)
		os.Exit(-1)
	}
}

func serializeRequest(req *fasthttp.Request) *Request {
	// do not proxy "Connection" header.
	req.Header.Del("Connection")

	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = string(req.Header.Method())
	data.RequestUri = string(req.URI().Path())
	data.ClientAddress = string(req.Host())
	data.Headers = map[string]string{}
	req.Header.VisitAll(func(key, value []byte) {
		data.Headers[string(key)] = string(value)
	})
	data.Querys = string(req.URI().QueryArgs().QueryString())
	// do not read body for file upload
	if !(req.Header.IsPost() && string(req.URI().Path()) == REST_PATH_UPLOAD) {
		data.HttpBody = string(req.Body())
	}
	return data
}

func applyResponse(ctx *fasthttp.RequestCtx, data *Response) {
	// headers
	for k, v := range data.GetHeaders() {
		ctx.Response.Header.Set(k, v)
	}
	// cross site header
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "*")
	// status code
	ctx.Response.SetStatusCode(int(data.GetHttpStatus()))
	// body
	if strings.HasPrefix(string(ctx.Request.URI().Path()), REST_PATH_FILE) && serveFile(ctx, data) {
		ctx.Logger().Printf("File send finished")
	} else {
		ctx.Response.SetBodyRaw([]byte(data.GetHttpBody()))
		ctx.SetContentType(data.GetHttpBodyMsgType())
		ctx.Logger().Printf("REST call Finished")
	}
}

func serveFile(ctx *fasthttp.RequestCtx, data *Response) bool {
	ctx.Logger().Printf(string(ctx.Request.URI().Path()))
	if ctx.Request.Header.IsGet() && string(ctx.Request.URI().Path()) == REST_PATH_DOWNLOAD && data.GetHttpStatus() == fasthttp.StatusOK {
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
		ctx.Logger().Printf("ServeFile: %s", fileName)
		fasthttp.ServeFile(ctx, filePath)
		return true
	} else if ctx.Request.Header.IsPost() && string(ctx.Request.URI().Path()) == REST_PATH_UPLOAD && data.GetHttpStatus() == fasthttp.StatusOK {
		// handle upload file
		ctx.Logger().Printf("upload file")
		filePath := string(ctx.Request.Header.Peek("File-Path"))
		if err := saveFile(ctx, filePath); err != nil {
			ctx.Error(err.Error(), fasthttp.StatusBadRequest)
		} else {
			// https://www.jianshu.com/p/216cb89c4d81
			mode, err := strconv.Atoi(string(ctx.Request.Header.Peek("File-Mode")))
			if err == nil {
				os.Chmod(filePath, os.FileMode(mode))
			}
			fileUserId := string(ctx.Request.Header.Peek("File-User"))
			uid, errUid := strconv.Atoi(fileUserId)
			fileGroupId := string(ctx.Request.Header.Peek("File-Group"))
			gid, errGid := strconv.Atoi(fileGroupId)
			if errUid == nil && errGid == nil {
				os.Chown(filePath, uid, gid)
			}
		}
		return true
	}
	return false
}

func saveFile(ctx *fasthttp.RequestCtx, filePath string) error {
	// https://freshman.tech/file-upload-golang/
	if file, err := ctx.FormFile("file"); err == nil {
		return fasthttp.SaveMultipartFile(file, filePath)
	} else {
		// compatibile with none-multipart upload
		return os.WriteFile(filePath, ctx.Request.Body(), 0444)
	}
}

func listenAgent(restAgentAddr string, router *fasthttprouter.Router) error {
	s := &fasthttp.Server{
		Handler:            router.Handler,
		MaxRequestBodySize: fasthttp.DefaultMaxRequestBodySize * 1024, // 4G
	}
	return s.ListenAndServe(restAgentAddr)
}

func listenAgentTls(restAgentAddr string, router *fasthttprouter.Router) error {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		Certificates:             []tls.Certificate{loadServerCertificates(filepath.Join(getAppMeshHomeDir(), "ssl/server.pem"), filepath.Join(getAppMeshHomeDir(), "ssl/server-key.pem"))},
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
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
	return s.Serve(tls.NewListener(ln, cfg))
}

func listenRest(restAgentAddr string, restTcpPort int) {
	addr, err := url.Parse(restAgentAddr)
	if err != nil {
		panic(err)
	}
	addrForListen := addr.Hostname() + ":" + addr.Port()

	// connect to TCP rest server
	conn, err := connectServer(restTcpPort)
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%d> with error: %v", restTcpPort, err)
		os.Exit(-1)
	}
	tcpConnect = conn
	go readProtobufLoop()

	// setup REST listener
	router := fasthttprouter.New()
	router.NotFound = restProxyHandler // set all default router to restProxyHandler
	grafana.RegGrafanaRestHandler(router, restAgentAddr)
	if addr.Scheme == "https" {
		err = listenAgentTls(addrForListen, router)
	} else {
		err = listenAgent(addrForListen, router)
	}
	if err != nil {
		log.Fatalf("Error in fasthttp Serve: %v", err)
		os.Exit(-1)
	}
}
