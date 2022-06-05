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

	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
	"google.golang.org/protobuf/proto"
)

const PROTOBUF_HEADER_LENGTH = 4

var tcpConnect net.Conn    // tcp connection
var socketMutex sync.Mutex // tcp connection lock
var requestMap sync.Map    // request cache for asyncrized response

func connectServer(restTcpPort int) (net.Conn, error) {
	return net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(restTcpPort))
}

func readSocketLoop() {
	for {
		// read header 4 bytes (int)
		buf := make([]byte, PROTOBUF_HEADER_LENGTH)
		_, _ = tcpConnect.Read(buf)
		bodyLength := binary.LittleEndian.Uint32(buf)
		// read body buffer
		buf = make([]byte, bodyLength)
		_, _ = tcpConnect.Read(buf)
		protocResponse := new(Response)
		_ = proto.Unmarshal(buf, protocResponse)

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
func restAgentProxyHandler(ctx *fasthttp.RequestCtx) {
	ctx.Logger().Printf("Start")
	// https://github.com/valyala/fasthttp/blob/master/examples/helloworldserver/helloworldserver.go
	req := &ctx.Request
	ctx.Logger().Printf("Request method is %q\n", ctx.Method())
	ctx.Logger().Printf("RequestURI is %q\n", ctx.RequestURI())
	ctx.Logger().Printf("Requested path is %q\n", ctx.Path())
	ctx.Logger().Printf("Client ip is %q\n", ctx.RemoteIP())

	// prepare header and body
	protocRequest := serializeRequest(req)
	bodyData, _ := proto.Marshal(protocRequest)
	headerData := make([]byte, PROTOBUF_HEADER_LENGTH)
	binary.LittleEndian.PutUint32(headerData, uint32(len(bodyData)))
	// ctx.Logger().Printf("---Request Protoc:---\n%v\n", protocRequest)

	var sendCount int
	var sendErr error
	// send header and body
	{
		socketMutex.Lock()
		defer socketMutex.Unlock()
		sendCount, sendErr = tcpConnect.Write(headerData)
		ctx.Logger().Printf("write header size %d = %d, error %v", uint32(len(headerData)), sendCount, sendErr)
		sendCount, sendErr = tcpConnect.Write(bodyData)
		ctx.Logger().Printf("write body size %d = %d, error %v", uint32(len(bodyData)), sendCount, sendErr)
	}
	if sendErr == nil {
		// create a chan and store in map
		ch := make(chan *Response)
		requestMap.Store(protocRequest.GetUuid(), ch)

		// wait chan to get response
		protocResponse := <-ch

		// reply to client
		applyResponse(ctx, protocResponse)

		// ctx.Logger().Printf("---Response Protoc:---\n%v\n", protocResponse)
	} else {
		ctx.Logger().Printf("Failed to send request to TCP Server: %s", sendErr)
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
	if !(string(req.URI().Path()) == "/appmesh/file/upload" && string(req.Header.Method()) == "POST") {
		// do not read body for file upload
		data.HttpBody = string(req.Body())
	}
	return data
}

func applyResponse(ctx *fasthttp.RequestCtx, data *Response) {
	// headers
	for k, v := range data.GetHeaders() {
		ctx.Response.Header.Add(k, v)
	}
	ctx.Response.Header.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
	ctx.Response.Header.Add("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Add("Access-Control-Allow-Headers", "*")
	// status code
	ctx.Response.SetStatusCode(int(data.GetHttpStatus()))
	// body
	if strings.HasPrefix(string(ctx.Request.URI().Path()), "/appmesh/file/") && serveFile(ctx, data) {
		ctx.Logger().Printf("File send finished")
	} else {
		ctx.Response.SetBodyRaw([]byte(data.GetHttpBody()))
		ctx.SetContentType(data.GetHttpBodyMsgType())
		ctx.Logger().Printf("REST call Finished")
	}
}

func serveFile(ctx *fasthttp.RequestCtx, data *Response) bool {
	ctx.Logger().Printf(string(ctx.Request.URI().Path()))
	if ctx.Request.Header.IsGet() && string(ctx.Request.URI().Path()) == "/appmesh/file/download" && data.GetHttpStatus() == fasthttp.StatusOK {
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
	} else if ctx.Request.Header.IsPost() && string(ctx.Request.URI().Path()) == "/appmesh/file/upload" && data.GetHttpStatus() == fasthttp.StatusOK {
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

func listenAgent(restAgentAddr string) error {
	return fasthttp.ListenAndServe(restAgentAddr, restAgentProxyHandler)
}

func listenAgentTls(restAgentAddr string) error {
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
		log.Fatalf("Error in Listen tcp4: %s", err)
		panic(err)
	}
	lnTls := tls.NewListener(ln, cfg)
	return fasthttp.Serve(lnTls, restAgentProxyHandler)
}

func listenRest(restAgentAddr string, restTcpPort int) {
	addr, err := url.Parse(restAgentAddr)
	if err != nil {
		panic(err)
	}
	enableTLS := (addr.Scheme == "https")
	restAgentAddr = addr.Hostname() + ":" + addr.Port()

	// connect to TCP rest server
	conn, err := connectServer(restTcpPort)
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%s> with error: %s", strconv.Itoa(restTcpPort), err)
		os.Exit(-1)
	}
	tcpConnect = conn
	go readSocketLoop()

	// setup REST listener
	if enableTLS {
		err = listenAgentTls(restAgentAddr)
	} else {
		err = listenAgent(restAgentAddr)
	}
	if err != nil {
		log.Fatalf("Error in fasthttp Serve: %s", err)
		os.Exit(-1)
	}
}
