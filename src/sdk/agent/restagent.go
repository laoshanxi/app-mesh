package main

import (
	"crypto/tls"
	"encoding/binary"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
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

func connectServer() (net.Conn, error) {
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
			log.Fatalf("Failed to found request ID to response: %s", protocResponse.GetUuid())
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
		ch := make(chan *Response)
		requestMap.Store(protocRequest.GetUuid(), ch)
		protocResponse := <-ch
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
	data.RequestUri = string(req.Header.RequestURI())
	data.ClientAddress = string(req.Host())
	data.HttpBody = string(req.Body())
	data.Headers = map[string]string{}
	req.Header.VisitAll(func(key, value []byte) {
		data.Headers[string(key)] = string(value)
	})
	data.Querys = string(req.URI().QueryArgs().QueryString())
	return data
}

func applyResponse(ctx *fasthttp.RequestCtx, data *Response) {
	for k, v := range data.GetHeaders() {
		ctx.Response.Header.Add(k, v)
	}
	ctx.Response.SetStatusCode(int(data.GetHttpStatus()))
	ctx.Response.SetBodyRaw([]byte(data.GetHttpBody()))
	ctx.SetContentType(data.GetHttpBodyMsgType())
}

func listenAgent() error {
	return fasthttp.ListenAndServe(restAgentAddr, restAgentProxyHandler)
}

func listenAgentTls() error {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		Certificates:             []tls.Certificate{loadServerCertificates("/opt/appmesh/ssl/server.pem", "/opt/appmesh/ssl/server-key.pem")},
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

func listenRest() {
	addr, err := url.Parse(restAgentAddr)
	if err != nil {
		panic(err)
	}
	enableTLS := (addr.Scheme == "https")
	restAgentAddr = addr.Hostname() + ":" + addr.Port()

	// connect to TCP rest server
	conn, err := connectServer()
	if err != nil {
		log.Fatalf("Failed to connected to TCP server <%s> with error: %s", strconv.Itoa(restTcpPort), err)
		os.Exit(-1)
	}
	tcpConnect = conn
	go readSocketLoop()

	// setup REST listener
	if enableTLS {
		err = listenAgentTls()
	} else {
		err = listenAgent()
	}
	if err != nil {
		log.Fatalf("Error in fasthttp Serve: %s", err)
		os.Exit(-1)
	}
}
