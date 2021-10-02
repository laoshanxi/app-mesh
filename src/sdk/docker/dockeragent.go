package main

// Reference
// https://github.com/open-cluster-management/rbac-query-proxy/blob/release-2.3/cmd/main.go
// https://github.com/valyala/fasthttp/issues/64
// Test:
// curl --verbose --cert /opt/appmesh/ssl/client.pem --key /opt/appmesh/ssl/client-key.pem --cacert /opt/appmesh/ssl/ca.pem  https://localhost:6058/containers/json | python -m json.tool

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/valyala/fasthttp"
)

var (
	localListenAddr = "https://127.0.0.1:6058"
	dockerSocket    = "/var/run/docker.sock"
	parentProPid    = os.Getppid()
	proxyClient     = &fasthttp.HostClient{
		Addr: dockerSocket,
		Dial: func(addr string) (net.Conn, error) {
			return net.Dial("unix", addr)
		}}
)

// http handler function
func reverseProxyHandler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	log.Printf("\n---Request:---\n%v\n", req)
	preCheckRequest(req)

	resp := &ctx.Response
	// do request
	if err := proxyClient.Do(req, resp); err != nil {
		ctx.Logger().Printf("Error when proxying the request: %s", err)
		proxyClient.CloseIdleConnections()

		resp.SetStatusCode(fasthttp.StatusForbidden)
		resp.SetBodyString(err.Error())
	}

	postCheckResponse(resp)

	log.Printf("\n---Response:---\n%v\n", resp)
}

func preCheckRequest(req *fasthttp.Request) {
	// do not proxy "Connection" header.
	req.Header.Del("Connection")
	// strip other unneeded headers.
	// alter other request params before sending them to upstream host
}

func postCheckResponse(resp *fasthttp.Response) {
	// do not proxy "Connection" header
	resp.Header.Del("Connection")
	// strip other unneeded headers
	// alter other response data if needed
}

func monitorParentExit() {
	// 1. Force process exit when parent was exited
	_, _, errno := syscall.RawSyscall(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0)
	if errno != 0 {
		log.Println("Failed to call prctl with error:", errno)
	}

	// 2. Period check parent exit and exit itself
	oneSecond := time.Duration(1) * time.Second
	for {
		if os.Getppid() != parentProPid {
			log.Println("Parent exit")
			os.Exit(0)
		}
		time.Sleep(oneSecond)
	}
}

func listenHttp() {
	if err := fasthttp.ListenAndServe(localListenAddr, reverseProxyHandler); err != nil {
		log.Fatalf("Error in fasthttp server: %s", err)
	}
}

func loadClientCA(caFile string) *x509.CertPool {
	pool := x509.NewCertPool()

	if ca, e := ioutil.ReadFile(caFile); e != nil {
		log.Fatal("ReadFile: ", e)
	} else {
		pool.AppendCertsFromPEM(ca)
	}
	return pool
}

func loadServerCertificates(pem string, key string) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(pem, key)
	if err != nil {
		log.Fatalf("Error in LoadX509KeyPair: %s", err)
		panic(err)
	}
	return cert
}

func listenHttps() {
	// https://github.com/valyala/fasthttp/blob/master/examples/letsencrypt/letsencryptserver.go
	// https://github.com/valyala/fasthttp/issues/804
	// https://studygolang.com/articles/9329
	// prepare TLS
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		Certificates:             []tls.Certificate{loadServerCertificates("/opt/appmesh/ssl/server.pem", "/opt/appmesh/ssl/server-key.pem")},
		ClientAuth:               tls.RequireAndVerifyClientCert,
		ClientCAs:                loadClientCA("/opt/appmesh/ssl/client.pem"),
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
	ln, err := net.Listen("tcp4", localListenAddr)
	if err != nil {
		log.Fatalf("Error in Listen tcp4: %s", err)
		panic(err)
	}
	lnTls := tls.NewListener(ln, cfg)
	if err := fasthttp.Serve(lnTls, reverseProxyHandler); err != nil {
		log.Fatalf("Error in fasthttp Serve: %s", err)
		panic(err)
	}
}

// main
func main() {
	log.Println("Docker Agent enter")

	// parse arguments
	addr := flag.String("url", localListenAddr, "The host URL used to listen")
	socket := flag.String("socket", dockerSocket, "Unix domain socket file path")
	flag.Parse()

	// exit when parent not exist
	go monitorParentExit()

	// read arguments
	dockerSocket = *socket
	localListenAddr = *addr
	log.Println("Docker socket:", dockerSocket)
	log.Println("Listening at:", localListenAddr)
	enableTLS := strings.HasPrefix(localListenAddr, "https://")

	// clean schema prefix for Listen
	localListenAddr = strings.Replace(localListenAddr, "https://", "", 1)
	localListenAddr = strings.Replace(localListenAddr, "http://", "", 1)

	// start listen
	if enableTLS {
		listenHttps()
	} else {
		listenHttp()
	}

	log.Fatalln("Process exiting")
}
