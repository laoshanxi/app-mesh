package main

// Reference
// https://github.com/open-cluster-management/rbac-query-proxy/blob/release-2.3/cmd/main.go
// https://github.com/valyala/fasthttp/issues/64

import (
	"flag"
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/valyala/fasthttp"
)

var localListenAddr = "127.0.0.1:6058"
var dockerSocket = "/var/run/docker.sock"
var parentProPid = os.Getppid()

// http handler function
func reverseProxyHandler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response
	preCheckRequest(req)

	// TODO: This can move to global var for better enhancement
	proxyClient := &fasthttp.HostClient{
		Addr: dockerSocket,
		Dial: func(addr string) (net.Conn, error) {
			return net.Dial("unix", addr)
		}}

	// do request
	if err := proxyClient.Do(req, resp); err != nil {
		ctx.Logger().Printf("error when proxying the request: %s", err)
		resp.SetStatusCode(fasthttp.StatusForbidden)
		resp.SetBodyString(err.Error())
	}
	defer proxyClient.CloseIdleConnections()

	postCheckResponse(resp)

	log.Printf("Request: %v, %v", req, resp)
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
	// guard-1: prctl
	_, _, errno := syscall.RawSyscall(uintptr(syscall.SYS_PRCTL), uintptr(syscall.PR_SET_PDEATHSIG), uintptr(syscall.SIGKILL), 0)
	if errno != 0 {
		log.Println("Failed to call prctl with error:", errno)
	}

	// guard-2: monitor parent process id
	for {
		if os.Getppid() != parentProPid {
			log.Println("Parent exit")
			os.Exit(0)
		}
		time.Sleep(time.Duration(1) * time.Second)
	}
}

// Entrypoint
func main() {
	log.Println("Docker proxy")

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

	// listen
	if err := fasthttp.ListenAndServe(localListenAddr, reverseProxyHandler); err != nil {
		log.Fatalf("Error in fasthttp server: %s", err)
	}
}
