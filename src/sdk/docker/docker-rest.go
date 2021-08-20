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

var (
	localListenAddr = "127.0.0.1:6058"
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
	resp := &ctx.Response
	preCheckRequest(req)

	// do request
	if err := proxyClient.Do(req, resp); err != nil {
		ctx.Logger().Printf("Error when proxying the request: %s", err)
		proxyClient.CloseIdleConnections()

		resp.SetStatusCode(fasthttp.StatusForbidden)
		resp.SetBodyString(err.Error())
	}

	postCheckResponse(resp)

	log.Printf("Request: \n %v \n %v \n", req, resp)
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

// main
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
