package http

// Reference
// https://github.com/open-cluster-management/rbac-query-proxy/blob/release-2.3/cmd/main.go
// https://github.com/valyala/fasthttp/issues/64
// Test:
// curl --verbose --cert /opt/appmesh/ssl/client.pem --key /opt/appmesh/ssl/client-key.pem --cacert /opt/appmesh/ssl/ca.pem  https://localhost:6058/containers/json | python -m json.tool

import (
	"log"
	"net"
	"net/url"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"github.com/valyala/fasthttp"
)

var (
	DockerSocketFilePath = "/var/run/docker.sock"
	dockerSocktClient    = &fasthttp.HostClient{
		Addr: DockerSocketFilePath,
		Dial: func(addr string) (net.Conn, error) {
			return net.Dial("unix", addr)
		}}
)

// http handler function
func dockerReverseProxyHandler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	log.Printf("---Request:---\n%v\n", req)

	resp := &ctx.Response
	// do request
	if err := dockerSocktClient.Do(req, resp); err != nil {
		ctx.Logger().Printf("Error when proxying the request: %s", err)
		dockerSocktClient.CloseIdleConnections()

		resp.SetStatusCode(fasthttp.StatusForbidden)
		resp.SetBodyString(err.Error())
	}

	log.Printf("---Response:---\n%v\n", resp)
}

func listenDockerAgent(dockerAgentAddr string) {
	if err := fasthttp.ListenAndServe(dockerAgentAddr, dockerReverseProxyHandler); err != nil {
		log.Fatalf("Error in fasthttp server: %s", err)
	}
}

func ListenDocker(dockerAgentAddr string) {

	if utils.IsFileExist(DockerSocketFilePath) {
		addr, err := url.Parse(dockerAgentAddr)
		if err != nil {
			panic(err)
		}
		if addr.Scheme == "https" {
			log.Print("Docker proxy does not support redirects https requests, use http instead.")
		}
		dockerAgentAddr = addr.Hostname() + ":" + addr.Port()
		listenDockerAgent(dockerAgentAddr)
	} else {
		log.Fatalf("Docker socket file not exist: %s", DockerSocketFilePath)
	}
}
