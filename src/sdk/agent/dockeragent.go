package main

// Reference
// https://github.com/open-cluster-management/rbac-query-proxy/blob/release-2.3/cmd/main.go
// https://github.com/valyala/fasthttp/issues/64
// Test:
// curl --verbose --cert /opt/appmesh/ssl/client.pem --key /opt/appmesh/ssl/client-key.pem --cacert /opt/appmesh/ssl/ca.pem  https://localhost:6058/containers/json | python -m json.tool

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/valyala/fasthttp"
)

var proxyClient = &fasthttp.HostClient{
	Addr: dockerSocketFile,
	Dial: func(addr string) (net.Conn, error) {
		return net.Dial("unix", addr)
	}}

// http handler function
func dockerReverseProxyHandler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	log.Printf("---Request:---\n%v\n", req)

	resp := &ctx.Response
	// do request
	if err := proxyClient.Do(req, resp); err != nil {
		ctx.Logger().Printf("Error when proxying the request: %s", err)
		proxyClient.CloseIdleConnections()

		resp.SetStatusCode(fasthttp.StatusForbidden)
		resp.SetBodyString(err.Error())
	}

	log.Printf("---Response:---\n%v\n", resp)
}

func listenDockerAgent() {
	if err := fasthttp.ListenAndServe(dockerAgentAddr, dockerReverseProxyHandler); err != nil {
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

func listenDockerAgentTls() {
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
	ln, err := net.Listen("tcp4", dockerAgentAddr)
	if err != nil {
		log.Fatalf("Error in Listen tcp4: %s", err)
		panic(err)
	}
	lnTls := tls.NewListener(ln, cfg)
	if err := fasthttp.Serve(lnTls, dockerReverseProxyHandler); err != nil {
		log.Fatalf("Error in fasthttp Serve: %s", err)
		panic(err)
	}
}

func listenDocker() {
	enableTLS := strings.HasPrefix(dockerAgentAddr, "https://")

	// clean schema prefix for Listen
	dockerAgentAddr = strings.Replace(dockerAgentAddr, "https://", "", 1)
	dockerAgentAddr = strings.Replace(dockerAgentAddr, "http://", "", 1)

	if enableTLS {
		listenDockerAgentTls()
	} else {
		listenDockerAgent()
	}
}
