package http

import (
	"fmt"
	"html"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
)

var HMAC *HMACVerify

// Request represents the message sent over TCP
type Request struct {
	appmesh.Request
}

func NewRequest(ctx *fasthttp.RequestCtx) *Request {
	req := &ctx.Request
	// do not proxy "Connection" header.
	req.Header.Del("Connection")

	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = string(req.Header.Method())
	data.RequestUri = string(req.URI().Path())
	data.ClientAddress = ctx.RemoteAddr().String()
	data.Headers = make(map[string]string)
	req.Header.VisitAll(func(key, value []byte) {
		data.Headers[string(key)] = string(value)
	})
	data.Queries = make(map[string]string)
	req.URI().QueryArgs().VisitAll(func(key, value []byte) {
		data.Queries[string(key)] = string(value)
	})

	// do not read body for file upload
	if !(req.Header.IsPost() && string(req.URI().Path()) == REST_PATH_UPLOAD) {
		data.Body = html.UnescapeString(string(req.Body()))
	}
	// data.setHMACVerify() // on-demand
	return data
}

func (r *Request) setHMACVerify() error {
	if HMAC != nil {
		r.Headers[string("X-Request-HMAC")] = HMAC.GenerateHMAC(r.Uuid)
	} else {
		return fmt.Errorf("HMAC not initialized")
	}
	return nil
}
