package agent

import (
	"html"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
)

func NewRequest(ctx *fasthttp.RequestCtx) *appmesh.Request {
	req := &ctx.Request
	// do not proxy "Connection" header.
	req.Header.Del("Connection")

	data := new(appmesh.Request)
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
	return data
}
