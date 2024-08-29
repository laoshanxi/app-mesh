package http

import (
	"html"

	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
	"github.com/vmihailenco/msgpack/v5"
)

type Request struct {
	Uuid          string            `msg:"uuid" msgpack:"uuid"`
	RequestUri    string            `msg:"request_uri" msgpack:"request_uri"`
	HttpMethod    string            `msg:"http_method" msgpack:"http_method"`
	ClientAddress string            `msg:"client_addr" msgpack:"client_addr"`
	Body          string            `msg:"body" msgpack:"body"`
	Headers       map[string]string `msg:"headers" msgpack:"headers"`
	Querys        map[string]string `msg:"querys" msgpack:"querys"`
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
	data.Querys = make(map[string]string)
	req.URI().QueryArgs().VisitAll(func(key, value []byte) {
		data.Querys[string(key)] = string(value)
	})

	// do not read body for file upload
	if !(req.Header.IsPost() && string(req.URI().Path()) == REST_PATH_UPLOAD) {
		data.Body = html.UnescapeString(string(req.Body()))
	}
	return data
}

func (r *Request) serialize() ([]byte, error) {
	return msgpack.Marshal(*r)
}
