package grafana

import "github.com/valyala/fasthttp"

// cors adds headers that Grafana requires to work as a direct access data
// source.
//
// forgetting to add these manifests itself as an unintellible error when
// adding a datasource.
//
// These are not required if using "proxy" access.
func cors(handle fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Methods", "POST,OPTIONS")
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		ctx.Response.Header.Set("Access-Control-Allow-Headers", "accept, content-type")
		handle(ctx)
	}
}
