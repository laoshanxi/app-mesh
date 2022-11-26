package http

import (
	"log"
	"strconv"

	"github.com/buaazp/fasthttprouter"
	"github.com/valyala/fasthttp"
)

const PROMETHEUS_METRIC_REST_PATH string = "/metrics"

func prometheusRootHandler(ctx *fasthttp.RequestCtx) {
	if string(ctx.Request.URI().Path()) != "/" {
		ctx.Error("File not found", fasthttp.StatusNotFound)
	}
	ctx.Response.SetBodyRaw([]byte("OK"))
}

func prometheusProxyHandler(ctx *fasthttp.RequestCtx) {
	// only allow GET /metrics
	if string(ctx.Request.URI().Path()) == PROMETHEUS_METRIC_REST_PATH && string(ctx.Request.Header.Method()) == "GET" {
		handleAppmeshRest(ctx)
	} else {
		ctx.Response.SetStatusCode(fasthttp.StatusBadRequest)
	}
}

func ListenPrometheus(port int) {
	router := fasthttprouter.New()
	router.GET("/", prometheusRootHandler)
	router.GET(PROMETHEUS_METRIC_REST_PATH, prometheusProxyHandler)

	if err := fasthttp.ListenAndServe(":"+strconv.Itoa(port), router.Handler); err != nil {
		log.Fatalf("Error in Prometheus exporter server: %s", err)
	}
}
