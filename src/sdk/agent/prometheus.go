package main

import (
	"log"
	"strconv"

	"github.com/valyala/fasthttp"
)

const PROMETHEUS_METRIC_REST_PATH string = "/metrics"

func prometheusProxyHandler(ctx *fasthttp.RequestCtx) {
	// only allow GET /metrics
	if string(ctx.Request.URI().Path()) == PROMETHEUS_METRIC_REST_PATH && string(ctx.Request.Header.Method()) == "GET" {
		restProxyHandler(ctx)
	} else {
		ctx.Response.SetStatusCode(fasthttp.StatusBadRequest)
	}
}
func listenPrometheus(port int) {
	if err := fasthttp.ListenAndServe(":"+strconv.Itoa(port), prometheusProxyHandler); err != nil {
		log.Fatalf("Error in Prometheus exporter server: %s", err)
	}
}
