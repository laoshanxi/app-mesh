package utils

import (
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
)

// Define the allowed headers
var allowedHeaders = []string{
	"Accept",
	"Content-Type",
	"Authorization",
	"Auth-Permission",
	"Expire-Seconds",
	"Username",
	"Totp-Challenge",
	"Totp",
	"New-Password",
	"File-Path",
	"X-Send-File-Socket",
	"X-Recv-File-Socket",
	"X-Target-Host",
}

// cross-origin
func Cors(handle fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, HEAD")
		ctx.Response.Header.Set("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))

		//contentSecurityPolicy := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
		//ctx.Response.Header.Set("Content-Security-Policy", contentSecurityPolicy)
		//ctx.Response.Header.Set("X-Frame-Options", "SAMEORIGIN")

		if string(ctx.Method()) == http.MethodOptions {
			ctx.Response.SetBodyRaw([]byte("Allow: POST,OPTIONS"))
			return
		}

		handle(ctx)
	}
}
