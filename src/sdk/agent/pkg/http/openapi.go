package http

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/buaazp/fasthttprouter"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"github.com/valyala/fasthttp"
)

var openAPIContent []byte

func init() {
	// Load the OpenAPI specification file
	openapiFileLocation := filepath.Join(config.GetAppMeshHomeDir(), "script/openapi.yaml")
	yamlFile, err := os.ReadFile(openapiFileLocation)
	if err != nil {
		log.Fatalf("Error os.ReadFile: %v", err)
	}
	openAPIContent = yamlFile
	log.Printf("OpenAPI yaml file: %s", openapiFileLocation)
}

func RegOpenapiRestHandler(router *fasthttprouter.Router) {
	router.GET("/openapi.yaml", utils.Cors(handleOpenAPI))
	router.GET("/swagger/", utils.Cors(handleSwaggerUI))
}

func handleOpenAPI(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Content-Type", "application/x-yaml")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(openAPIContent)
}

func handleSwaggerUI(ctx *fasthttp.RequestCtx) {
	swaggerURL := fmt.Sprintf("https://petstore.swagger.io/?url=https://%s/openapi.yaml", string(ctx.Host()))
	ctx.Redirect(swaggerURL, fasthttp.StatusTemporaryRedirect)
}
