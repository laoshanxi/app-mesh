package agent

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/mux"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
)

var (
	openAPIContent []byte
	openAPIOnce    sync.Once
)

// loadOpenAPIContent loads the OpenAPI specification file
func loadOpenAPIContent() {
	openAPIOnce.Do(func() {
		openapiFileLocation := filepath.Join(config.GetAppMeshHomeDir(), "script/openapi.yaml")
		yamlFile, err := os.ReadFile(openapiFileLocation)
		if err != nil {
			log.Printf("Error reading OpenAPI file: %v", err)
			return
		}
		openAPIContent = yamlFile
		log.Printf("OpenAPI yaml file loaded: %s", openapiFileLocation)
	})
}

// RegOpenapiRestHandler registers OpenAPI and Swagger UI routes with gorilla/mux
func RegOpenapiRestHandler(router *mux.Router) {
	loadOpenAPIContent()

	router.HandleFunc("/openapi.yaml", utils.Cors(utils.DefaultCORSConfig)(handleOpenAPI)).Methods(http.MethodGet)
	router.HandleFunc("/swagger/", utils.Cors(utils.DefaultCORSConfig)(handleSwaggerUI)).Methods(http.MethodGet)
}

// handleOpenAPI serves the OpenAPI specification
func handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if len(openAPIContent) == 0 {
		http.Error(w, "OpenAPI content not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(openAPIContent)
	if err != nil {
		log.Printf("Error writing OpenAPI content: %v", err)
	}
}

// handleSwaggerUI redirects to Swagger UI
func handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	swaggerURL := fmt.Sprintf("https://petstore.swagger.io/?url=https://%s/openapi.yaml", r.Host)
	http.Redirect(w, r, swaggerURL, http.StatusTemporaryRedirect)
}
