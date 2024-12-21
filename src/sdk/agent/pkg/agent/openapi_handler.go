package agent

import (
	"fmt"
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

// LoadOpenAPIContent loads the OpenAPI specification file
func LoadOpenAPIContent() {
	openAPIOnce.Do(func() {
		openapiFileLocation := filepath.Join(config.GetAppMeshHomeDir(), "script/openapi.yaml")
		yamlFile, err := os.ReadFile(openapiFileLocation)
		if err != nil {
			logger.Errorf("Error reading OpenAPI file: %v", err)
			return
		}
		openAPIContent = yamlFile
		logger.Infof("OpenAPI yaml file loaded: %s", openapiFileLocation)
	})
}

// RegisterOpenAPIRoutes registers OpenAPI and Swagger UI routes with gorilla/mux
func RegisterOpenAPIRoutes(router *mux.Router) {
	LoadOpenAPIContent()

	router.HandleFunc("/openapi.yaml", utils.Cors(utils.DefaultCORSConfig)(HandleOpenAPI)).Methods(http.MethodGet)
	router.HandleFunc("/swagger/", utils.Cors(utils.DefaultCORSConfig)(HandleSwaggerUI)).Methods(http.MethodGet)
}

// HandleOpenAPI serves the OpenAPI specification
func HandleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if len(openAPIContent) == 0 {
		http.Error(w, "OpenAPI content not available", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(openAPIContent)
	if err != nil {
		logger.Warnf("Error writing OpenAPI content: %v", err)
	}
}

// HandleSwaggerUI redirects to Swagger UI
func HandleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	swaggerURL := fmt.Sprintf("https://petstore.swagger.io/?url=https://%s/openapi.yaml", r.Host)
	http.Redirect(w, r, swaggerURL, http.StatusTemporaryRedirect)
}
