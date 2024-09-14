package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"gopkg.in/yaml.v3"
)

// configuration definition
type (
	RESTConfig struct {
		RestEnabled                  bool   `yaml:"RestEnabled"`
		RestListenAddress            string `yaml:"RestListenAddress"`
		RestListenPort               int    `yaml:"RestListenPort"`
		RestTcpPort                  int    `yaml:"RestTcpPort"`
		PrometheusExporterListenPort int    `yaml:"PrometheusExporterListenPort"`

		SSL appmesh.SSLConfig `yaml:"SSL"`
	}

	Configuration struct {
		REST RESTConfig `yaml:"REST"`
	}
)

// config with some default value
var ConfigData = Configuration{
	REST: RESTConfig{
		RestEnabled:                  true,
		RestListenAddress:            "localhost",
		RestListenPort:               6060,
		RestTcpPort:                  6059,
		PrometheusExporterListenPort: 0,

		SSL: appmesh.SSLConfig{
			SSLCaPath:                   "/opt/appmesh/ssl/ca.pem",
			SSLCertificateFile:          "/opt/appmesh/ssl/server.pem",
			SSLCertificateKeyFile:       "/opt/appmesh/ssl/server-key.pem",
			SSLClientCertificateFile:    "/opt/appmesh/ssl/client.pem",
			SSLClientCertificateKeyFile: "/opt/appmesh/ssl/client-key.pem",
			VerifyClient:                false,
			VerifyServer:                true,
			VerifyServerDelegate:        true,
		},
	},
}

func init() {
	yamlFile, err := os.ReadFile(getConfigFilePath())
	if err != nil {
		log.Fatalf("Error os.ReadFile: %v", err)
	}
	err = yaml.Unmarshal(yamlFile, &ConfigData)
	if err != nil {
		log.Fatalf("Error yaml.Unmarshal: %v", err)
	}
}

func getConfigFilePath() string {
	workConfig := filepath.Join(GetAppMeshHomeDir(), "work/config/config.yaml")
	if appmesh.IsFileExist(workConfig) {
		return workConfig
	}
	return filepath.Join(GetAppMeshHomeDir(), "config.yaml")
}

func GetAppMeshHomeDir() string {
	return utils.GetParentDir(utils.GetCurrentAbPath())
}
