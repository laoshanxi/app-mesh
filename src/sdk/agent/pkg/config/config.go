package config

import (
	"log"
	"os"
	"path/filepath"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	"gopkg.in/yaml.v3"
)

// configuration definition
type (
	SSLConfig struct {
		VerifyClient                bool   `yaml:"VerifyClient"`
		VerifyServer                bool   `yaml:"VerifyServer"`
		VerifyServerDelegate        bool   `yaml:"VerifyServerDelegate"`
		SSLCaPath                   string `yaml:"SSLCaPath"`
		SSLCertificateFile          string `yaml:"SSLCertificateFile"`
		SSLCertificateKeyFile       string `yaml:"SSLCertificateKeyFile"`
		SSLClientCertificateFile    string `yaml:"SSLClientCertificateFile"`
		SSLClientCertificateKeyFile string `yaml:"SSLClientCertificateKeyFile"`
	}

	RESTConfig struct {
		RestEnabled                  bool   `yaml:"RestEnabled"`
		RestListenAddress            string `yaml:"RestListenAddress"`
		RestListenPort               int    `yaml:"RestListenPort"`
		RestTcpPort                  int    `yaml:"RestTcpPort"`
		PrometheusExporterListenPort int    `yaml:"PrometheusExporterListenPort"`

		SSL SSLConfig `yaml:"SSL"`
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

		SSL: SSLConfig{
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
	if utils.IsFileExist(workConfig) {
		return workConfig
	}
	return filepath.Join(GetAppMeshHomeDir(), "config.yaml")
}

func GetAppMeshHomeDir() string {
	return utils.GetParentDir(utils.GetCurrentAbPath())
}
