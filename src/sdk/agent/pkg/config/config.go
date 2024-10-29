package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

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

var logger *zap.SugaredLogger = utils.GetLogger()

// default configuration
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
	if err := readConfig(); err != nil {
		logger.Fatalf("Failed to initialize config: %v", err)
	}
}

func readConfig() error {
	// Load YAML configuration
	yamlFile, err := os.ReadFile(getConfigFilePath())
	if err != nil {
		return err
	}
	if err = yaml.Unmarshal(yamlFile, &ConfigData); err != nil {
		return err
	}

	// Apply environment variable overrides
	return ApplyEnvConfig(&ConfigData)
}

// Reads environment variables and applies overrides
func ApplyEnvConfig(config interface{}) error {
	envVars := os.Environ()
	const ENV_PREFIX = "APPMESH_"

	v := reflect.ValueOf(config).Elem()

	for _, env := range envVars {
		if strings.HasPrefix(env, ENV_PREFIX) {
			parts := strings.SplitN(env, "=", 2)
			envKey := parts[0]
			envValue := parts[1]

			// Split and remove the prefix from the environment key
			keys := strings.Split(envKey[len(ENV_PREFIX):], "_")

			// Check if the path exists in YAML
			exists, result := traverseStruct(v, keys, envValue)
			if !exists {
				logger.Warnf("Env configuration <%s>: path not found in YAML configuration", envKey)
			} else if result {
				logger.Infof("Env configuration <%s>: applied environment value", envKey)
			} else {
				logger.Errorf("Env configuration <%s>: failed to apply environment value", envKey)
			}
		}
	}
	return nil
}

// Traverse struct to find and apply environment values
// Returns (exists, applied) where:
// - exists: indicates if the path exists in the YAML
// - applied: indicates if the value was successfully applied
func traverseStruct(v reflect.Value, keys []string, envValue string) (bool, bool) {
	if len(keys) == 0 {
		return false, false
	}

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fieldType := v.Type().Field(i)

		// Match the field with the first key
		if strings.EqualFold(fieldType.Name, keys[0]) {
			if len(keys) == 1 {
				// If this is the last key, apply the environment value
				return true, applyEnv(field, envValue)
			} else if field.Kind() == reflect.Struct {
				// Traverse deeper into the nested struct
				return traverseStruct(field, keys[1:], envValue)
			}
			// Path exists but not complete
			return true, false
		}
	}
	// Path doesn't exist in YAML
	return false, false
}

// Apply environment value to field based on its type
func applyEnv(fieldVal reflect.Value, envValue string) bool {
	switch fieldVal.Kind() {
	case reflect.String:
		fieldVal.SetString(envValue)
		return true
	case reflect.Int:
		if num, err := strconv.Atoi(envValue); err == nil {
			fieldVal.SetInt(int64(num))
			return true
		}
	case reflect.Bool:
		boolVal, err := strconv.ParseBool(envValue)
		if err == nil {
			fieldVal.SetBool(boolVal)
			return true
		}
	}
	return false
}

// GetConfigFilePath determines the configuration file path
func getConfigFilePath() string {
	workConfig := filepath.Join(GetAppMeshHomeDir(), "work/config/config.yaml")
	if appmesh.IsFileExist(workConfig) {
		return workConfig
	}
	return filepath.Join(GetAppMeshHomeDir(), "config.yaml")
}

// GetAppMeshHomeDir determines the app mesh home directory
func GetAppMeshHomeDir() string {
	if IsAgentProdEnv() {
		return utils.GetParentDir(utils.GetCurrentAbPath())
	}
	return "/opt/appmesh"
}

// IsAgentProdEnv checks if the current environment is production
func IsAgentProdEnv() bool {
	exePath, _ := os.Executable()
	return filepath.Base(exePath) == "agent"
}
