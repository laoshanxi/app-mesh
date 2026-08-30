package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

type (
	RESTConfig struct {
		RestEnabled                  bool   `yaml:"RestEnabled"`
		RestListenAddress            string `yaml:"RestListenAddress"`
		RestListenPort               int    `yaml:"RestListenPort"`
		RestTcpPort                  int    `yaml:"RestTcpPort"`
		PrometheusExporterListenPort int    `yaml:"PrometheusExporterListenPort"`
		CorsDisabled                 bool   `yaml:"CorsDisabled"`

		SSL appmesh.SSLConfig `yaml:"SSL"`
	}
	OIDCConfig struct {
		Issuer          string `yaml:"issuer" mapstructure:"issuer"`
		AccessURL       string `yaml:"access_url" mapstructure:"access_url"`
		TLSVerify       bool   `yaml:"tls_verify" mapstructure:"tls_verify"`
		CAPath          string `yaml:"ca_path" mapstructure:"ca_path"`
		LegacyAccessURL string `yaml:"-" mapstructure:"dex_access_url"`
		LegacyTLSVerify *bool  `yaml:"-" mapstructure:"dex_tls_verify"`
		LegacyCAPath    string `yaml:"-" mapstructure:"dex_ca_path"`
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
		RestListenAddress:            "127.0.0.1",
		RestListenPort:               6060,
		RestTcpPort:                  6059,
		PrometheusExporterListenPort: 0,
		CorsDisabled:                 false,

		SSL: appmesh.SSLConfig{
			SSLCaPath:                   "ssl/ca.pem",
			SSLCertificateFile:          "ssl/server.pem",
			SSLCertificateKeyFile:       "ssl/server-key.pem",
			SSLClientCertificateFile:    "ssl/client.pem",
			SSLClientCertificateKeyFile: "ssl/client-key.pem",
			VerifyClient:                false,
			VerifyServer:                true,
			VerifyServerDelegate:        true,
		},
	},
}

var OIDCData = OIDCConfig{
	Issuer:    "http://127.0.0.1:6062/auth",
	AccessURL: "http://127.0.0.1:6062/auth",
	TLSVerify: true,
}

func init() {
	if err := readConfig(); err != nil {
		logger.Errorf("Failed to initialize config: %v", err)
	}
	if err := readOIDCConfig(); err != nil {
		logger.Errorf("Failed to initialize OIDC config: %v", err)
	}
}

// Convert all relative paths to absolute paths
func ResolveAbsolutePaths() {
	ConfigData.REST.SSL.SSLCaPath = ResolveAbsolutePath(ConfigData.REST.SSL.SSLCaPath)
	ConfigData.REST.SSL.SSLCertificateFile = ResolveAbsolutePath(ConfigData.REST.SSL.SSLCertificateFile)
	ConfigData.REST.SSL.SSLCertificateKeyFile = ResolveAbsolutePath(ConfigData.REST.SSL.SSLCertificateKeyFile)
	ConfigData.REST.SSL.SSLClientCertificateFile = ResolveAbsolutePath(ConfigData.REST.SSL.SSLClientCertificateFile)
	ConfigData.REST.SSL.SSLClientCertificateKeyFile = ResolveAbsolutePath(ConfigData.REST.SSL.SSLClientCertificateKeyFile)
}

// readConfig loads the application config.yaml from files and environment variables.
// It returns an error if the configuration cannot be loaded or unmarshaled.
func readConfig() error {
	config := viper.New()
	config.SetConfigName("config")
	config.SetConfigType("yaml")

	// Add config file paths
	if !IsAgentProdEnv() {
		config.AddConfigPath("../../../../daemon")
	}
	config.AddConfigPath(filepath.Join(GetAppMeshHomeDir(), "work/config/"))
	config.AddConfigPath(filepath.Join(GetAppMeshHomeDir(), "config"))

	// Read YAML file
	if err := config.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Override config with environment variables
	OverrideConfigWithEnv(config)

	// Unmarshal into struct
	if err := config.Unmarshal(&ConfigData); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

func readOIDCConfig() error {
	config := viper.New()
	config.SetConfigName("oidc")
	config.SetConfigType("yaml")
	if !IsAgentProdEnv() {
		config.AddConfigPath("../../../../daemon/security")
	}
	config.AddConfigPath(filepath.Join(GetAppMeshHomeDir(), "work/config/"))
	config.AddConfigPath(filepath.Join(GetAppMeshHomeDir(), "config"))
	if err := config.ReadInConfig(); err != nil {
		return fmt.Errorf("failed to read oidc config file: %w", err)
	}
	root := struct {
		OIDC OIDCConfig `mapstructure:"OIDC"`
	}{OIDC: OIDCConfig{TLSVerify: true}}
	if err := config.Unmarshal(&root); err != nil {
		return fmt.Errorf("failed to unmarshal oidc config: %w", err)
	}
	if root.OIDC.AccessURL == "" {
		root.OIDC.AccessURL = root.OIDC.LegacyAccessURL
	}
	if root.OIDC.CAPath == "" {
		root.OIDC.CAPath = root.OIDC.LegacyCAPath
	}
	if !config.IsSet("OIDC.tls_verify") && root.OIDC.LegacyTLSVerify != nil {
		root.OIDC.TLSVerify = *root.OIDC.LegacyTLSVerify
	}
	if root.OIDC.Issuer == "" {
		return fmt.Errorf("OIDC issuer is required")
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_ISSUER", "APPMESH_DEX_ISSUER"); value != "" {
		root.OIDC.Issuer = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_ACCESS_URL", "APPMESH_DEX_ACCESS_URL"); value != "" {
		root.OIDC.AccessURL = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_CA_PATH", "APPMESH_DEX_CA_PATH"); value != "" {
		root.OIDC.CAPath = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_TLS_VERIFY", "APPMESH_DEX_TLS_VERIFY"); value != "" {
		root.OIDC.TLSVerify = value != "0" && !strings.EqualFold(value, "false")
	}
	root.OIDC.Issuer = strings.TrimRight(root.OIDC.Issuer, "/")
	root.OIDC.AccessURL = strings.TrimRight(root.OIDC.AccessURL, "/")
	if root.OIDC.Issuer == "" || root.OIDC.AccessURL == "" {
		return fmt.Errorf("OIDC issuer and access URL must be non-empty absolute URLs")
	}
	if err := validateAbsoluteHTTPURL(root.OIDC.Issuer); err != nil {
		return fmt.Errorf("invalid OIDC issuer: %w", err)
	}
	if err := validateAbsoluteHTTPURL(root.OIDC.AccessURL); err != nil {
		return fmt.Errorf("invalid OIDC access URL: %w", err)
	}
	OIDCData = root.OIDC
	return nil
}

func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func validateAbsoluteHTTPURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.Hostname() == "" {
		return fmt.Errorf("must be an absolute HTTP(S) URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return fmt.Errorf("credentials, query, and fragment are not allowed")
	}
	return nil
}

// OverrideConfigWithEnv overrides configuration with environment variables that have the APPMESH_ prefix.
func OverrideConfigWithEnv(config *viper.Viper) {
	const prefix = "APPMESH_"
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}

		key, value, _ := strings.Cut(env, "=")
		configKey := strings.ToLower(strings.NewReplacer(prefix, "", "_", ".").Replace(key))

		// Check if the key already exists in config and set
		if config.IsSet(configKey) {
			existing := config.GetString(configKey)
			config.Set(configKey, value)
			logger.Infof("Overriding config: %s (previous: %s, new: %s)", configKey, utils.MaskSecret(existing, 2, "***"), utils.MaskSecret(value, 2, "***"))
		} else {
			logger.Infof("Ignoring environment variable: '%s' (not found in config)", key)
		}
	}
}

// GetAppMeshHomeDir determines the app mesh home directory
func GetAppMeshHomeDir() string {
	if IsAgentProdEnv() {
		return utils.GetParentDir(utils.GetCurrentAbPath())
	}
	if runtime.GOOS == "windows" {
		return "C:\\local\\appmesh"
	}
	return "/opt/appmesh"
}

// IsAgentProdEnv checks if the current environment is production
func IsAgentProdEnv() bool {
	exePath, _ := os.Executable()
	baseName := filepath.Base(exePath)
	baseName = strings.TrimSuffix(baseName, ".exe") // Remove .exe postfix
	return filepath.Base(baseName) == "agent"
}

func ResolveAbsolutePath(path string) string {
	// Convert relative paths to absolute paths if necessary
	if !filepath.IsAbs(path) {
		absPath := filepath.Join(GetAppMeshHomeDir(), path)
		logger.Infof("Converting relative path <%s> to absolute path <%s>", path, absPath)
		return absPath
	}
	return path
}
