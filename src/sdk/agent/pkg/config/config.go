package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"gopkg.in/yaml.v3"
)

type (
	RESTConfig struct {
		RestEnabled                  bool   `yaml:"RestEnabled"`
		RestListenAddress            string `yaml:"RestListenAddress"`
		RestListenPort               int    `yaml:"RestListenPort"`
		TcpApiPort                   int    `yaml:"TcpApiPort"`
		PrometheusExporterListenPort int    `yaml:"PrometheusExporterListenPort"`
		CorsDisabled                 bool   `yaml:"CorsDisabled"`

		SSL appmesh.SSLConfig `yaml:"SSL"`
	}
	OIDCConfig struct {
		Issuer    string `yaml:"issuer"`
		AccessURL string `yaml:"access_url"`
		TLSVerify bool   `yaml:"tls_verify"`
		CAPath    string `yaml:"ca_path"`
	}

	Configuration struct {
		REST RESTConfig `yaml:"REST"`
	}
)

var logger *utils.Logger = utils.GetLogger()

// default configuration
var ConfigData = Configuration{
	REST: RESTConfig{
		RestEnabled:                  true,
		RestListenAddress:            "127.0.0.1",
		RestListenPort:               6060,
		TcpApiPort:                   6059,
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
	path, err := findConfigFile("config", "../../../../daemon")
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse into a generic map first: it records which keys the file actually
	// defines (environment overrides apply only to existing keys) and lets us
	// canonicalize key casing to the struct yaml tags (viper/mapstructure used
	// to match keys case-insensitively).
	var fileConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	canonicalizeKeys(fileConfig, reflect.TypeOf(Configuration{}))

	content, err := yaml.Marshal(fileConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := yaml.Unmarshal(content, &ConfigData); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Override config with environment variables
	return overrideConfigWithEnv(fileConfig)
}

// findConfigFile locates name.yaml in the search paths, in order: the dev
// path (non-production only), <home>/work/config/, then <home>/config.
// The first existing file wins.
func findConfigFile(name, devPath string) (string, error) {
	var paths []string
	if !IsAgentProdEnv() {
		paths = append(paths, devPath)
	}
	home := GetAppMeshHomeDir()
	paths = append(paths, filepath.Join(home, "work/config/"), filepath.Join(home, "config"))
	for _, dir := range paths {
		candidate := filepath.Join(dir, name+".yaml")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("config file %q not found in %v", name+".yaml", paths)
}

// canonicalizeKeys rewrites map keys to the exact yaml tag casing of the
// target struct fields, matching case-insensitively, recursively.
func canonicalizeKeys(node map[string]interface{}, t reflect.Type) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for key, value := range node {
		field, tagName, ok := findFieldByYAMLTag(t, key)
		if !ok {
			continue
		}
		if tagName != key {
			delete(node, key)
			node[tagName] = value
		}
		if child, ok := value.(map[string]interface{}); ok {
			canonicalizeKeys(child, field.Type)
		}
	}
}

// findFieldByYAMLTag returns the struct field whose yaml tag (or lowercased
// field name) matches key case-insensitively.
func findFieldByYAMLTag(t reflect.Type, key string) (reflect.StructField, string, bool) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if field.PkgPath != "" {
			continue // unexported
		}
		tagName := field.Tag.Get("yaml")
		if idx := strings.IndexByte(tagName, ','); idx >= 0 {
			tagName = tagName[:idx]
		}
		if tagName == "-" {
			continue
		}
		if tagName == "" {
			tagName = strings.ToLower(field.Name)
		}
		if strings.EqualFold(tagName, key) {
			return field, tagName, true
		}
	}
	return reflect.StructField{}, "", false
}

func readOIDCConfig() error {
	path, err := findConfigFile("oidc", "../../../../daemon/security")
	if err != nil {
		return fmt.Errorf("failed to read oidc config file: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read oidc config file: %w", err)
	}
	root := struct {
		OIDC OIDCConfig `yaml:"OIDC"`
	}{OIDC: OIDCConfig{TLSVerify: true}}
	var fileConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return fmt.Errorf("failed to unmarshal oidc config: %w", err)
	}
	// Canonicalize key casing to the struct yaml tags, as in readConfig.
	canonicalizeKeys(fileConfig, reflect.TypeOf(root))
	content, err := yaml.Marshal(fileConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal oidc config: %w", err)
	}
	if err := yaml.Unmarshal(content, &root); err != nil {
		return fmt.Errorf("failed to unmarshal oidc config: %w", err)
	}
	if root.OIDC.Issuer == "" {
		return fmt.Errorf("OIDC issuer is required")
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_ISSUER"); value != "" {
		root.OIDC.Issuer = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_ACCESS_URL"); value != "" {
		root.OIDC.AccessURL = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_CA_PATH"); value != "" {
		root.OIDC.CAPath = value
	}
	if value := firstNonEmptyEnv("APPMESH_AUTH_TLS_VERIFY"); value != "" {
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

// overrideConfigWithEnv overrides configuration with environment variables that have the APPMESH_ prefix.
// An override applies only when the key path already exists in the config file
// (matched case-insensitively), replicating viper's IsSet semantics.
func overrideConfigWithEnv(fileConfig map[string]interface{}) error {
	const prefix = "APPMESH_"
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, prefix) {
			continue
		}

		key, value, _ := strings.Cut(env, "=")
		configKey := strings.ToLower(strings.NewReplacer(prefix, "", "_", ".").Replace(key))
		path := strings.Split(configKey, ".")

		// Check if the key already exists in config and set
		if existing, ok := lookupConfigKey(fileConfig, path); ok {
			previous := fmt.Sprintf("%v", existing)
			if err := setConfigValue(&ConfigData, path, value); err != nil {
				return fmt.Errorf("failed to override config %q: %w", configKey, err)
			}
			logger.Infof("Overriding config: %s (previous: %s, new: %s)", configKey, utils.MaskSecret(previous, 2, "***"), utils.MaskSecret(value, 2, "***"))
		} else {
			logger.Infof("Ignoring environment variable: '%s' (not found in config)", key)
		}
	}
	return nil
}

// lookupConfigKey returns the value at the dot-separated key path in the
// parsed config file map, matching keys case-insensitively.
func lookupConfigKey(node map[string]interface{}, path []string) (interface{}, bool) {
	for i, segment := range path {
		var value interface{}
		found := false
		for key, v := range node {
			if strings.EqualFold(key, segment) {
				value, found = v, true
				break
			}
		}
		if !found {
			return nil, false
		}
		if i == len(path)-1 {
			return value, true
		}
		child, ok := value.(map[string]interface{})
		if !ok {
			return nil, false
		}
		node = child
	}
	return nil, false
}

// setConfigValue walks the struct along the dot-separated key path (matching
// yaml tags case-insensitively) and sets the leaf field, converting the string
// value to the field type. Keys that exist in the file but not in the struct
// are accepted and dropped, as viper's Unmarshal did; only conversion failures
// on known fields are errors.
func setConfigValue(target interface{}, path []string, value string) error {
	v := reflect.ValueOf(target)
	for _, segment := range path {
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		if v.Kind() != reflect.Struct {
			return fmt.Errorf("key %q is not a config section", segment)
		}
		field, _, ok := findFieldByYAMLTag(v.Type(), segment)
		if !ok {
			return nil
		}
		v = v.FieldByIndex(field.Index)
	}

	switch v.Kind() {
	case reflect.String:
		v.SetString(value)
	case reflect.Bool:
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return err
		}
		v.SetBool(parsed)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return err
		}
		v.SetInt(parsed)
	default:
		return fmt.Errorf("unsupported config field type %s", v.Kind())
	}
	return nil
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

// agentBinaryName is the production binary file name of the agent executable.
const agentBinaryName = "agent"

// IsAgentProdEnv checks if the current environment is production
func IsAgentProdEnv() bool {
	exePath, _ := os.Executable()
	baseName := filepath.Base(exePath)
	baseName = strings.TrimSuffix(baseName, ".exe") // Remove .exe postfix
	return filepath.Base(baseName) == agentBinaryName
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
