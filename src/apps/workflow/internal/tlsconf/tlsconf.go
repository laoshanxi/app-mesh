// Package tlsconf resolves the Workflow engine's connection policy for
// connections that carry real credentials (caller Dex bearers, run/control
// capabilities).
//
// Transport: the daemon's frame port speaks TLS by default, plaintext frames
// under SSL.SSLEnabled=false. APPMESH_ENGINE_TRANSPORT overrides; otherwise the
// daemon's effective config.yaml decides, and anything unreadable defaults to
// TLS. All engine clients must resolve their Option through Apply — never
// hardcode a transport or InsecureSkipVerify. TLS verification mirrors the
// daemon's OIDC semantics: on by default, an optional CA pins the anchor, and
// only an explicit opt-out disables it.
package tlsconf

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// EnvVerify disables verification when set to "false"/"0" (case-insensitive).
const EnvVerify = "APPMESH_ENGINE_TLS_VERIFY"

// EnvCA is the PEM CA file (or directory) replacing the trust anchor.
const EnvCA = "APPMESH_CA"

// EnvTransport forces the daemon frame transport: "plain" or "tls" (default);
// unset falls back to the daemon config file.
const EnvTransport = "APPMESH_ENGINE_TRANSPORT"

// EnvConfigRoot overrides the daemon installation root probed for the effective config.yaml.
const EnvConfigRoot = "APPMESH_ENGINE_CONFIG_ROOT"

// EnvWebSocketPort and EnvRestListenPort mirror the daemon's APPMESH_REST_<Key>
// overrides for the two REST listener ports; the workflow process inherits them
// from the daemon.
const (
	EnvWebSocketPort  = "APPMESH_REST_WebSocketPort"
	EnvRestListenPort = "APPMESH_REST_RestListenPort"
)

// Default REST listener ports from the shipped daemon config.yaml.
const (
	defaultWebSocketPort  = 6063
	defaultRestListenPort = 6060
)

// VerifyEnabled reports whether daemon connections must verify the server
// certificate. Verification is the default; any value other than an explicit
// opt-out ("false"/"0") keeps it on, so a typo fails closed instead of open.
func VerifyEnabled() bool {
	v := os.Getenv(EnvVerify)
	return !strings.EqualFold(v, "false") && v != "0"
}

// TransportPlain reports whether engine connections dial the daemon's plaintext
// frame port: the env override wins, else the daemon config; unreadable = TLS.
func TransportPlain() bool {
	if value, set := os.LookupEnv(EnvTransport); set && value != "" {
		return strings.EqualFold(value, "plain")
	}
	return !daemonSSLEnabled()
}

// TransportName labels the selected transport for startup errors and logs.
func TransportName() string {
	if TransportPlain() {
		return "plain"
	}
	return "tls"
}

// RESTPort returns the port of the daemon REST entry local Engine calls use:
// the native WebSocketPort listener when enabled, otherwise the agent's
// RestListenPort (the only REST entry when the native listener is disabled).
func RESTPort() int {
	cfg := readDaemonRESTConfig()
	if cfg.webSocketPort > 0 {
		return cfg.webSocketPort
	}
	return cfg.restListenPort
}

type daemonRESTConfig struct {
	sslEnabled     bool
	webSocketPort  int
	restListenPort int
}

// readDaemonRESTConfig reads the daemon's effective REST settings from the
// first existing config file in its own search order, then applies the
// APPMESH_REST_<Key> overrides both processes honor. A missing file keeps the
// shipped defaults (TLS on, 6060/6063); a broken file fails closed to TLS but
// keeps the port defaults. Like the daemon, an out-of-range RestListenPort
// falls back to its default.
func readDaemonRESTConfig() daemonRESTConfig {
	cfg := daemonRESTConfig{
		sslEnabled:     true,
		webSocketPort:  defaultWebSocketPort,
		restListenPort: defaultRestListenPort,
	}
	root := os.Getenv(EnvConfigRoot)
	if root == "" {
		// A custom install exports APPMESH_HOME; the daemon's own config search
		// starts at that home, so the engine must resolve the same tree.
		root = os.Getenv("APPMESH_HOME")
	}
	if root == "" {
		if runtime.GOOS == "windows" {
			root = "c:/local/appmesh"
		} else {
			root = "/opt/appmesh"
		}
	}
	for _, candidate := range []string{
		filepath.Join(root, "work", "config", "config.yaml"),
		filepath.Join(root, "config", "config.yaml"),
	} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue // missing/unreadable: try the next candidate
		}
		var raw struct {
			REST struct {
				WebSocketPort  *int `yaml:"WebSocketPort"`
				RestListenPort *int `yaml:"RestListenPort"`
				SSL            struct {
					// Nil (key absent) keeps TLS on, like the daemon's own default.
					SSLEnabled *bool `yaml:"SSLEnabled"`
				} `yaml:"SSL"`
			} `yaml:"REST"`
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return cfg // broken file: fail closed to TLS (and default ports)
		}
		cfg.sslEnabled = raw.REST.SSL.SSLEnabled == nil || *raw.REST.SSL.SSLEnabled
		// A port key absent from an existing file mirrors the daemon's parsed
		// zero value: WebSocketPort 0 disables the native listener.
		cfg.webSocketPort = 0
		if raw.REST.WebSocketPort != nil {
			cfg.webSocketPort = *raw.REST.WebSocketPort
		}
		cfg.restListenPort = 0
		if raw.REST.RestListenPort != nil {
			cfg.restListenPort = *raw.REST.RestListenPort
		}
		break
	}
	if v, ok := envInt(EnvWebSocketPort); ok {
		cfg.webSocketPort = v
	}
	if v, ok := envInt(EnvRestListenPort); ok {
		cfg.restListenPort = v
	}
	if cfg.restListenPort < 1000 || cfg.restListenPort > 65534 {
		cfg.restListenPort = defaultRestListenPort
	}
	return cfg
}

func envInt(name string) (int, bool) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return n, true
}

// daemonSSLEnabled reports whether the daemon's effective config enables TLS.
func daemonSSLEnabled() bool {
	return readDaemonRESTConfig().sslEnabled
}

// Apply sets the transport and verification fields of opt from the
// environment: plaintext dials when the daemon runs plaintext frames (no CA
// is loaded then — a leftover APPMESH_CA must not become a hard failure), and
// on TLS verify by default, pin APPMESH_CA when provided, skipping
// verification only on explicit opt-out. A configured CA that cannot be loaded
// is a hard error at client creation — never a silent fallback to skipping
// verification.
func Apply(opt *appmesh.Option) {
	if TransportPlain() {
		opt.PlainTransport = true
		return
	}
	if !VerifyEnabled() {
		opt.InsecureSkipVerify = true
		return
	}
	if caPath := os.Getenv(EnvCA); caPath != "" {
		opt.SSLTrustedCA = &caPath
	}
}
