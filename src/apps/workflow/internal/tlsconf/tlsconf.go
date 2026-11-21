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

// daemonSSLEnabled reads the daemon's effective SSL.SSLEnabled setting from
// the first existing config file in its own search order.
func daemonSSLEnabled() bool {
	root := os.Getenv(EnvConfigRoot)
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
		var cfg struct {
			REST struct {
				SSL struct {
					// Nil (key absent) keeps TLS on, like the daemon's own default.
					SSLEnabled *bool `yaml:"SSLEnabled"`
				} `yaml:"SSL"`
			} `yaml:"REST"`
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return true // broken file: fail closed to TLS
		}
		if cfg.REST.SSL.SSLEnabled == nil {
			return true
		}
		return *cfg.REST.SSL.SSLEnabled
	}
	return true
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
