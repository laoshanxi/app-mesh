// Package tlsconf resolves the Workflow engine's TLS policy for connections
// that carry real credentials (caller Dex bearers, run/control capabilities).
//
// It mirrors the daemon's OIDC semantics (oidc.yaml dex_tls_verify/dex_ca_path):
// server-certificate verification is on by default, an optional CA path pins
// the trust anchor, and only an explicit opt-out disables verification. All
// engine clients that transport a bearer or capability must resolve their
// Option through Apply — never hardcode InsecureSkipVerify.
package tlsconf

import (
	"os"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// EnvVerify disables verification when set to "false"/"0" (case-insensitive).
const EnvVerify = "APPMESH_ENGINE_TLS_VERIFY"

// EnvCA is the PEM CA file (or directory) replacing the trust anchor.
const EnvCA = "APPMESH_CA"

// VerifyEnabled reports whether daemon connections must verify the server
// certificate. Verification is the default; any value other than an explicit
// opt-out ("false"/"0") keeps it on, so a typo fails closed instead of open.
func VerifyEnabled() bool {
	v := os.Getenv(EnvVerify)
	return !strings.EqualFold(v, "false") && v != "0"
}

// Apply sets the verification fields of opt from the environment: verify by
// default, pin APPMESH_CA when provided, skip verification only on explicit
// opt-out. A configured CA that cannot be loaded is a hard error at client
// creation — never a silent fallback to skipping verification.
func Apply(opt *appmesh.Option) {
	if !VerifyEnabled() {
		opt.InsecureSkipVerify = true
		return
	}
	if caPath := os.Getenv(EnvCA); caPath != "" {
		opt.SslTrustedCA = &caPath
	}
}
