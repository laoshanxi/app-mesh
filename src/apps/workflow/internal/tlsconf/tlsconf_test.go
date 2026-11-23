package tlsconf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// TestApplyDefaultsToVerify pins the policy defaults: verification is on
// unless explicitly opted out, an opt-out wins over a pinned CA, and a
// typo in the opt-out value fails closed to verification. Engine clients
// carry real bearers/capabilities, so a policy that silently skipped
// verification would leak those credentials to a network attacker.
func TestApplyDefaultsToVerify(t *testing.T) {
	const anyCA = "/opt/appmesh/ssl/ca.pem"
	cases := []struct {
		name       string
		verifyEnv  string
		caEnv      string
		skipVerify bool
		caPinned   bool
	}{
		{"unset verifies", "", "", false, false},
		{"explicit true verifies", "true", "", false, false},
		{"false disables verification", "false", "", true, false},
		{"zero disables verification", "0", "", true, false},
		{"uppercase FALSE disables verification", "FALSE", "", true, false},
		{"unrecognized value fails closed to verification", "yes", "", false, false},
		{"CA pinned while verifying", "", anyCA, false, true},
		{"opt-out wins over pinned CA", "false", anyCA, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvVerify, tc.verifyEnv)
			t.Setenv(EnvCA, tc.caEnv)
			// Pin the transport probes away from a possible host /opt/appmesh:
			// these cases assert the TLS-verification policy only.
			t.Setenv(EnvTransport, "tls")
			opt := appmesh.Option{}
			Apply(&opt)
			if opt.InsecureSkipVerify != tc.skipVerify {
				t.Fatalf("InsecureSkipVerify = %v, want %v", opt.InsecureSkipVerify, tc.skipVerify)
			}
			if tc.caPinned && (opt.SSLTrustedCA == nil || *opt.SSLTrustedCA != tc.caEnv) {
				t.Fatalf("SSLTrustedCA = %v, want %q", opt.SSLTrustedCA, tc.caEnv)
			}
			if !tc.caPinned && opt.SSLTrustedCA != nil {
				t.Fatalf("SSLTrustedCA = %q, want nil", *opt.SSLTrustedCA)
			}
		})
	}
}

// TestApplyVerifiesDaemonCertificate proves the policy is enforced on the
// wire, not just in Option fields: a client built via Apply connects to a
// self-signed TLS daemon when APPMESH_CA pins that certificate, and fails
// closed (TLS verification error) when the CA does not match. This is the
// local self-signed development path E2E relies on.
func TestApplyVerifiesDaemonCertificate(t *testing.T) {
	addr, goodCA := startTestTLSDaemon(t)
	badDER, _ := generateSelfSigned(t)
	badCA := writeCert(t, badDER)

	t.Setenv(EnvVerify, "")
	t.Setenv(EnvCA, goodCA)
	// Pin the transport to TLS: this test asserts certificate verification.
	t.Setenv(EnvTransport, "tls")
	opt := appmesh.Option{AppMeshURI: addr}
	Apply(&opt)
	if opt.InsecureSkipVerify {
		t.Fatal("pinned-CA client must not skip verification")
	}
	client, err := appmesh.NewTCPClient(opt)
	if err != nil {
		t.Fatalf("client with pinned CA must verify and connect: %v", err)
	}
	client.CloseConnection()

	// A mismatched CA must fail closed instead of silently connecting.
	t.Setenv(EnvCA, badCA)
	opt = appmesh.Option{AppMeshURI: addr}
	Apply(&opt)
	if client, err := appmesh.NewTCPClient(opt); err == nil {
		client.CloseConnection()
		t.Fatal("client with mismatched CA must fail closed, not connect")
	}
}

// generateSelfSigned returns a fresh self-signed certificate (DER) plus its
// TLS form, usable as both the server certificate and its own root CA, like a
// dev self-signed App Mesh deployment.
func generateSelfSigned(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "appmesh-test-daemon"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeCert(t *testing.T, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// startTestTLSDaemon runs a local TLS listener presenting a self-signed
// certificate and returns its address plus the CA file that verifies it.
func startTestTLSDaemon(t *testing.T) (addr, caFile string) {
	t.Helper()
	der, serverCert := generateSelfSigned(t)
	caFile = writeCert(t, der)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tlsLn := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
	})
	go func() {
		for {
			conn, err := tlsLn.Accept()
			if err != nil {
				return
			}
			// Drive the server-side handshake, then drop the connection; the
			// SDK client only needs the handshake to verify the certificate.
			go func() {
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return
				}
				buf := make([]byte, 1)
				_, _ = conn.Read(buf)
			}()
		}
	}()
	return ln.Addr().String(), caFile
}

// writeDaemonConfig writes a daemon config.yaml at rel (relative to the test's
// config root) and returns the root.
func writeDaemonConfig(t *testing.T, rel, content string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

// sslConfig renders a daemon REST.SSL block with the given SSLEnabled value.
func sslConfig(enabled bool) string {
	return fmt.Sprintf("REST:\n  SSL:\n    SSLEnabled: %v\n", enabled)
}

// TestTransportPlainResolvesByEnvThenConfig pins the transport-selection
// priority: APPMESH_ENGINE_TRANSPORT wins outright, otherwise the daemon's
// effective config.yaml decides in the daemon's own search order
// (work/config/config.yaml before config/config.yaml), and a missing key,
// missing file or broken YAML fails closed to TLS.
func TestTransportPlainResolvesByEnvThenConfig(t *testing.T) {
	cases := []struct {
		name      string
		env       string
		envSet    bool
		workCfg   string
		mainCfg   string
		wantPlain bool
	}{
		{"env plain wins over TLS config", "plain", true, sslConfig(true), "", true},
		{"env tls wins over plain config", "tls", true, sslConfig(false), "", false},
		{"env unset, work config disables SSL", "", false, sslConfig(false), sslConfig(true), true},
		{"env unset, work config enables SSL", "", false, sslConfig(true), sslConfig(false), false},
		{"env unset, fallback config disables SSL", "", false, "", sslConfig(false), true},
		{"env unset, absent key defaults to TLS", "", false, "REST:\n  SSL:\n", "", false},
		{"env unset, no config defaults to TLS", "", false, "", "", false},
		{"env unset, broken config fails closed to TLS", "", false, "\t:::not yaml:::", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvConfigRoot, t.TempDir()) // no config until one is written
			if tc.envSet {
				t.Setenv(EnvTransport, tc.env)
			} else {
				t.Setenv(EnvTransport, "") // empty behaves as unset
			}
			if tc.workCfg != "" {
				t.Setenv(EnvConfigRoot, writeDaemonConfig(t, filepath.Join("work", "config", "config.yaml"), tc.workCfg))
			} else if tc.mainCfg != "" {
				t.Setenv(EnvConfigRoot, writeDaemonConfig(t, filepath.Join("config", "config.yaml"), tc.mainCfg))
			}

			if got := TransportPlain(); got != tc.wantPlain {
				t.Fatalf("TransportPlain() = %v, want %v", got, tc.wantPlain)
			}
			wantName := "tls"
			if tc.wantPlain {
				wantName = "plain"
			}
			if got := TransportName(); got != wantName {
				t.Fatalf("TransportName() = %q, want %q", got, wantName)
			}
		})
	}
}

// TestApplyPlainSkipsCA pins the plain-mode Apply behavior: no CA is pinned
// (a leftover or missing APPMESH_CA must not hard-fail client creation on a
// plaintext daemon) and the TLS verification fields stay untouched.
func TestApplyPlainSkipsCA(t *testing.T) {
	t.Setenv(EnvTransport, "plain")
	t.Setenv(EnvCA, filepath.Join(t.TempDir(), "absent-ca.pem"))

	opt := appmesh.Option{}
	Apply(&opt)
	if !opt.PlainTransport {
		t.Fatal("plain transport must be selected in plain mode")
	}
	if opt.SSLTrustedCA != nil {
		t.Fatalf("plain mode must not pin a CA, got %q", *opt.SSLTrustedCA)
	}
	if opt.InsecureSkipVerify {
		t.Fatal("plain mode must not touch InsecureSkipVerify")
	}
}

// TestRESTPortResolvesEffectiveConfig pins the local Engine REST entry: the
// native WebSocketPort listener when enabled, else the agent RestListenPort;
// APPMESH_REST_<Key> overrides win, and an existing config without the port
// keys mirrors the daemon's parsed zero values.
func TestRESTPortUsesAppMeshHomeWhenConfigRootUnset(t *testing.T) {
	home := writeDaemonConfig(t, filepath.Join("work", "config", "config.yaml"),
		"REST:\n  WebSocketPort: 0\n  RestListenPort: 7070\n")
	t.Setenv(EnvConfigRoot, "")
	t.Setenv("APPMESH_HOME", home)
	t.Setenv(EnvWebSocketPort, "")
	t.Setenv(EnvRestListenPort, "")
	if got := RESTPort(); got != 7070 {
		t.Fatalf("RESTPort() = %d, want 7070 from $APPMESH_HOME/work/config/config.yaml", got)
	}
}

func TestRESTPortResolvesEffectiveConfig(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		wsEnv   string
		restEnv string
		want    int
	}{
		{"no config uses shipped defaults", "", "", "", 6058},
		{"native listener from config", "REST:\n  WebSocketPort: 7058\n  RestListenPort: 7060\n", "", "", 7058},
		{"disabled native listener falls back to agent", "REST:\n  WebSocketPort: 0\n  RestListenPort: 7060\n", "", "", 7060},
		{"absent keys mirror daemon zeros", "REST:\n  SSL:\n    SSLEnabled: true\n", "", "", 6060},
		{"out-of-range agent port defaults", "REST:\n  WebSocketPort: 0\n  RestListenPort: 80\n", "", "", 6060},
		{"env native port overrides config", "REST:\n  WebSocketPort: 7058\n  RestListenPort: 7060\n", "7090", "", 7090},
		{"env agent port used when native disabled", "REST:\n  WebSocketPort: 0\n  RestListenPort: 7060\n", "", "7091", 7091},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvConfigRoot, t.TempDir())
			if tc.config != "" {
				t.Setenv(EnvConfigRoot, writeDaemonConfig(t, filepath.Join("work", "config", "config.yaml"), tc.config))
			}
			t.Setenv(EnvWebSocketPort, tc.wsEnv)
			t.Setenv(EnvRestListenPort, tc.restEnv)
			if got := RESTPort(); got != tc.want {
				t.Fatalf("RESTPort() = %d, want %d", got, tc.want)
			}
		})
	}
}
