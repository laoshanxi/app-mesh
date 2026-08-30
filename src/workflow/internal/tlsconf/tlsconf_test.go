package tlsconf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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
			opt := appmesh.Option{}
			Apply(&opt)
			if opt.InsecureSkipVerify != tc.skipVerify {
				t.Fatalf("InsecureSkipVerify = %v, want %v", opt.InsecureSkipVerify, tc.skipVerify)
			}
			if tc.caPinned && (opt.SslTrustedCA == nil || *opt.SslTrustedCA != tc.caEnv) {
				t.Fatalf("SslTrustedCA = %v, want %q", opt.SslTrustedCA, tc.caEnv)
			}
			if !tc.caPinned && opt.SslTrustedCA != nil {
				t.Fatalf("SslTrustedCA = %q, want nil", *opt.SslTrustedCA)
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
	opt := appmesh.Option{AppMeshUri: addr}
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
	opt = appmesh.Option{AppMeshUri: addr}
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
