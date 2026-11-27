package agent

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// Framed-protocol daemon stand-in mirroring the daemon's length-prefixed
// msgpack channel, with fault knobs for the stale-connection and file-transfer
// behaviors the REST fixes must survive.

const testFrameMagic = uint32(0x07C707F8)

type framedRequest struct {
	req  appmesh.Request
	conn net.Conn
}

// framedDaemonConfig controls how the fake daemon answers.
type framedDaemonConfig struct {
	// failFirstRequest closes the first accepted connection right after
	// reading its first request, without replying (idle-close signature).
	failFirstRequest bool
	// failFirstWait delays that close, so the client's send has completed and
	// it is already waiting for the reply (a post-send failure).
	failFirstWait time.Duration
	// uploadFailAfterBytes closes the connection mid-upload once this many
	// body bytes arrived (0 = serve the whole transfer).
	uploadFailAfterBytes int
}

type framedDaemon struct {
	t        *testing.T
	cfg      framedDaemonConfig
	addr     net.Addr
	mu       sync.Mutex
	requests []framedRequest
	uploaded int
	conns    int
}

func newFramedDaemon(t *testing.T, cfg framedDaemonConfig) *framedDaemon {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	address := probe.Addr().String()
	probe.Close()

	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(certServer.Close)
	ln, err := tls.Listen("tcp", address, certServer.TLS)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	d := &framedDaemon{t: t, cfg: cfg, addr: ln.Addr()}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns++
			fail := d.cfg.failFirstRequest && d.conns == 1
			d.mu.Unlock()
			go d.serve(conn, fail)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return d
}

func (d *framedDaemon) serve(conn net.Conn, failFirst bool) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	for {
		payload, err := readTestFrame(reader)
		if err != nil {
			return
		}
		var req appmesh.Request
		if err := msgpack.Unmarshal(payload, &req); err != nil {
			return
		}
		d.mu.Lock()
		d.requests = append(d.requests, framedRequest{req: req, conn: conn})
		if _, isUpload := req.Headers[HTTPHeaderKeyXSendFileSocket]; isUpload {
			d.mu.Unlock()
			d.serveUpload(conn, req)
			return
		}
		d.mu.Unlock()

		if failFirst {
			// Idle-close signature: connection dies before any answer.
			time.Sleep(d.cfg.failFirstWait)
			return
		}
		resp := appmesh.Response{
			UUID:        req.UUID,
			RequestURI:  req.RequestURI,
			HTTPStatus:  http.StatusOK,
			BodyMsgType: "application/json",
			Body:        []byte(`{"status":"ok"}`),
			Headers:     map[string]string{},
		}
		data, err := resp.Serialize()
		if err != nil {
			return
		}
		if err := writeTestFrame(conn, data); err != nil {
			return
		}
	}
}

func (d *framedDaemon) serveUpload(conn net.Conn, req appmesh.Request) {
	// Arm the transfer like the daemon's precheck reply.
	resp := appmesh.Response{
		UUID:        req.UUID,
		RequestURI:  req.RequestURI,
		HTTPStatus:  http.StatusOK,
		BodyMsgType: "application/json",
		Body:        []byte(`{"status":"armed"}`),
		Headers:     map[string]string{HTTPHeaderKeyXSendFileSocket: req.Headers[HTTPHeaderKeyXSendFileSocket]},
	}
	data, err := resp.Serialize()
	if err != nil {
		return
	}
	if err := writeTestFrame(conn, data); err != nil {
		return
	}

	reader := bufio.NewReader(conn)
	total := 0
	for {
		payload, err := readTestFrame(reader)
		if err != nil {
			return // peer hangup: transfer incomplete
		}
		if len(payload) == 0 {
			d.mu.Lock()
			d.uploaded = total
			d.mu.Unlock()
			return // EOF marker: complete
		}
		total += len(payload)
		if d.cfg.uploadFailAfterBytes > 0 && total >= d.cfg.uploadFailAfterBytes {
			return // daemon dies mid-transfer, dropping the connection
		}
	}
}

func (d *framedDaemon) uploadBytes() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.uploaded
}

func (d *framedDaemon) requestCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.requests)
}

func (d *framedDaemon) requestMethod(index int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.requests) {
		return ""
	}
	return d.requests[index].req.HTTPMethod
}

func (d *framedDaemon) requestUUID(index int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if index < 0 || index >= len(d.requests) {
		return ""
	}
	return d.requests[index].req.UUID
}

func readTestFrame(reader *bufio.Reader) ([]byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(header[:4]) != testFrameMagic {
		return nil, fmt.Errorf("bad magic")
	}
	body := make([]byte, binary.BigEndian.Uint32(header[4:]))
	if len(body) == 0 {
		return []byte{}, nil
	}
	if _, err := io.ReadFull(reader, body); err != nil {
		return nil, err
	}
	return body, nil
}

func writeTestFrame(conn net.Conn, payload []byte) error {
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], testFrameMagic)
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	if _, err := conn.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := conn.Write(payload)
	return err
}

// mountLocalDaemon points the agent's local-daemon globals and staging
// directory at test-local locations.
func mountLocalDaemon(t *testing.T, d *framedDaemon) {
	t.Helper()
	resetConnectionState(t)
	localTCPAddr = d.addr
	localWSSAddr = strings.TrimPrefix(d.addr.String(), "tcp://")
	savedTemp := tempDirBase
	tempDirBase = t.TempDir()
	t.Cleanup(func() { tempDirBase = savedTemp })
}

func newAgentRequest(t *testing.T, method, target string, body io.ReadCloser, headers map[string]string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

// TestHandleAppMeshRequestRetriesStalePooledLocalConnection pins that the
// first request on a daemon-idle-closed pooled connection transparently
// re-dials instead of answering 502.
func TestHandleAppMeshRequestRetriesStalePooledLocalConnection(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{failFirstRequest: true})
	mountLocalDaemon(t, d)

	// Pool the connection the daemon will kill before any request is served.
	if _, err := getLocalConnection(); err != nil {
		t.Fatalf("eager connect: %v", err)
	}

	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder, newAgentRequest(t, http.MethodGet, "https://agent/appmesh/config", nil, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("first request after stale close: got %d (%s), want 200", recorder.Code, recorder.Body.String())
	}
	if n := d.requestCount(); n != 2 {
		t.Fatalf("daemon saw %d requests, want the original plus one retry", n)
	}
	if first, retry := d.requestUUID(0), d.requestUUID(1); first == retry {
		t.Fatalf("retry reused the lost attempt's UUID %q", first)
	}

	// The replacement connection keeps serving subsequent requests.
	recorder = httptest.NewRecorder()
	HandleAppMeshRequest(recorder, newAgentRequest(t, http.MethodGet, "https://agent/appmesh/config", nil, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("follow-up request: got %d, want 200", recorder.Code)
	}
}

// TestStaleLocalConnectionDoesNotReplayNonIdempotent pins the retry rule: a
// request the daemon may already have executed (it received the POST and only
// the reply was lost) is never replayed; the agent answers 502 instead.
func TestStaleLocalConnectionDoesNotReplayNonIdempotent(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{failFirstRequest: true, failFirstWait: 200 * time.Millisecond})
	mountLocalDaemon(t, d)

	// Pool the connection the daemon will kill before any request is served.
	if _, err := getLocalConnection(); err != nil {
		t.Fatalf("eager connect: %v", err)
	}

	body := io.NopCloser(strings.NewReader(`{"name":"demo"}`))
	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder,
		newAgentRequest(t, http.MethodPost, "https://agent/appmesh/app/demo", body, nil))
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("lost POST reply answered %d (%s), want 502", recorder.Code, recorder.Body.String())
	}
	if n := d.requestCount(); n != 1 {
		t.Fatalf("daemon saw %d POST attempts, want exactly 1", n)
	}
	if got := d.requestMethod(0); got != http.MethodPost {
		t.Fatalf("daemon saw method %q, want POST", got)
	}
}

// TestClientCancellationDoesNotEvictPooledLocalConnection pins that a client
// abort fails only its own request: evicting the shared pooled connection would
// close every other in-flight request on it.
func TestClientCancellationDoesNotEvictPooledLocalConnection(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{})
	mountLocalDaemon(t, d)

	conn, err := getLocalConnection()
	if err != nil {
		t.Fatalf("eager connect: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := newAgentRequest(t, http.MethodGet, "https://agent/appmesh/config", nil, nil).WithContext(ctx)
	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder, req)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("canceled request answered %d (%s), want 502", recorder.Code, recorder.Body.String())
	}
	if n := d.requestCount(); n != 0 {
		t.Fatalf("daemon received %d requests for a canceled client request", n)
	}
	if pooled, ok := remoteConnections.Load(conn.key); !ok || pooled != conn {
		t.Fatal("client cancellation evicted the pooled connection")
	}
	select {
	case <-conn.closed:
		t.Fatal("client cancellation closed the pooled connection")
	default:
	}
}

// TestRefreshLocalConnectionDoesNotEvictReplacement pins the CAS guard: a
// stale failure must never close the connection a concurrent retry replaced.
func TestRefreshLocalConnectionDoesNotEvictReplacement(t *testing.T) {
	resetConnectionState(t)

	key := "tcp://127.0.0.1:6062"
	stale := &Connection{key: key, messageConnection: appmesh.NewTCPConnection(),
		pending: make(map[string]chan *Response), closed: make(chan struct{})}
	replacement := &Connection{key: key, messageConnection: appmesh.NewTCPConnection(),
		pending: make(map[string]chan *Response), closed: make(chan struct{})}

	remoteConnections.Store(key, stale)
	refreshLocalConnection(stale)
	if _, ok := remoteConnections.Load(key); ok {
		t.Fatalf("stale connection not evicted")
	}
	select {
	case <-stale.closed:
	default:
		t.Fatalf("stale connection not closed")
	}

	remoteConnections.Store(key, replacement)
	refreshLocalConnection(stale) // stale already replaced: must be a no-op
	if pooled, ok := remoteConnections.Load(key); !ok || pooled != replacement {
		t.Fatalf("replacement evicted by a stale failure")
	}
	select {
	case <-replacement.closed:
		t.Fatalf("replacement closed by a stale failure")
	default:
	}
}

// TestForwardPrecheckRetriesStalePooledLocalConnection pins that the bearer
// precheck of a forwarded request survives a daemon-idle-closed pooled
// connection (it answered 503 before the retry existed).
func TestForwardPrecheckRetriesStalePooledLocalConnection(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{failFirstRequest: true})
	mountLocalDaemon(t, d)

	if _, err := getLocalConnection(); err != nil {
		t.Fatalf("eager connect: %v", err)
	}

	req := newAgentRequest(t, http.MethodGet, "https://agent/appmesh/principal/self", nil,
		map[string]string{HTTPHeaderKeyXTargetHost: "http://127.0.0.1:1", HTTPHeaderKeyAuthorization: "Bearer test-token"})
	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder, req)

	// The fake daemon answers the retried precheck without the host-forward
	// permission, so the capability gate (not a transport failure) responds.
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("forwarded precheck after stale close: got %d (%s), want 403", recorder.Code, recorder.Body.String())
	}
}

// TestUploadTransferFailureFailsLoud pins that a daemon transfer lost
// mid-upload answers 502 instead of committing the staged 200.
func TestUploadTransferFailureFailsLoud(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{uploadFailAfterBytes: 64 * 1024})
	mountLocalDaemon(t, d)

	body := strings.Repeat("a", 512*1024)
	req := newAgentRequest(t, http.MethodPost, "https://agent"+RestPathUpload, io.NopCloser(strings.NewReader(body)),
		map[string]string{HTTPHeaderKeyFilePath: "/opt/appmesh/work/tmp/fixa-upload.bin"})
	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder, req)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("dropped transfer answered %d (%s), want 502", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "failed to store the file") {
		t.Fatalf("502 body %q does not carry the transfer failure reason", recorder.Body.String())
	}
	if got := d.uploadBytes(); got != 0 {
		t.Fatalf("daemon committed %d bytes for a dropped transfer", got)
	}
}

// TestUploadTransferSuccessKeeps200 pins the working small-upload path stays
// byte-complete with a 200 answer.
func TestUploadTransferSuccessKeeps200(t *testing.T) {
	d := newFramedDaemon(t, framedDaemonConfig{})
	mountLocalDaemon(t, d)

	body := strings.Repeat("a", 512*1024)
	req := newAgentRequest(t, http.MethodPost, "https://agent"+RestPathUpload, io.NopCloser(strings.NewReader(body)),
		map[string]string{HTTPHeaderKeyFilePath: "/opt/appmesh/work/tmp/fixa-upload-ok.bin"})
	recorder := httptest.NewRecorder()
	HandleAppMeshRequest(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("complete transfer answered %d (%s), want 200", recorder.Code, recorder.Body.String())
	}
	if got := d.uploadBytes(); got != len(body) {
		t.Fatalf("daemon stored %d bytes, want %d", got, len(body))
	}
}

// TestRelayStreamRequestStreamsIncrementally pins that SSE answers pass
// through the agent chunk by chunk, not buffered until completion.
func TestRelayStreamRequestStreamsIncrementally(t *testing.T) {
	resetConnectionState(t)

	engine := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("event: partial\n\n"))
		flusher.Flush()
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte("event: final\n\n"))
	}))
	t.Cleanup(engine.Close)

	savedWSS := localWSSAddr
	savedVerify := config.ConfigData.REST.SSL.VerifyServer
	localWSSAddr = strings.TrimPrefix(engine.URL, "https://")
	config.ConfigData.REST.SSL.VerifyServer = false
	t.Cleanup(func() { localWSSAddr, config.ConfigData.REST.SSL.VerifyServer = savedWSS, savedVerify })

	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayStreamRequest(w, r)
	}))
	t.Cleanup(relay.Close)

	start := time.Now()
	resp, err := http.Post(relay.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("relay request: %v", err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("stream content type %q", ct)
	}

	firstEvent := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 && strings.Contains(string(buf[:n]), "partial") {
				close(firstEvent)
				return
			}
			if err != nil {
				close(firstEvent)
				return
			}
		}
	}()
	select {
	case <-firstEvent:
		if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
			t.Fatalf("first chunk arrived after %v: stream is buffered, not incremental", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("stream never delivered the first chunk")
	}
	rest, err := io.ReadAll(resp.Body)
	if err != nil || !strings.Contains(string(rest), "final") {
		t.Fatalf("stream truncated: %v %q", err, string(rest))
	}
}

// TestFlushCopiedForwardedBodyStillWorks pins plain (non-streaming) forwarded
// bodies stay intact with the flushing writer in place.
func TestFlushCopiedForwardedBodyStillWorks(t *testing.T) {
	payload := strings.Repeat("x", 128*1024)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(upstream.Close)

	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}
	savedVerify := config.ConfigData.REST.SSL.VerifyServer
	config.ConfigData.REST.SSL.VerifyServer = false
	t.Cleanup(func() { config.ConfigData.REST.SSL.VerifyServer = savedVerify })

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://agent/appmesh/logo.svg", nil)
	ForwardAppMeshRequest(recorder, req, target)
	if recorder.Code != http.StatusOK || recorder.Body.String() != payload {
		t.Fatalf("forwarded body broken: code=%d len=%d", recorder.Code, recorder.Body.Len())
	}
}

// newClientCertificate writes a self-signed client certificate/key pair for
// mutual-TLS tests and returns their paths.
func newClientCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write client certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatalf("write client key: %v", err)
	}
	return certPath, keyPath
}

// TestRelayStreamRequestPresentsClientCertificate pins the SSE relay's mutual
// TLS: with REST.SSL.VerifyClient the daemon's REST listener requires a client
// certificate, which the shared delegate client never presents.
func TestRelayStreamRequestPresentsClientCertificate(t *testing.T) {
	resetConnectionState(t)

	engine := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("event: relayed\n\n"))
	}))
	engine.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert}
	engine.StartTLS()
	t.Cleanup(engine.Close)

	certPath, keyPath := newClientCertificate(t)
	ssl := &config.ConfigData.REST.SSL
	savedEnabled := ssl.SSLEnabled
	savedCert, savedKey := ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile
	savedWSS := localWSSAddr
	enabled := true
	ssl.SSLEnabled = &enabled
	ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile = certPath, keyPath
	localWSSAddr = strings.TrimPrefix(engine.URL, "https://")
	t.Cleanup(func() {
		ssl.SSLEnabled = savedEnabled
		ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile = savedCert, savedKey
		localWSSAddr = savedWSS
	})

	recorder := httptest.NewRecorder()
	relayStreamRequest(recorder,
		httptest.NewRequest(http.MethodGet, "https://agent/appmesh/app/demo/output/stream", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("relay with a client certificate: got %d (%s), want 200", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "relayed") {
		t.Fatalf("relay body %q does not carry the streamed event", recorder.Body.String())
	}
}

// TestNewStreamRelayClientPlainTransportSkipsCertificateMaterial pins that a
// plaintext deployment, whose install carries no certificate files, still
// builds its relay client.
func TestNewStreamRelayClientPlainTransportSkipsCertificateMaterial(t *testing.T) {
	ssl := &config.ConfigData.REST.SSL
	savedEnabled := ssl.SSLEnabled
	savedCert, savedKey := ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile
	disabled := false
	ssl.SSLEnabled = &disabled
	ssl.SSLClientCertificateFile = filepath.Join(t.TempDir(), "missing.pem")
	ssl.SSLClientCertificateKeyFile = filepath.Join(t.TempDir(), "missing-key.pem")
	t.Cleanup(func() {
		ssl.SSLEnabled = savedEnabled
		ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile = savedCert, savedKey
	})

	client, err := newStreamRelayClient()
	if err != nil {
		t.Fatalf("plaintext relay client: %v", err)
	}
	client.CloseIdleConnections()
}
