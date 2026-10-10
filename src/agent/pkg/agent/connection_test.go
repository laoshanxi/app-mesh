package agent

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// resetConnectionState isolates a test from the pool, the globals and the TLS file settings.
func resetConnectionState(t *testing.T) {
	t.Helper()
	ssl := &config.ConfigData.REST.SSL
	cert, certKey, verifyServer := ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile, ssl.VerifyServer
	pingInterval := wssPingInterval

	ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile, ssl.VerifyServer = "", "", false
	clearConnections()

	t.Cleanup(func() {
		clearConnections()
		ssl.SSLClientCertificateFile, ssl.SSLClientCertificateKeyFile, ssl.VerifyServer = cert, certKey, verifyServer
		localTCPAddr, localWSSAddr = nil, ""
		wssPingInterval = pingInterval
	})
}

// clearConnections empties the pool and closes the pooled sockets.
func clearConnections() {
	remoteConnections.Range(func(key, value interface{}) bool {
		remoteConnections.Delete(key)
		if conn, ok := value.(*Connection); ok {
			conn.close()
		}
		return true
	})
}

// newWSSTestServer starts a TLS WebSocket daemon stand-in that counts pings and reports session end.
func newWSSTestServer(t *testing.T) (hostPort string, pingCount func() int64, sessionClosed <-chan struct{}) {
	t.Helper()
	var pings int64
	closed := make(chan struct{})
	var closedOnce sync.Once

	upgrader := websocket.Upgrader{Subprotocols: []string{"appmesh-ws"}}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		conn.SetPingHandler(func(appData string) error {
			atomic.AddInt64(&pings, 1)
			return conn.WriteControl(websocket.PongMessage, []byte(appData), time.Now().Add(time.Second))
		})
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				closedOnce.Do(func() { close(closed) })
				return
			}
		}
	})

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	return strings.TrimPrefix(server.URL, "https://"), func() int64 { return atomic.LoadInt64(&pings) }, closed
}

// freeTCPAddr returns an unbound address and a function that starts a TLS listener on it.
func freeTCPAddr(t *testing.T) (net.Addr, func() net.Addr) {
	t.Helper()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	address := probe.Addr().String()
	probe.Close()

	resolve := func() net.Addr {
		addr, err := net.ResolveTCPAddr("tcp", address)
		if err != nil {
			t.Fatalf("resolve %s: %v", address, err)
		}
		return addr
	}
	listen := func() net.Addr {
		// httptest supplies a certificate the SDK accepts; the socket is then held open.
		certServer := httptest.NewTLSServer(http.NotFoundHandler())
		t.Cleanup(certServer.Close)
		ln, err := tls.Listen("tcp", address, certServer.TLS)
		if err != nil {
			t.Fatalf("listen on %s: %v", address, err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					_, _ = io.Copy(io.Discard, conn)
				}()
			}
		}()
		return ln.Addr()
	}
	return resolve(), listen
}

// waitFor polls until cond holds so tests do not depend on fixed sleeps.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestConnectionPoolSeparatesTCPAndWSSEntries pins that one transport is never returned for the other's key.
func TestConnectionPoolSeparatesTCPAndWSSEntries(t *testing.T) {
	resetConnectionState(t)
	tcpAddr, startTCP := freeTCPAddr(t)
	wssHostPort, _, _ := newWSSTestServer(t)

	wssConn, err := getOrCreateWSSConnection(wssHostPort, false)
	if err != nil {
		t.Fatalf("create WSS connection: %v", err)
	}
	if _, ok := wssConn.messageConnection.(*appmesh.WSSConnection); !ok {
		t.Fatalf("WSS pool entry carries %T, want *appmesh.WSSConnection", wssConn.messageConnection)
	}

	tcpConn, err := getOrCreateConnection(startTCP(), false, false)
	if err != nil {
		t.Fatalf("create TCP connection: %v", err)
	}
	if _, ok := tcpConn.messageConnection.(*appmesh.TCPConnection); !ok {
		t.Fatalf("TCP pool entry carries %T, want *appmesh.TCPConnection", tcpConn.messageConnection)
	}

	if wssConn.key != wssPoolKey(wssHostPort) {
		t.Fatalf("WSS pool key = %q, want %q", wssConn.key, wssPoolKey(wssHostPort))
	}
	if tcpConn.key != "tcp://"+tcpAddr.String() {
		t.Fatalf("TCP pool key = %q, want %q", tcpConn.key, "tcp://"+tcpAddr.String())
	}
	if wssConn == tcpConn {
		t.Fatal("both transports were pooled as one connection")
	}

	// Each lookup returns its own pooled entry.
	if again, err := getOrCreateWSSConnection(wssHostPort, false); err != nil || again != wssConn {
		t.Fatalf("WSS lookup = %v (err %v), want the pooled entry", again, err)
	}
	if again, err := getOrCreateConnection(tcpAddr, false, false); err != nil || again != tcpConn {
		t.Fatalf("TCP lookup = %v (err %v), want the pooled entry", again, err)
	}

	// Dropping the WSS fallback must not disturb the TCP entry.
	deleteConnection(wssConn)
	if _, ok := remoteConnections.Load(wssPoolKey(wssHostPort)); ok {
		t.Fatal("WSS entry still pooled after deleteConnection")
	}
	if again, err := getOrCreateConnection(tcpAddr, false, false); err != nil || again != tcpConn {
		t.Fatalf("TCP lookup after WSS delete = %v (err %v), want the pooled entry", again, err)
	}
}

// TestGetLocalConnectionPrefersTCPAndFallsBackToWSS pins that WSS carries requests only while the TCP port is closed.
func TestGetLocalConnectionPrefersTCPAndFallsBackToWSS(t *testing.T) {
	resetConnectionState(t)
	wssHostPort, _, _ := newWSSTestServer(t)
	tcpAddr, startTCP := freeTCPAddr(t)
	localWSSAddr, localTCPAddr = wssHostPort, tcpAddr

	fallback, err := getLocalConnection()
	if err != nil {
		t.Fatalf("fall back to WSS: %v", err)
	}
	if fallback.key != wssPoolKey(wssHostPort) {
		t.Fatalf("connection = %q, want the WSS fallback %q", fallback.key, wssPoolKey(wssHostPort))
	}
	if again, err := getLocalConnection(); err != nil || again != fallback {
		t.Fatalf("second lookup = %v (err %v), want the pooled WSS fallback", again, err)
	}

	startTCP()
	recovered, err := getLocalConnection()
	if err != nil {
		t.Fatalf("reconnect over TCP: %v", err)
	}
	if recovered.key != "tcp://"+tcpAddr.String() {
		t.Fatalf("connection after TCP recovery = %q, want %q", recovered.key, "tcp://"+tcpAddr.String())
	}
}

// TestTCPRecoveryReclaimsWSSFallback pins that a recovered TCP port retires the WSS fallback and its keepalive.
func TestTCPRecoveryReclaimsWSSFallback(t *testing.T) {
	resetConnectionState(t)
	wssPingInterval = 5 * time.Millisecond
	wssHostPort, pingCount, sessionClosed := newWSSTestServer(t)
	tcpAddr, startTCP := freeTCPAddr(t)
	localWSSAddr, localTCPAddr = wssHostPort, tcpAddr

	fallback, err := getLocalConnection()
	if err != nil {
		t.Fatalf("fall back to WSS: %v", err)
	}
	if fallback.key != wssPoolKey(wssHostPort) {
		t.Fatalf("connection = %q, want the WSS fallback", fallback.key)
	}
	waitFor(t, "the WSS keepalive ping", func() bool { return pingCount() > 0 })

	startTCP()
	if _, err := getLocalConnection(); err != nil {
		t.Fatalf("reconnect over TCP: %v", err)
	}

	if _, ok := remoteConnections.Load(wssPoolKey(wssHostPort)); ok {
		t.Fatal("WSS fallback is still pooled after TCP recovery")
	}
	wss := fallback.messageConnection.(*appmesh.WSSConnection)
	waitFor(t, "the reclaimed fallback socket to close", func() bool { return !wss.Connected() })
	select {
	case <-sessionClosed:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon-side WSS session is still open after TCP recovery")
	}

	// Let a tick already in flight finish before sampling.
	time.Sleep(10 * wssPingInterval)
	stopped := pingCount()
	time.Sleep(20 * wssPingInterval)
	if got := pingCount(); got != stopped {
		t.Fatalf("WSS keepalive kept pinging after reclaim: %d -> %d", stopped, got)
	}
}

// TestReclaimWaitsForInFlightRequests pins that a reclaimed fallback keeps
// serving the requests it already accepted; the socket closes only after they finish.
func TestReclaimWaitsForInFlightRequests(t *testing.T) {
	resetConnectionState(t)
	wssHostPort, _, _ := newWSSTestServer(t)
	tcpAddr, startTCP := freeTCPAddr(t)
	localWSSAddr, localTCPAddr = wssHostPort, tcpAddr

	fallback, err := getLocalConnection()
	if err != nil {
		t.Fatalf("fall back to WSS: %v", err)
	}

	// Hold one request in flight on the fallback.
	respCh := fallback.registerPendingResp("uuid-in-flight")

	startTCP()
	if _, err := getLocalConnection(); err != nil {
		t.Fatalf("reconnect over TCP: %v", err)
	}
	if _, ok := remoteConnections.Load(wssPoolKey(wssHostPort)); ok {
		t.Fatal("WSS fallback is still pooled after TCP recovery")
	}

	// The pool entry is gone, but the socket survives the in-flight request.
	time.Sleep(50 * time.Millisecond)
	wss := fallback.messageConnection.(*appmesh.WSSConnection)
	if !wss.Connected() {
		t.Fatal("reclaim closed the fallback while a request was in flight")
	}

	// The request finishes; the fallback then closes.
	fallback.unregisterPendingResp("uuid-in-flight")
	waitFor(t, "the reclaimed fallback to close after the last request", func() bool { return !wss.Connected() })
	_ = respCh
}

// fakeMessageConnection is a transport stand-in for the keepalive test.
type fakeMessageConnection struct{}

func (f *fakeMessageConnection) ReadMessage() ([]byte, error) { return nil, io.EOF }

func (f *fakeMessageConnection) SendMessage(context.Context, []byte) error { return nil }

func (f *fakeMessageConnection) Close() {}

func (f *fakeMessageConnection) ClientAddress() string { return "fake" }

// TestKeepWSSAliveStopsOnClose pins that the keepalive stops on the close signal, not on a ping error.
func TestKeepWSSAliveStopsOnClose(t *testing.T) {
	resetConnectionState(t)

	var pings int64
	ping := func() error {
		atomic.AddInt64(&pings, 1)
		return nil
	}

	conn := &Connection{
		key:               wssPoolKey("127.0.0.1:1"),
		messageConnection: &fakeMessageConnection{},
		pending:           make(map[string]chan *Response),
		closed:            make(chan struct{}),
	}

	done := make(chan struct{})
	go func() {
		keepWSSAlive(conn, &url.URL{Scheme: "wss", Host: "127.0.0.1:1"}, conn.key, time.Millisecond, ping)
		close(done)
	}()
	waitFor(t, "a keepalive ping", func() bool { return atomic.LoadInt64(&pings) > 0 })

	conn.close()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keepalive goroutine still running after the connection closed")
	}

	stopped := atomic.LoadInt64(&pings)
	time.Sleep(20 * time.Millisecond)
	if got := atomic.LoadInt64(&pings); got != stopped {
		t.Fatalf("keepalive kept pinging after close: %d -> %d", stopped, got)
	}
}
