package appmesh

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAppmeshTCPFile(t *testing.T) {
	// Skip before dialing so offline runs skip instead of failing on connect.
	token := requireBearerToken(t)
	client, err := NewTCPClient(Option{InsecureSkipVerify: true, JWTToken: token})
	require.Nil(t, err)

	// With FileAllowedBaseDir unset the file API jails transfers to the daemon
	// work tree, and inside it only work/tmp is exchangeable: upload to that
	// scratch, then download back and compare.
	var scratch string
	if runtime.GOOS == "windows" {
		scratch = `C:\local\appmesh\work\tmp`
	} else {
		scratch = "/opt/appmesh/work/tmp"
	}
	localFile := "go_file_test"
	tempFile := filepath.Join(os.TempDir(), "go_file_test.copy")
	remotePath := filepath.Join(scratch, "go_file_test.txt")

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	require.Nil(t, os.WriteFile(localFile, []byte("go_file_roundtrip"), 0o644))

	require.Nil(t, client.UploadFile(localFile, remotePath, true))
	require.Nil(t, client.DownloadFile(remotePath, tempFile, true))
	content, err := os.ReadFile(tempFile)
	require.Nil(t, err)
	require.Equal(t, "go_file_roundtrip", string(content))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}

func TestAppmeshTCPOperations(t *testing.T) {
	// Skip before dialing so offline runs skip instead of failing on connect.
	token := requireBearerToken(t)
	client, err := NewTCPClient(Option{InsecureSkipVerify: true, JWTToken: token})
	require.NoError(t, err)
	defer client.CloseConnection()

	// 2. ListApps - verify count > 0
	apps, err := client.ListApps()
	require.NoError(t, err, "TCP ListApps should succeed")
	require.Greater(t, len(apps), 0, "TCP ListApps should return at least one app")
	t.Logf("TCP ListApps count: %d", len(apps))

	// 3. RunAppSync - echo command, verify exit code 0
	cmd := "echo hello_tcp"
	shellMode := true
	runApp := Application{
		Name:      "go-tcp-sync-test",
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	exitCode, output, err := client.RunAppSync(runApp, 10, 15)
	require.NoError(t, err, "TCP RunAppSync should succeed")
	require.Equal(t, 0, exitCode, "TCP RunAppSync exit code should be 0")
	require.Contains(t, output, "hello_tcp", "TCP RunAppSync output should contain echoed text")
	t.Logf("TCP RunAppSync output: %q, exit: %d", output, exitCode)

	// 4. GetHostResources - verify non-empty
	res, err := client.GetHostResources()
	require.NoError(t, err, "TCP GetHostResources should succeed")
	require.NotEmpty(t, res, "TCP GetHostResources should return non-empty data")
	t.Logf("TCP GetHostResources keys: %d", len(res))

	// 5. GetConfig - verify non-empty
	cfg, err := client.GetConfig()
	require.NoError(t, err, "TCP GetConfig should succeed")
	require.NotEmpty(t, cfg, "TCP GetConfig should return non-empty data")
	t.Logf("TCP GetConfig keys: %d", len(cfg))

	// 6. AddLabel / ListLabels / DeleteLabel
	const tagName = "go-tcp-test-tag"
	const tagValue = "tcp-test-value"

	added, err := client.AddLabel(tagName, tagValue)
	require.NoError(t, err, "TCP AddLabel should succeed")
	require.True(t, added, "TCP AddLabel should return true")

	tags, err := client.ListLabels()
	require.NoError(t, err, "TCP ListLabels should succeed")
	require.Equal(t, tagValue, tags[tagName], "TCP ListLabels should contain the added label with correct value")
	t.Logf("TCP ListLabels: %v", tags)

	deleted, err := client.DeleteLabel(tagName)
	require.NoError(t, err, "TCP DeleteLabel should succeed")
	require.True(t, deleted, "TCP DeleteLabel should return true")

	tagsAfter, err := client.ListLabels()
	require.NoError(t, err, "TCP ListLabels after delete should succeed")
	_, stillPresent := tagsAfter[tagName]
	require.False(t, stillPresent, "TCP label should be absent after deletion")

}

// startPlainFrameListener stands in for a daemon frame port that answers
// plaintext (SSL.SSLEnabled=false) by accepting and immediately dropping TCP
// connections: enough for the SDK to distinguish a plain dial (connect OK)
// from a TLS dial (handshake failure).
func startPlainFrameListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// TestNewTCPClientPlainTransportSelection pins the dial-mode selection: with
// PlainTransport the client connects to a plaintext frame port and reconnects
// in plain mode after the connection drops, while the default TLS mode fails
// its handshake against the same plaintext port.
func TestNewTCPClientPlainTransportSelection(t *testing.T) {
	addr := startPlainFrameListener(t)

	client, err := NewTCPClient(Option{AppMeshURI: addr, PlainTransport: true})
	require.NoError(t, err, "plain dial against a plaintext frame port must connect")
	require.True(t, client.tcpReq.Connected(), "plain client must report connected")
	// The SSE side channel follows the transport: a plaintext daemon serves
	// plaintext REST too.
	require.Equal(t, "http", client.tcpReq.restBase.Scheme, "SSE side channel scheme")

	client.CloseConnection()
	require.False(t, client.tcpReq.Connected(), "connection must drop after CloseConnection")
	require.NoError(t, client.tcpReq.ensureConnected(), "reconnect must redial in plain mode")
	require.True(t, client.tcpReq.Connected(), "plain reconnect must succeed")
	client.CloseConnection()

	// Default mode dials TLS, so the same plaintext port fails the handshake.
	_, err = NewTCPClient(Option{AppMeshURI: addr, InsecureSkipVerify: true})
	require.Error(t, err, "TLS dial against a plaintext port must fail its handshake")
}

// startStaleFirstFrameServer accepts plaintext frames and records every
// request. The first accepted connection closes right after reading its request
// without replying (daemon idle-close); later connections answer 200.
func startStaleFirstFrameServer(t *testing.T) (string, func() []Request) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	conns := 0
	var seen []Request
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns++
			first := conns == 1
			mu.Unlock()
			go func(conn net.Conn, first bool) {
				defer conn.Close()
				frame := readPipeFrame(conn)
				if frame == nil {
					return
				}
				var sent Request
				if err := msgpack.Unmarshal(frame, &sent); err != nil {
					return
				}
				mu.Lock()
				seen = append(seen, sent)
				mu.Unlock()
				if first {
					return
				}
				resp := &Response{UUID: sent.UUID, RequestURI: sent.RequestURI, HTTPStatus: http.StatusOK,
					Body: []byte("{}"), Headers: map[string]string{}}
				buf, err := resp.Serialize()
				if err != nil {
					return
				}
				writePipeFrame(conn, buf)
			}(conn, first)
		}
	}()
	return ln.Addr().String(), func() []Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]Request(nil), seen...)
	}
}

// TestTCPRequesterRetriesIdempotentOnStaleConnection pins the direct-TCP
// recovery rule: a GET that found its pooled connection closed by the daemon is
// replayed once on a fresh connection.
func TestTCPRequesterRetriesIdempotentOnStaleConnection(t *testing.T) {
	addr, requests := startStaleFirstFrameServer(t)
	client, err := NewTCPClient(Option{AppMeshURI: addr, PlainTransport: true, JWTToken: "test-token"})
	require.NoError(t, err)
	defer client.CloseConnection()

	cfg, err := client.GetConfig()
	require.NoError(t, err, "the retried GET must succeed on the fresh connection")
	require.NotNil(t, cfg)

	seen := requests()
	require.Len(t, seen, 2, "a stale GET must be retried exactly once")
	require.Equal(t, http.MethodGet, seen[0].HTTPMethod)
	require.Equal(t, http.MethodGet, seen[1].HTTPMethod)
	require.NotEqual(t, seen[0].UUID, seen[1].UUID, "the retry must use a fresh request UUID")
}

// TestTCPRequesterDoesNotReplayNonIdempotent pins the other half of the rule: a
// POST that may already have executed is never replayed.
func TestTCPRequesterDoesNotReplayNonIdempotent(t *testing.T) {
	addr, requests := startStaleFirstFrameServer(t)
	client, err := NewTCPClient(Option{AppMeshURI: addr, PlainTransport: true, JWTToken: "test-token"})
	require.NoError(t, err)
	defer client.CloseConnection()

	_, err = client.SetConfig(map[string]interface{}{
		"BaseConfig": map[string]interface{}{"LogLevel": "INFO"},
	})
	require.Error(t, err, "the lost POST reply must surface as an error")

	seen := requests()
	require.Len(t, seen, 1, "a POST must never be replayed")
	require.Equal(t, http.MethodPost, seen[0].HTTPMethod)
}
