package appmesh

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAppmeshWSSLogin(t *testing.T) {
	// Skip before dialing so offline runs skip instead of failing on connect.
	token := requireBearerToken(t)
	client, err := NewWSSClient(Option{
		AppMeshURI:         "https://127.0.0.1:6063",
		InsecureSkipVerify: true,
		JWTToken:           token,
	})
	require.NoError(t, err)
	defer client.CloseConnection()

	apps, err := client.ListApps()
	require.NoError(t, err)
	t.Logf("WSS ListApps count: %d", len(apps))

	tags, err := client.ListLabels()
	require.NoError(t, err)
	t.Logf("WSS labels: %v", tags)

	metrics, err := client.GetMetrics()
	require.NoError(t, err)
	require.NotEmpty(t, metrics)
	t.Logf("WSS metrics length: %d", len(metrics))

	res, err := client.GetHostResources()
	require.NoError(t, err)
	require.NotEmpty(t, res)

}

func TestAppmeshWSSOperations(t *testing.T) {
	// Skip before dialing so offline runs skip instead of failing on connect.
	token := requireBearerToken(t)
	client, err := NewWSSClient(Option{
		AppMeshURI:         "https://127.0.0.1:6063",
		InsecureSkipVerify: true,
		JWTToken:           token,
	})
	require.NoError(t, err)
	defer client.CloseConnection()

	// 2. RunAppSync - echo command, verify exit code 0
	cmd := "echo hello_wss"
	shellMode := true
	runApp := Application{
		Name:      "go-wss-sync-test",
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	exitCode, output, err := client.RunAppSync(runApp, 10, 15)
	require.NoError(t, err, "WSS RunAppSync should succeed")
	require.Equal(t, 0, exitCode, "WSS RunAppSync exit code should be 0")
	require.Contains(t, output, "hello_wss", "WSS RunAppSync output should contain echoed text")
	t.Logf("WSS RunAppSync output: %q, exit: %d", output, exitCode)

	// 3. AddApp + DisableApp + EnableApp + DeleteApp
	const testAppName = "go-wss-lifecycle-test"
	appCmd := fmt.Sprintf("echo wss-lifecycle-%s", testAppName)
	newApp := Application{
		Name:    testAppName,
		Command: &appCmd,
	}
	// ensure clean state at the start and on any exit
	_, _ = client.DeleteApp(testAppName)
	defer func() {
		_, _ = client.DeleteApp(testAppName)
	}()

	addedApp, err := client.AddApp(newApp)
	require.NoError(t, err, "WSS AddApp should succeed")
	require.NotNil(t, addedApp, "WSS AddApp should return the created app")
	require.Equal(t, testAppName, addedApp.Name, "WSS AddApp returned app should have correct name")
	t.Logf("WSS AddApp: %s enabled=%t", addedApp.Name, addedApp.Enabled)

	disabled, err := client.DisableApp(testAppName)
	require.NoError(t, err, "WSS DisableApp should succeed")
	require.True(t, disabled, "WSS DisableApp should return true")

	enabled, err := client.EnableApp(testAppName)
	require.NoError(t, err, "WSS EnableApp should succeed")
	require.True(t, enabled, "WSS EnableApp should return true")

	removed, err := client.DeleteApp(testAppName)
	require.NoError(t, err, "WSS DeleteApp should succeed")
	require.True(t, removed, "WSS DeleteApp should return true")

	// 4. GetConfig
	cfg, err := client.GetConfig()
	require.NoError(t, err, "WSS GetConfig should succeed")
	require.NotEmpty(t, cfg, "WSS GetConfig should return non-empty data")
	t.Logf("WSS GetConfig keys: %d", len(cfg))

	// 5. Current principal
	self, err := client.GetCurrentUser()
	require.NoError(t, err, "WSS GetCurrentUser should succeed")
	require.NotEmpty(t, self, "WSS GetCurrentUser should return non-empty data")
	t.Logf("WSS GetCurrentUser: %v", self)

}

// TestWSSUploadSendsFileAttributesOnDataChannel pins that the streaming upload
// data channel carries the POSIX attribute headers: the daemon applies them
// from the data-channel request, not from the control precheck.
func TestWSSUploadSendsFileAttributesOnDataChannel(t *testing.T) {
	upgrader := websocket.Upgrader{Subprotocols: []string{"appmesh-ws"}}
	headersSeen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				mt, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if mt != websocket.BinaryMessage {
					continue
				}
				var sent Request
				resp := &Response{HTTPStatus: http.StatusCreated, Body: []byte(`{"status":"ok"}`),
					Headers: map[string]string{}}
				if err := msgpack.Unmarshal(data, &sent); err == nil {
					resp.UUID = sent.UUID
				}
				buf, err := resp.Serialize()
				if err != nil {
					return
				}
				if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
					return
				}
			}
		}
		if r.Method != http.MethodPost || r.URL.Path != "/appmesh/file/upload/ws" {
			http.NotFound(w, r)
			return
		}
		headersSeen <- r.Header.Clone()
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	t.Cleanup(srv.Close)

	client, err := NewWSSClient(Option{AppMeshURI: srv.URL, InsecureSkipVerify: true, JWTToken: "test-token"})
	require.NoError(t, err)
	defer client.CloseConnection()

	local := filepath.Join(t.TempDir(), "attrs.bin")
	require.NoError(t, os.WriteFile(local, []byte("payload"), 0o640))
	expected, err := fileAttributes(local)
	require.NoError(t, err)
	require.NotEmpty(t, expected)

	require.NoError(t, client.UploadFileContext(context.Background(), local, "/tmp/attrs.bin", true))
	select {
	case got := <-headersSeen:
		for key, value := range expected {
			require.Equal(t, value, got.Get(key), "data-channel header %s", key)
		}
		require.Equal(t, escapeRemoteFilePath("/tmp/attrs.bin"), got.Get(headerFilePath))
	case <-time.After(5 * time.Second):
		t.Fatal("the upload data channel was never reached")
	}
}
