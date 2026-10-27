package appmesh

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

// Option.ForwardTo must reach every transport, not only HTTP: NewTCPClient and
// NewWSSClient hand a prebuilt requester to the shared constructor, and dropping
// the option there made workflow jobs with node_label run on the local node while
// the run record named the remote one.
func TestConstructorKeepsForwardToForEveryTransport(t *testing.T) {
	base := url.URL{Scheme: "https", Host: "gateway.local:6059"}
	requesters := map[string]Requester{
		"tcp":  &TCPRequester{TCPConnection: NewTCPConnection(), baseURL: base},
		"wss":  &WSSRequester{WSSConnection: NewWSSConnection(), baseURL: base},
		"http": nil,
	}
	for name, r := range requesters {
		c, err := newHTTPClientWithRequester(Option{ForwardTo: "appmesh_slave1", InsecureSkipVerify: true}, r)
		require.NoError(t, err, name)
		assert.Equal(t, "appmesh_slave1", c.getForwardTo(), "%s requester must carry Option.ForwardTo", name)
	}
}

// A WSS file transfer is two hops: a control request over the WebSocket and a
// data request over HTTP(S). Both must carry the forwarding target, otherwise the
// gateway stores or serves the file itself while reporting success.
func TestWSSFileDataChannelCarriesForwardTarget(t *testing.T) {
	var mu sync.Mutex
	controlTargets := map[string]string{} // control request URI -> X-Target-Host
	dataTargets := map[string]string{}    // data request path -> X-Target-Host
	upgrader := websocket.Upgrader{Subprotocols: []string{"appmesh-ws"}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !websocket.IsWebSocketUpgrade(r) {
			mu.Lock()
			dataTargets[r.URL.Path] = r.Header.Get(headerTargetHost)
			mu.Unlock()
			_, _ = w.Write([]byte("file-bytes"))
			return
		}
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
			resp := &Response{RequestURI: "/reply", HTTPStatus: http.StatusOK, Body: []byte("{}"),
				Headers: map[string]string{}}
			if err := msgpack.Unmarshal(data, &sent); err == nil {
				resp.UUID = sent.UUID
				mu.Lock()
				controlTargets[sent.RequestURI] = sent.Headers[headerTargetHost]
				mu.Unlock()
			}
			buf, err := resp.Serialize()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	u, err := url.Parse("ws://" + srv.Listener.Addr().String())
	require.NoError(t, err)
	wssReq := &WSSRequester{WSSConnection: NewWSSConnection(), baseURL: *u}
	defer wssReq.Close()
	c := &AppMeshClientWSS{AppMeshClient: &AppMeshClient{req: wssReq}, wssReq: wssReq}
	c.SetToken("token")
	c.updateForwardTo("appmesh_slave1")

	dir := t.TempDir()
	local := filepath.Join(dir, "got.txt")
	require.NoError(t, c.DownloadFile("/tmp/remote.txt", local, false))
	got, err := os.ReadFile(local)
	require.NoError(t, err)
	assert.Equal(t, "file-bytes", string(got))

	src := filepath.Join(dir, "put.txt")
	require.NoError(t, os.WriteFile(src, []byte("payload"), 0o600))
	require.NoError(t, c.UploadFile(src, "/tmp/remote-put.txt", false))

	want := "appmesh_slave1" // sent as given: the server resolves its own service port
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, want, controlTargets[restPathDownload], "download control request")
	assert.Equal(t, want, controlTargets[restPathUpload], "upload control request")
	assert.Equal(t, want, dataTargets["/appmesh/file/download/ws"], "download data request")
	assert.Equal(t, want, dataTargets["/appmesh/file/upload/ws"], "upload data request")
}
