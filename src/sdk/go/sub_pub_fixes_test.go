package appmesh

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

// newWSEchoServer runs a local WebSocket server that answers every binary
// message with a serialized 200 Response (no frame header: WSS messages are
// their own frame).
func newWSEchoServer(t *testing.T, upgrader websocket.Upgrader, connections *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		atomic.AddInt32(connections, 1)
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
}

// A file transfer must be rejected while the event demuxer owns the read side:
// the demuxer read loop would steal the raw (non-msgpack) chunk frames and
// corrupt the transfer (mirrors the Python SDK's _ensure_no_active_demuxer).
func TestFileTransferRejectedWhileDemuxerActive(t *testing.T) {
	tcpReq := &TCPRequester{TCPConnection: NewTCPConnection()}
	blockCh := make(chan []byte) // reader blocks until test ends
	tcpReq.demuxer = newMessageDemuxer(func() ([]byte, error) { return <-blockCh, nil })
	tcpReq.demuxer.start()
	defer func() {
		tcpReq.demuxer.stop()
		close(blockCh)
	}()

	c := &AppMeshClientTCP{AppMeshClient: &AppMeshClient{}, tcpReq: tcpReq}

	err := c.DownloadFileContext(context.Background(), "/remote/file", t.TempDir()+"/local", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	err = c.UploadFileContext(context.Background(), t.TempDir()+"/local", "/remote/file", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")

	// Without an active demuxer the guard passes (the request itself would then
	// proceed over the transport).
	c2 := &AppMeshClientTCP{AppMeshClient: &AppMeshClient{}, tcpReq: &TCPRequester{TCPConnection: NewTCPConnection()}}
	assert.NoError(t, c2.ensureNoActiveDemuxer())
}

// A zero-length frame is not a message: the read loop must skip it silently
// instead of logging it as undecodable (Python parity).
func TestMessageDemuxerSkipsZeroLengthFrames(t *testing.T) {
	logs := make(chan string, 4)
	SetLogger(func(format string, args ...any) { logs <- fmt.Sprintf(format, args...) })
	defer SetLogger(nil)

	msgCh := make(chan []byte, 10)
	defer close(msgCh) // let the readLoop goroutine exit after stop()
	readFn := func() ([]byte, error) {
		data, ok := <-msgCh
		if !ok {
			return nil, io.EOF
		}
		return data, nil
	}
	demuxer := newMessageDemuxer(readFn)
	demuxer.start()
	defer demuxer.stop()

	received := make(chan AppEvent, 1)
	demuxer.registerEventCallback("sub-zero", func(event AppEvent) {
		if event.EventType != EventTypeDisconnected {
			received <- event
		}
	})

	// Zero-length frame first, then a real event.
	msgCh <- []byte{}
	pushEvent(t, msgCh, "sub-zero", "START", `{"pid":1}`)

	select {
	case event := <-received:
		assert.Equal(t, "START", event.EventType)
	case <-time.After(2 * time.Second):
		t.Fatal("event after zero-length frame was not delivered")
	}
	select {
	case msg := <-logs:
		t.Fatalf("zero-length frame must not be logged as undecodable, got: %s", msg)
	default:
	}
}

// A framing error (bad magic) must close the connection: the stream is
// desynchronized, and a later SendMessage must fail fast instead of writing
// into a garbage stream.
func TestTCPConnectionFramingErrorClosesConnection(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	conn := NewTCPConnection()
	conn.muConn.Lock()
	conn.conn = client
	conn.muConn.Unlock()
	require.True(t, conn.Connected())

	// Serve a header with a wrong magic number.
	go func() {
		var header [8]byte
		binary.BigEndian.PutUint32(header[:4], 0xDEADBEEF)
		binary.BigEndian.PutUint32(header[4:], 4)
		_, _ = server.Write(header[:])
		_, _ = server.Write([]byte("junk"))
	}()

	_, err := conn.ReadMessage()
	require.Error(t, err)
	assert.False(t, conn.Connected(), "framing error must close the connection")

	err = conn.SendMessage(context.Background(), []byte("x"))
	require.Error(t, err, "send on the closed connection must fail fast")
}

func readPipeFrame(r io.Reader) []byte {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil
	}
	length := binary.BigEndian.Uint32(header[4:])
	if length == 0 {
		return []byte{}
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil
	}
	return body
}

func writePipeFrame(w io.Writer, payload []byte) {
	var header [8]byte
	binary.BigEndian.PutUint32(header[:4], tcpMessageMagic)
	binary.BigEndian.PutUint32(header[4:], uint32(len(payload)))
	_, _ = w.Write(header[:])
	_, _ = w.Write(payload)
}

// A 401 over TCP triggers exactly one provider refresh and one replay whose
// request carries the refreshed bearer (mirroring the Python SDK and the HTTP
// requester).
func TestTCPRequester401RefreshRetry(t *testing.T) {
	client, server := net.Pipe()
	_ = server.SetDeadline(time.Now().Add(10 * time.Second))
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	defer server.Close()

	conn := NewTCPConnection()
	conn.muConn.Lock()
	conn.conn = client
	conn.muConn.Unlock()

	req := &TCPRequester{TCPConnection: conn, baseURL: url.URL{Scheme: "https", Host: "pipe.local:6059"}}
	provider := &fakeRefreshProvider{token: "stale-token"}
	req.setTokenProvider(provider)

	var authHeaders []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		statuses := []int{http.StatusUnauthorized, http.StatusOK}
		for i, status := range statuses {
			frame := readPipeFrame(server)
			if frame == nil {
				return
			}
			var sent Request
			if err := msgpack.Unmarshal(frame, &sent); err == nil {
				authHeaders = append(authHeaders, sent.Headers["Authorization"])
			}
			resp := &Response{
				UUID:        sent.UUID,
				RequestURI:  "/appmesh/app/test",
				HTTPStatus:  status,
				Body:        []byte("{}"),
				Headers:     map[string]string{},
				BodyMsgType: "application/json",
			}
			buf, err := resp.Serialize()
			if err != nil {
				return
			}
			writePipeFrame(server, buf)
			_ = i
		}
	}()

	status, _, _, err := req.Send(http.MethodGet, "/appmesh/app/test", nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, 1, provider.refreshCount, "401 must trigger exactly one refresh")

	require.Len(t, authHeaders, 2)
	assert.Equal(t, "Bearer stale-token", authHeaders[0])
	assert.Equal(t, "Bearer fresh-token", authHeaders[1], "the replay must carry the refreshed bearer")
}

// A live WSS session is kept across a token rotation: the upgrade pinned the
// session principal, and closing the socket would kill the demuxer reader and
// every active subscription. The refreshed bearer applies on the next natural
// reconnect (Python parity).
func TestWSSRequesterKeepsLiveSessionOnTokenRotation(t *testing.T) {
	var connections int32
	upgrader := websocket.Upgrader{Subprotocols: []string{"appmesh-ws"}}
	srv := newWSEchoServer(t, upgrader, &connections)
	defer srv.Close()

	u, err := url.Parse("http://" + srv.Listener.Addr().String())
	require.NoError(t, err)

	wssReq := &WSSRequester{WSSConnection: NewWSSConnection(), baseURL: *u}
	defer wssReq.Close()
	provider := &fakeRefreshProvider{token: "token-a"}
	wssReq.setTokenProvider(provider)

	status, _, _, err := wssReq.Send(http.MethodGet, "/appmesh/app/test", nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, int32(1), atomic.LoadInt32(&connections))

	// Rotate the provider token: the live session must be reused, not re-dialed.
	provider.mu.Lock()
	provider.token = "token-b"
	provider.mu.Unlock()

	status, _, _, err = wssReq.Send(http.MethodGet, "/appmesh/app/test", nil, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, int32(1), atomic.LoadInt32(&connections), "token rotation must not re-dial a live session")
	assert.Equal(t, 0, provider.refreshCount)
}
