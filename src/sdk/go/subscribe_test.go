package appmesh

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppEventDeserialization(t *testing.T) {
	raw := `{"subscription_id":"sub123","event_type":"EXIT","app_name":"myapp","timestamp":1714000000,"sequence":42,"data":{"exit_code":1,"pid":12345}}`
	var event AppEvent
	err := json.Unmarshal([]byte(raw), &event)
	require.NoError(t, err)
	assert.Equal(t, "sub123", event.SubscriptionID)
	assert.Equal(t, "EXIT", event.EventType)
	assert.Equal(t, "myapp", event.AppName)
	assert.Equal(t, int64(1714000000), event.Timestamp)
	assert.Equal(t, uint64(42), event.Sequence)
	assert.NotEmpty(t, event.Data)
}

func TestMessageDemuxerRouting(t *testing.T) {
	// Create a channel-based mock reader
	msgCh := make(chan []byte, 10)
	readFn := func() ([]byte, error) {
		data, ok := <-msgCh
		if !ok {
			return nil, fmt.Errorf("closed")
		}
		return data, nil
	}

	demuxer := newMessageDemuxer(readFn)
	demuxer.start()
	defer demuxer.stop()

	// Test: event callback routing
	var receivedEvent AppEvent
	var wg sync.WaitGroup
	wg.Add(1)
	demuxer.registerEventCallback("sub-test", func(event AppEvent) {
		if event.EventType == EventTypeDisconnected {
			return // stop() broadcasts Disconnected; only count the real event
		}
		receivedEvent = event
		wg.Done()
	})

	// Simulate a server-push event message
	eventBody := `{"subscription_id":"sub-test","event_type":"START","app_name":"test-app","timestamp":1714000000,"sequence":1,"data":{"pid":9999}}`
	resp := &Response{
		UUID:        "evt-uuid-1",
		RequestUri:  EVENT_URI,
		HttpStatus:  200,
		BodyMsgType: "application/json",
		Body:        []byte(eventBody),
		Headers:     map[string]string{"X-Subscription-Id": "sub-test"},
	}
	buf, err := resp.Serialize()
	require.NoError(t, err)
	msgCh <- buf

	// Wait for event delivery
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		assert.Equal(t, "sub-test", receivedEvent.SubscriptionID)
		assert.Equal(t, "START", receivedEvent.EventType)
		assert.Equal(t, "test-app", receivedEvent.AppName)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event callback")
	}
}

// Conformance: S7 (partial) — pending waiter registered before the response
// arrives is routed by UUID; see docs/source/SDKContract.md.
func TestMessageDemuxerRequestResponse(t *testing.T) {
	msgCh := make(chan []byte, 10)
	readFn := func() ([]byte, error) {
		data, ok := <-msgCh
		if !ok {
			return nil, fmt.Errorf("closed")
		}
		return data, nil
	}

	demuxer := newMessageDemuxer(readFn)
	demuxer.start()
	defer demuxer.stop()

	// Register a pending request
	reqUUID := "req-uuid-123"
	ch := demuxer.registerRequest(reqUUID)

	// Simulate server response for this request
	resp := &Response{
		UUID:       reqUUID,
		RequestUri: "/appmesh/app/test",
		HttpStatus: 200,
		Body:       []byte(`{"name":"test"}`),
		Headers:    map[string]string{},
	}
	buf, err := resp.Serialize()
	require.NoError(t, err)
	msgCh <- buf

	// Should receive on the channel
	select {
	case result := <-ch:
		require.NotNil(t, result)
		assert.Equal(t, reqUUID, result.UUID)
		assert.Equal(t, 200, result.HttpStatus)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for response")
	}
}

// Conformance: S2 (demuxer) — transport EOF wakes pending request waiters
// (closed channel) and broadcasts EventTypeDisconnected to every registered
// event callback; see docs/source/SDKContract.md.
func TestMessageDemuxerDisconnectBroadcast(t *testing.T) {
	msgCh := make(chan []byte, 10)
	readFn := func() ([]byte, error) {
		data, ok := <-msgCh
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		return data, nil
	}

	demuxer := newMessageDemuxer(readFn)
	demuxer.start()

	eventCh := make(chan AppEvent, 1)
	demuxer.registerEventCallback("sub-disc", func(event AppEvent) {
		eventCh <- event
	})
	pending := demuxer.registerRequest("req-disc")

	close(msgCh) // transport EOF

	select {
	case event := <-eventCh:
		assert.Equal(t, EventTypeDisconnected, event.EventType)
		assert.Equal(t, "sub-disc", event.SubscriptionID)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for disconnect broadcast")
	}

	select {
	case resp, ok := <-pending:
		assert.Nil(t, resp)
		assert.False(t, ok, "pending channel should be closed on disconnect")
	case <-time.After(2 * time.Second):
		t.Fatal("pending waiter not woken on disconnect")
	}
}

// fakeWaitRequester scripts the request/response half of WaitForAsyncRun while
// a real MessageDemuxer (fed through msgCh) delivers server-push events.
type fakeWaitRequester struct {
	demuxer *MessageDemuxer
}

func (f *fakeWaitRequester) Send(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	return f.SendContext(context.Background(), method, apiPath, queries, headers, body)
}

func (f *fakeWaitRequester) SendContext(ctx context.Context, method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader) (int, []byte, http.Header, error) {
	switch {
	case method == http.MethodPost && strings.HasSuffix(apiPath, "/subscribe"):
		return http.StatusOK, []byte(`{"subscription_id":"sub-wait","app_name":"waitapp","events":["STDOUT","EXIT","REMOVED"]}`), http.Header{}, nil
	default:
		// Backfill output (no data, process still running), unsubscribe, delete.
		return http.StatusOK, []byte(""), http.Header{}, nil
	}
}

func (f *fakeWaitRequester) Close()                      {}
func (f *fakeWaitRequester) handleTokenUpdate(string)    {}
func (f *fakeWaitRequester) setToken(string)             {}
func (f *fakeWaitRequester) getAccessToken() string      { return "" }
func (f *fakeWaitRequester) setForwardTo(string)         {}
func (f *fakeWaitRequester) getForwardTo() string        { return "" }
func (f *fakeWaitRequester) enableDemuxer()              {}
func (f *fakeWaitRequester) getDemuxer() *MessageDemuxer { return f.demuxer }

// newWaitHarness wires an AppMeshClient to a scripted requester and a live
// demuxer whose transport is the returned channel (close = EOF).
func newWaitHarness() (*AppMeshClient, chan []byte) {
	msgCh := make(chan []byte, 10)
	readFn := func() ([]byte, error) {
		data, ok := <-msgCh
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		return data, nil
	}
	demuxer := newMessageDemuxer(readFn)
	demuxer.start()
	return &AppMeshClient{req: &fakeWaitRequester{demuxer: demuxer}}, msgCh
}

// pushEvent frames an event push for subID onto the mock transport.
func pushEvent(t *testing.T, msgCh chan []byte, subID string, eventType string, data string) {
	t.Helper()
	body := fmt.Sprintf(`{"subscription_id":"%s","event_type":"%s","app_name":"waitapp","timestamp":0,"sequence":1,"data":%s}`, subID, eventType, data)
	resp := &Response{
		UUID:        "evt-" + eventType,
		RequestUri:  EVENT_URI,
		HttpStatus:  200,
		BodyMsgType: "application/json",
		Body:        []byte(body),
	}
	buf, err := resp.Serialize()
	require.NoError(t, err)
	msgCh <- buf
}

// Conformance: S6 — a negative exit code (signal kill, e.g. -2 = SIGINT) is
// returned as the exit code, never conflated with an error sentinel; see
// docs/source/SDKContract.md.
func TestWaitForAsyncRunNegativeExitCode(t *testing.T) {
	client, msgCh := newWaitHarness()

	// The pre-registration buffer makes this safe even if the event is read
	// before WaitForAsyncRun registers its callback.
	pushEvent(t, msgCh, "sub-wait", "EXIT", `{"exit_code":-2}`)

	code, err := client.WaitForAsyncRun(context.Background(), &AppRun{AppName: "waitapp", ProcUid: "proc-1"}, nil, 5*time.Second)
	require.NoError(t, err)
	require.NotNil(t, code)
	assert.Equal(t, -2, *code)
}

// Conformance: S2 — transport disconnect mid-WaitForAsyncRun unblocks the wait
// promptly with ErrTransportDisconnected instead of hanging; see
// docs/source/SDKContract.md.
func TestWaitForAsyncRunDisconnectUnblocks(t *testing.T) {
	client, msgCh := newWaitHarness()

	go func() {
		// Let the wait subscribe and block first, then kill the transport.
		time.Sleep(100 * time.Millisecond)
		close(msgCh)
	}()

	start := time.Now()
	code, err := client.WaitForAsyncRun(context.Background(), &AppRun{AppName: "waitapp", ProcUid: "proc-1"}, nil, 30*time.Second)
	require.ErrorIs(t, err, ErrTransportDisconnected)
	assert.Nil(t, code)
	assert.Less(t, time.Since(start), 10*time.Second, "disconnect must unblock the wait, not run into the timeout")
}

func TestSubscribeOptionPath(t *testing.T) {
	// Test: specific app path
	opt := SubscribeOption{AppName: "myapp", Events: []string{"START", "STDOUT"}}
	assert.Equal(t, "myapp", opt.AppName)
	assert.Len(t, opt.Events, 2)

	// Test: wildcard path
	opt2 := SubscribeOption{AppName: "*"}
	assert.Equal(t, "*", opt2.AppName)

	// Test: empty means wildcard
	opt3 := SubscribeOption{}
	assert.Empty(t, opt3.AppName)
}

func TestResponseDeserialize(t *testing.T) {
	resp := &Response{
		UUID:        "test-uuid",
		RequestUri:  "/appmesh/event",
		HttpStatus:  200,
		BodyMsgType: "application/json",
		Body:        []byte(`{"key":"value"}`),
		Headers:     map[string]string{"X-Test": "yes"},
	}
	buf, err := resp.Serialize()
	require.NoError(t, err)
	require.NotEmpty(t, buf)

	var decoded Response
	err = decoded.Deserialize(buf)
	require.NoError(t, err)
	assert.Equal(t, "test-uuid", decoded.UUID)
	assert.Equal(t, "/appmesh/event", decoded.RequestUri)
	assert.Equal(t, 200, decoded.HttpStatus)
	assert.Equal(t, "yes", decoded.Headers["X-Test"])
}
