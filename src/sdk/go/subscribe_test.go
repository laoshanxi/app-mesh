package appmesh

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppEventDeserialization(t *testing.T) {
	raw := `{"subscription_id":"sub123","event_type":"process_exit","app_name":"myapp","timestamp":1714000000,"sequence":42,"data":{"exit_code":1,"pid":12345}}`
	var event AppEvent
	err := json.Unmarshal([]byte(raw), &event)
	require.NoError(t, err)
	assert.Equal(t, "sub123", event.SubscriptionID)
	assert.Equal(t, "process_exit", event.EventType)
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
		receivedEvent = event
		wg.Done()
	})

	// Simulate a server-push event message
	eventBody := `{"subscription_id":"sub-test","event_type":"process_start","app_name":"test-app","timestamp":1714000000,"sequence":1,"data":{"pid":9999}}`
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
		assert.Equal(t, "process_start", receivedEvent.EventType)
		assert.Equal(t, "test-app", receivedEvent.AppName)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event callback")
	}
}

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

func TestSubscribeOptionPath(t *testing.T) {
	// Test: specific app path
	opt := SubscribeOption{AppName: "myapp", Events: []string{"process_start", "stdout"}}
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
