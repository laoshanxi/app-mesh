package appmesh

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

const (
	EVENT_URI = "/appmesh/event"
)

// AppEvent represents a server-push event notification.
type AppEvent struct {
	SubscriptionID string          `json:"subscription_id"`
	EventType      string          `json:"event_type"`
	AppName        string          `json:"app_name"`
	Timestamp      int64           `json:"timestamp"`
	Sequence       uint64          `json:"sequence"`
	Data           json.RawMessage `json:"data"`
}

// EventCallback is invoked when a subscribed event arrives.
type EventCallback func(event AppEvent)

// MessageDemuxer reads messages from a transport connection and routes them
// to either pending request channels (by UUID) or event subscription callbacks.
type MessageDemuxer struct {
	mu       sync.Mutex
	pending  map[string]chan *Response // uuid -> response channel
	eventCBs map[string]EventCallback // subscription_id -> callback
	started  bool
	stopCh   chan struct{}
	readMsg  func() ([]byte, error) // transport-specific read function
}

func newMessageDemuxer(readMsg func() ([]byte, error)) *MessageDemuxer {
	return &MessageDemuxer{
		pending: make(map[string]chan *Response),
		eventCBs: make(map[string]EventCallback),
		stopCh:  make(chan struct{}),
		readMsg: readMsg,
	}
}

// start begins the background reader goroutine.
func (d *MessageDemuxer) start() {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return
	}
	d.started = true
	d.mu.Unlock()

	go d.readLoop()
}

// stop terminates the background reader.
func (d *MessageDemuxer) stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.started {
		return
	}
	close(d.stopCh)
	d.started = false

	// Close all pending channels
	for _, ch := range d.pending {
		close(ch)
	}
	d.pending = make(map[string]chan *Response)
}

// registerRequest creates a channel for a pending request identified by UUID.
func (d *MessageDemuxer) registerRequest(uuid string) chan *Response {
	ch := make(chan *Response, 1)
	d.mu.Lock()
	d.pending[uuid] = ch
	d.mu.Unlock()
	return ch
}

// unregisterRequest removes a pending request channel.
func (d *MessageDemuxer) unregisterRequest(uuid string) {
	d.mu.Lock()
	delete(d.pending, uuid)
	d.mu.Unlock()
}

// registerEventCallback registers a callback for a subscription ID.
func (d *MessageDemuxer) registerEventCallback(subID string, cb EventCallback) {
	d.mu.Lock()
	d.eventCBs[subID] = cb
	d.mu.Unlock()
}

// unregisterEventCallback removes a callback for a subscription ID.
func (d *MessageDemuxer) unregisterEventCallback(subID string) {
	d.mu.Lock()
	delete(d.eventCBs, subID)
	d.mu.Unlock()
}

// readLoop continuously reads messages and routes them.
func (d *MessageDemuxer) readLoop() {
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}

		data, err := d.readMsg()
		if err != nil {
			// Connection error — close all pending
			d.mu.Lock()
			for _, ch := range d.pending {
				close(ch)
			}
			d.pending = make(map[string]chan *Response)
			d.mu.Unlock()
			return
		}

		resp := &Response{}
		if err := resp.Deserialize(data); err != nil {
			continue
		}

		if resp.RequestUri == EVENT_URI {
			d.dispatchEvent(resp)
		} else {
			d.dispatchResponse(resp)
		}
	}
}

// dispatchEvent routes an event push to the matching subscription callback.
func (d *MessageDemuxer) dispatchEvent(resp *Response) {
	var event AppEvent
	if err := json.Unmarshal(resp.Body, &event); err != nil {
		return
	}

	subID := event.SubscriptionID
	if subID == "" {
		if v, ok := resp.Headers["X-Subscription-Id"]; ok {
			subID = v
		}
	}

	d.mu.Lock()
	cb, ok := d.eventCBs[subID]
	d.mu.Unlock()

	if ok && cb != nil {
		go cb(event) // invoke callback in a separate goroutine to avoid blocking the reader
	}
}

// dispatchResponse routes a request response to the matching pending channel.
func (d *MessageDemuxer) dispatchResponse(resp *Response) {
	d.mu.Lock()
	ch, ok := d.pending[resp.UUID]
	if ok {
		delete(d.pending, resp.UUID)
	}
	d.mu.Unlock()

	if ok && ch != nil {
		ch <- resp
	}
}

// SubscribeOption configures a subscription request.
type SubscribeOption struct {
	AppName string   // App name, or empty/"*" for all apps
	Events  []string // Event types: "process_start", "process_exit", "stdout", "health_change", "status_change", "app_removed"
}

// SubscriptionResult contains the server's response to a subscribe request.
type SubscriptionResult struct {
	SubscriptionID string   `json:"subscription_id"`
	AppName        string   `json:"app_name"`
	Events         []string `json:"events"`
}

// Subscribe registers for events on a named app (or all apps if AppName is empty/"*").
// The callback is invoked in a separate goroutine for each event.
// Returns the subscription ID and any error.
func (c *AppMeshClient) Subscribe(opt SubscribeOption, callback EventCallback) (*SubscriptionResult, error) {
	apiPath := "/appmesh/subscribe"
	if opt.AppName != "" && opt.AppName != "*" {
		apiPath = fmt.Sprintf("/appmesh/app/%s/subscribe", opt.AppName)
	}

	queries := url.Values{}
	if len(opt.Events) > 0 {
		queries.Set("events", strings.Join(opt.Events, ","))
	}

	status, raw, _, err := c.req.Send(http.MethodPost, apiPath, queries, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("subscribe failed with status %d: %s", status, string(raw))
	}

	var result SubscriptionResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to parse subscribe response: %w", err)
	}

	// Register the callback with the demuxer (if transport supports it)
	if sub, ok := c.req.(subscribableRequester); ok {
		sub.enableDemuxer()
		sub.getDemuxer().registerEventCallback(result.SubscriptionID, callback)
	}

	return &result, nil
}

// Unsubscribe removes a subscription by ID.
func (c *AppMeshClient) Unsubscribe(subscriptionID string) error {
	queries := url.Values{}
	queries.Set("subscription_id", subscriptionID)

	status, raw, _, err := c.req.Send(http.MethodDelete, "/appmesh/subscribe", queries, nil, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNotFound {
		return fmt.Errorf("unsubscribe failed with status %d: %s", status, string(raw))
	}

	// Unregister from demuxer
	if sub, ok := c.req.(subscribableRequester); ok {
		sub.getDemuxer().unregisterEventCallback(subscriptionID)
	}

	return nil
}

// subscribableRequester is implemented by transports that support event subscriptions.
type subscribableRequester interface {
	enableDemuxer()
	getDemuxer() *MessageDemuxer
}
