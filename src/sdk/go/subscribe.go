package appmesh

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	EVENT_URI = "/appmesh/event"

	// EventTypeDisconnected is a synthetic event_type pushed to every registered
	// callback when the demuxer stops or the underlying transport disconnects.
	// This lets long-running waits (e.g. wait_for_async_run) unblock instead of
	// hanging forever.
	EventTypeDisconnected = "__disconnected__"
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
	if !d.started {
		d.mu.Unlock()
		return
	}
	close(d.stopCh)
	d.started = false

	// Snapshot callbacks + pending under lock, then release before invoking
	type cbEntry struct {
		subID string
		cb    EventCallback
	}
	snapshot := make([]cbEntry, 0, len(d.eventCBs))
	for subID, cb := range d.eventCBs {
		snapshot = append(snapshot, cbEntry{subID, cb})
	}
	pendingCopy := d.pending
	d.pending = make(map[string]chan *Response)
	d.mu.Unlock()

	// Close pending channels (outside lock)
	for _, ch := range pendingCopy {
		close(ch)
	}

	// Broadcast disconnect (outside lock — no deadlock from re-entrant callbacks)
	for _, e := range snapshot {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("broadcastDisconnect: callback panic: %v", r)
				}
			}()
			e.cb(AppEvent{SubscriptionID: e.subID, EventType: EventTypeDisconnected})
		}()
	}
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
			// Connection error — stop() handles broadcast + cleanup
			d.stop()
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
	Events  []string // Event types: "START", "EXIT", "STDOUT", "HEALTH", "STATUS", "REMOVED"
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

// WaitForAsyncRun waits for an asynchronous application run to complete using
// subscribe-based streaming instead of polling. It subscribes to STDOUT, EXIT,
// and REMOVED events, then backfills any output emitted before the subscription
// took effect. Stdout is deduplicated by byte position to handle overlap between
// the backfill and live events.
//
// Returns the process exit code, or a sentinel:
//   - nil:  caller-side timeout (no EXIT/REMOVED observed within the deadline)
//   - -1:   REMOVED before EXIT observed
//   - -2:   transport disconnected
//
// When exit_code >= 0 the temporary run app is deleted as best-effort cleanup.
func (c *AppMeshClient) WaitForAsyncRun(run *AppRun, printStdout bool, timeout time.Duration) *int {
	if run == nil || run.AppName == "" {
		return nil
	}

	var (
		exitCode       *int           // nil until EXIT, REMOVED, or disconnect
		deliveredUntil int64          // next-byte offset already printed
		mu             sync.Mutex     // guards exitCode and deliveredUntil
		done           = make(chan struct{})
		doneOnce       sync.Once
	)

	signalDone := func() { doneOnce.Do(func() { close(done) }) }

	// deliver outputs the portion of chunk that has not yet been printed,
	// based on the byte-position dedup logic from the Python reference.
	deliver := func(chunk string, pos int64) {
		if len(chunk) == 0 {
			return
		}
		mu.Lock()
		end := pos + int64(len(chunk))
		if end <= deliveredUntil {
			mu.Unlock()
			return
		}
		if pos < deliveredUntil {
			chunk = chunk[deliveredUntil-pos:]
		}
		deliveredUntil = end
		mu.Unlock()

		if printStdout {
			fmt.Print(chunk)
		}
	}

	// Event callback invoked by the demuxer for each subscribed event.
	onEvent := func(event AppEvent) {
		switch event.EventType {
		case "STDOUT":
			var data struct {
				Output   string `json:"output"`
				Position int64  `json:"position"`
			}
			if err := json.Unmarshal(event.Data, &data); err != nil {
				return
			}
			deliver(data.Output, data.Position)

		case "EXIT":
			var data struct {
				ExitCode int `json:"exit_code"`
			}
			code := -1
			if err := json.Unmarshal(event.Data, &data); err == nil {
				code = data.ExitCode
			}
			mu.Lock()
			if exitCode == nil {
				exitCode = &code
			}
			mu.Unlock()
			signalDone()

		case "REMOVED":
			mu.Lock()
			if exitCode == nil {
				code := -1
				exitCode = &code
			}
			mu.Unlock()
			signalDone()

		case EventTypeDisconnected:
			mu.Lock()
			if exitCode == nil {
				code := -2
				exitCode = &code
			}
			mu.Unlock()
			signalDone()
		}
	}

	sub, err := c.Subscribe(SubscribeOption{
		AppName: run.AppName,
		Events:  []string{"STDOUT", "EXIT", "REMOVED"},
	}, onEvent)

	if err != nil {
		log.Printf("WaitForAsyncRun: subscribe failed for %s: %v", run.AppName, err)
		return nil
	}

	defer func() {
		// Unsubscribe
		if sub.SubscriptionID != "" {
			_ = c.Unsubscribe(sub.SubscriptionID)
		}
		// Best-effort delete on a real exit. Sentinels (-1 REMOVED, -2 disconnected)
		// mean the daemon already lost track or the app is gone -- don't try to delete.
		mu.Lock()
		ec := exitCode
		mu.Unlock()
		if ec != nil && *ec >= 0 {
			_, _ = c.RemoveApp(run.AppName)
		}
	}()

	// Backfill: fetch output emitted before the subscribe took effect.
	// Also catches the case where the process already exited.
	backfill := c.GetAppOutput(run.AppName, 0, 0, 0, run.ProcUid, 0)
	if backfill.HttpBody != "" {
		deliver(backfill.HttpBody, 0)
	}
	if backfill.ExitCode != nil {
		mu.Lock()
		if exitCode == nil {
			ec := *backfill.ExitCode
			exitCode = &ec
		}
		mu.Unlock()
		signalDone()
	}

	// Wait for completion or timeout.
	if timeout <= 0 {
		<-done
	} else {
		select {
		case <-done:
		case <-time.After(timeout):
		}
	}

	mu.Lock()
	result := exitCode
	mu.Unlock()
	return result
}

// subscribableRequester is implemented by transports that support event subscriptions.
type subscribableRequester interface {
	enableDemuxer()
	getDemuxer() *MessageDemuxer
}
