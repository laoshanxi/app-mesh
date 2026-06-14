package appmesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Sentinel errors returned by WaitForAsyncRun to disambiguate non-EXIT terminations
// from real (possibly negative) process exit codes (e.g. -SIGINT = -2).
var (
	ErrTransportDisconnected = errors.New("transport disconnected before exit")
	ErrAppRemoved            = errors.New("app removed before exit")
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
// Event callbacks are dispatched serially via a single worker goroutine, so
// per-subscription event ordering is preserved (matching Python/Java SDKs).
type MessageDemuxer struct {
	mu       sync.Mutex
	pending  map[string]chan *Response // uuid -> response channel
	eventCBs map[string]EventCallback  // subscription_id -> callback
	// Events that arrive between server-side subscription and the client
	// registering its callback (e.g. atomic add_app(subscribe_events) on a fast
	// app, whose output is pushed before add_app returns). Held per subID and
	// flushed on registerEventCallback so no events are lost.
	eventBufs map[string][]AppEvent
	started   bool
	stopCh    chan struct{}
	eventQ    chan dispatchTask
	readMsg   func() ([]byte, error) // transport-specific read function
}

// Bound the pre-registration event buffer (atomic-subscribe race window) so a
// subscription whose callback never registers cannot grow memory without limit.
const (
	maxBufferedSubs         = 64
	maxBufferedEventsPerSub = 1000
)

type dispatchTask struct {
	cb    EventCallback
	event AppEvent
}

func newMessageDemuxer(readMsg func() ([]byte, error)) *MessageDemuxer {
	return &MessageDemuxer{
		pending:   make(map[string]chan *Response),
		eventCBs:  make(map[string]EventCallback),
		eventBufs: make(map[string][]AppEvent),
		stopCh:    make(chan struct{}),
		eventQ:    make(chan dispatchTask, 256),
		readMsg:   readMsg,
	}
}

// start begins the background reader and dispatch goroutines.
func (d *MessageDemuxer) start() {
	d.mu.Lock()
	if d.started {
		d.mu.Unlock()
		return
	}
	d.started = true
	d.mu.Unlock()

	go d.readLoop()
	go d.dispatchWorker()
}

// dispatchWorker invokes event callbacks serially in arrival order.
// One slow callback delays subsequent events but never the socket reader.
func (d *MessageDemuxer) dispatchWorker() {
	for {
		select {
		case <-d.stopCh:
			return
		case task := <-d.eventQ:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("dispatchWorker: callback panic: %v", r)
					}
				}()
				task.cb(task.event)
			}()
		}
	}
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
	d.eventBufs = make(map[string][]AppEvent) // drop events buffered for never-registered subs
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

// registerEventCallback registers a callback for a subscription ID, flushing any
// events that arrived before registration (atomic-subscribe race).
func (d *MessageDemuxer) registerEventCallback(subID string, cb EventCallback) {
	d.mu.Lock()
	d.eventCBs[subID] = cb
	buffered := d.eventBufs[subID]
	delete(d.eventBufs, subID)
	// Enqueue under the lock so buffered events precede later live events.
	for _, event := range buffered {
		select {
		case d.eventQ <- dispatchTask{cb: cb, event: event}:
		case <-d.stopCh:
		}
	}
	d.mu.Unlock()
}

// unregisterEventCallback removes a callback for a subscription ID.
func (d *MessageDemuxer) unregisterEventCallback(subID string) {
	d.mu.Lock()
	delete(d.eventCBs, subID)
	delete(d.eventBufs, subID)
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
	if (!ok || cb == nil) && subID != "" {
		// No callback yet: buffer the event so an atomic add_app(subscribe_events)
		// on a fast app does not lose output pushed before the client registers.
		d.bufferEventLocked(subID, event)
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	if !ok || cb == nil {
		return
	}
	// Enqueue for serial dispatch. Order matters — STDOUT dedup by byte-position
	// in WaitForAsyncRun assumes events arrive in the order the daemon emitted them.
	select {
	case d.eventQ <- dispatchTask{cb: cb, event: event}:
	case <-d.stopCh:
	}
}

// bufferEventLocked holds an event whose callback has not registered yet.
// The caller must hold d.mu. Bounded: caps distinct buffered subIDs and uses
// drop-oldest per subID so a never-registered subscription cannot grow memory
// without limit.
func (d *MessageDemuxer) bufferEventLocked(subID string, event AppEvent) {
	buf, exists := d.eventBufs[subID]
	if !exists && len(d.eventBufs) >= maxBufferedSubs {
		return // cap distinct unregistered subs to bound memory
	}
	if len(buf) >= maxBufferedEventsPerSub {
		buf = buf[1:] // drop oldest
	}
	d.eventBufs[subID] = append(buf, event)
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
	if result.SubscriptionID == "" {
		return nil, fmt.Errorf("server returned empty subscription_id")
	}

	// Register the callback with the demuxer (if transport supports it).
	if sub, ok := c.req.(subscribableRequester); ok {
		sub.enableDemuxer()
		if d := sub.getDemuxer(); d != nil {
			d.registerEventCallback(result.SubscriptionID, callback)
		}
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

	// Unregister from demuxer (no-op if transport is closed or demuxer not enabled).
	if sub, ok := c.req.(subscribableRequester); ok {
		if d := sub.getDemuxer(); d != nil {
			d.unregisterEventCallback(subscriptionID)
		}
	}

	return nil
}

// WaitForAsyncRun waits for an asynchronous application run to complete using
// subscribe-based streaming instead of polling. It subscribes to STDOUT, EXIT,
// and REMOVED events, then backfills any output emitted before the subscription
// took effect. Stdout is deduplicated by byte position to handle overlap between
// the backfill and live events.
//
// Return values:
//   - (&code, nil):                  process exited normally (code may be negative for signal kills)
//   - (nil, nil):                    timeout or context cancelled
//   - (nil, ErrAppRemoved):          app removed before EXIT observed
//   - (nil, ErrTransportDisconnected): TCP/WSS connection lost
//   - (nil, err):                    subscribe failed
func (c *AppMeshClient) WaitForAsyncRun(ctx context.Context, run *AppRun, stdoutHandler OutputHandler, timeout time.Duration) (*int, error) {
	if run == nil || run.AppName == "" {
		return nil, fmt.Errorf("invalid async run")
	}

	var (
		exitCode       *int       // set on EXIT
		waitErr        error      // first non-EXIT termination reason
		disconnected   bool       // transport-dead flag (set even if waitErr is already populated)
		deliveredUntil int64      // next-byte offset already delivered to handler
		mu             sync.Mutex // guards all of the above
		done           = make(chan struct{})
		doneOnce       sync.Once
	)

	signalDone := func() { doneOnce.Do(func() { close(done) }) }

	setExit := func(code int) {
		mu.Lock()
		if exitCode == nil && waitErr == nil {
			exitCode = &code
		}
		mu.Unlock()
		signalDone()
	}

	setErr := func(e error) {
		mu.Lock()
		if exitCode == nil && waitErr == nil {
			waitErr = e
		}
		mu.Unlock()
		signalDone()
	}

	// deliver passes the not-yet-seen portion of chunk to the handler,
	// using byte-position dedup to bridge backfill ↔ live events.
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
		startPos := pos
		if pos < deliveredUntil {
			chunk = chunk[deliveredUntil-pos:]
			startPos = deliveredUntil
		}
		deliveredUntil = end
		mu.Unlock()

		if stdoutHandler != nil {
			stdoutHandler(chunk, startPos)
		}
	}

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
				ExitCode *int `json:"exit_code"`
			}
			if err := json.Unmarshal(event.Data, &data); err == nil && data.ExitCode != nil {
				setExit(*data.ExitCode)
			} else {
				setErr(fmt.Errorf("EXIT event missing exit_code"))
			}

		case "REMOVED":
			setErr(ErrAppRemoved)

		case EventTypeDisconnected:
			// Always mark disconnected (even if waitErr already set) so the
			// defer below skips Unsubscribe on a dead connection.
			mu.Lock()
			disconnected = true
			switch {
			case exitCode != nil:
				// Exit already reported — leave it alone, the process finished
				// successfully (or with a normal code) before the transport died.
			case waitErr == nil:
				waitErr = ErrTransportDisconnected
			default:
				// Wrap the existing reason so callers using errors.Is can still
				// detect ErrTransportDisconnected (race: REMOVED/malformed-EXIT
				// arrived just before the transport dropped).
				waitErr = fmt.Errorf("%w (also: %w)", waitErr, ErrTransportDisconnected)
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
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	defer func() {
		mu.Lock()
		disc := disconnected
		mu.Unlock()
		// On disconnect the demuxer is stopped; calling Unsubscribe would
		// register a request channel that never gets a response.
		if disc {
			return
		}
		if sub.SubscriptionID != "" {
			_ = c.Unsubscribe(sub.SubscriptionID)
		}
	}()

	// Backfill: fetch output emitted before the subscribe took effect, and
	// detect a process that already exited.
	backfill := c.GetAppOutput(run.AppName, 0, 0, 0, run.ProcUid, 0)
	if backfill.HttpBody != "" {
		deliver(backfill.HttpBody, 0)
	}
	if backfill.ExitCode != nil {
		setExit(*backfill.ExitCode)
	}

	// Wait for completion, timeout, or context cancellation.
	if timeout <= 0 {
		select {
		case <-done:
		case <-ctx.Done():
		}
	} else {
		select {
		case <-done:
		case <-time.After(timeout):
		case <-ctx.Done():
		}
	}

	mu.Lock()
	defer mu.Unlock()
	return exitCode, waitErr
}

// EnableConcurrency makes this client's transport safe for concurrent use by multiple
// goroutines. It starts the response demuxer, which correlates each reply to its request
// by UUID; without it a TCP/WSS connection shared across goroutines uses a synchronous
// send-then-read that can cross-wire responses (e.g. a token-renew reply consumed by an
// unrelated call, leaving a stale/revoked token in place). No-op on transports without
// multiplexing (HTTP) and idempotent (Subscribe also enables it on demand).
func (c *AppMeshClient) EnableConcurrency() {
	if sub, ok := c.req.(subscribableRequester); ok {
		sub.enableDemuxer()
	}
}

// subscribableRequester is implemented by transports that support event subscriptions.
type subscribableRequester interface {
	enableDemuxer()
	getDemuxer() *MessageDemuxer
}
