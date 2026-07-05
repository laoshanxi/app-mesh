// subscribe.rs
//! Message demuxer for routing TCP/WSS responses and event notifications.
//!
//! When a subscription is active the background reader owns the transport's
//! read side.  Incoming messages are routed by inspecting `request_uri`:
//!   - `/appmesh/event` -> dispatched to the registered event callback
//!   - anything else    -> dispatched to the pending oneshot channel by UUID

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, error, warn};
use tokio::sync::{mpsc, oneshot, watch, Mutex};

use crate::constants::{EVENT_TYPE_DISCONNECTED, EVENT_URI};
use crate::error::AppMeshError;
use crate::models::AppEvent;
use crate::wire_messages::ResponseMessage;

/// Callback invoked for each received event. Events for a subscription are
/// delivered serially in arrival order on a dedicated dispatch task (matching the
/// other SDK demuxers), so a slow callback never blocks the reader loop or other subs.
pub type EventCallback = Arc<dyn Fn(AppEvent) + Send + Sync>;

/// Trait abstracting the transport read side so the demuxer works with both
/// TCP and WSS transports.
#[async_trait]
pub(crate) trait MessageReader: Send + Sync {
    async fn read_message(&self) -> Result<Option<Vec<u8>>, AppMeshError>;
}

/// Bound the pre-registration event buffer (atomic-subscribe race window) so a
/// subscription whose callback never registers cannot grow memory without limit.
const MAX_BUFFERED_SUBS: usize = 64;
const MAX_BUFFERED_EVENTS_PER_SUB: usize = 1000;

/// State protected together by a single mutex so the dispatch-channel map and
/// the pre-registration event buffer stay consistent (events buffered while a
/// callback is absent are flushed atomically on registration, preserving order
/// vs. concurrent live events).
struct EventState {
    /// Per-subscription dispatch channels: one worker task per sub_id drains its
    /// channel and invokes the callback, so buffered flushes, live events, and the
    /// disconnect broadcast are delivered serially in arrival order.
    senders: HashMap<String, mpsc::UnboundedSender<AppEvent>>,
    /// Events that arrive between the server-side subscription and the client
    /// registering its callback (e.g. atomic add_app(subscribe_events) on a fast
    /// app, whose output is pushed before the response returns). Held per sub_id
    /// and flushed on register_event_callback so no events are lost.
    buffers: HashMap<String, VecDeque<AppEvent>>,
}

/// Routes incoming messages to pending request channels or event callbacks.
pub struct MessageDemuxer {
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>,
    event_state: Arc<std::sync::Mutex<EventState>>,
    stop_tx: std::sync::Mutex<Option<watch::Sender<bool>>>,
    running: Arc<AtomicBool>,
}

impl MessageDemuxer {
    /// Create a new (stopped) demuxer.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            event_state: Arc::new(std::sync::Mutex::new(EventState {
                senders: HashMap::new(),
                buffers: HashMap::new(),
            })),
            stop_tx: std::sync::Mutex::new(None),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start the background read loop.  No-op if already running.
    pub(crate) fn start(&self, reader: Arc<dyn MessageReader>) {
        if self.running.swap(true, Ordering::SeqCst) {
            return; // already running
        }

        let (stop_tx, stop_rx) = watch::channel(false);
        // Poisoning is benign here (guarded state stays valid), so recover the guard.
        *self.stop_tx.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop_tx);

        let pending = Arc::clone(&self.pending);
        let event_state = Arc::clone(&self.event_state);
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            Self::read_loop(reader, stop_rx, pending, event_state, running).await;
        });
    }

    /// Stop the background reader and fail all pending requests.
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return; // already stopped
        }

        // Broadcast a synthetic disconnect event to all registered event
        // callbacks so long-running waits can unblock cleanly, and discard any
        // events buffered for never-registered subs so nothing leaks.
        Self::broadcast_disconnect(&self.event_state);

        // Signal the read loop to exit
        if let Some(tx) = self.stop_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(true);
        }

        // Drop all pending senders so waiters get a RecvError. stop() may run
        // outside a tokio runtime (e.g. from Drop): spawn when possible, else
        // clear inline — with no runtime nothing holds the async lock.
        let pending = self.pending.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let mut map = pending.lock().await;
                map.clear();
            });
        } else if let Ok(mut map) = pending.try_lock() {
            map.clear();
        }
    }

    /// Register a pending request and return the receiver end.
    ///
    /// The caller should `await` the receiver; the read loop will send the
    /// matching `ResponseMessage` when it arrives.
    pub async fn register_request(&self, uuid: &str) -> oneshot::Receiver<ResponseMessage> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.pending.lock().await;
        // Re-check `running` under the pending lock: stop()/read-loop exit flip it
        // false BEFORE clearing the map, so any clear after a true reading must wait
        // on this lock and will drop our sender (waking the waiter). Inserting after
        // the clear would strand the sender forever and hang the waiter.
        if self.running.load(Ordering::SeqCst) {
            map.insert(uuid.to_string(), tx);
        }
        // When stopped, `tx` drops here so `rx.await` fails immediately instead of hanging.
        rx
    }

    /// Remove a pending request (e.g. on timeout / cancellation).
    pub async fn unregister_request(&self, uuid: &str) {
        let mut map = self.pending.lock().await;
        map.remove(uuid);
    }

    /// Register an event callback for a subscription id, flushing any events
    /// that arrived before registration (atomic-subscribe race).
    pub fn register_event_callback(&self, sub_id: &str, callback: EventCallback) {
        let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();

        // Single dispatch worker per subscription: drains the channel and invokes
        // the callback serially in arrival order.
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                // Isolate callback panics (e.g. print! on a closed stdout pipe) so
                // later events — including EXIT and DISCONNECTED — are still delivered.
                let call = std::panic::AssertUnwindSafe(|| callback(event));
                if std::panic::catch_unwind(call).is_err() {
                    error!("event callback panicked; continuing event dispatch");
                }
            }
        });

        // Flush buffered events and publish the sender under the same lock so live
        // events can only be enqueued after the buffered ones (order preserved).
        let mut state = self.event_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(buffered) = state.buffers.remove(sub_id) {
            for event in buffered {
                let _ = tx.send(event);
            }
        }
        // Replacing an existing sender drops it, stopping the old worker after it drains.
        state.senders.insert(sub_id.to_string(), tx);
    }

    /// Remove an event callback and discard any events buffered for it.
    pub fn unregister_event_callback(&self, sub_id: &str) {
        let mut state = self.event_state.lock().unwrap_or_else(|e| e.into_inner());
        // Dropping the sender stops the dispatch worker after it drains.
        state.senders.remove(sub_id);
        state.buffers.remove(sub_id);
    }

    /// Whether the background reader is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // -- internal -------------------------------------------------------------

    /// Push a synthetic disconnect event to every registered event callback,
    /// and discard any events buffered for never-registered subs.
    fn broadcast_disconnect(event_state: &Arc<std::sync::Mutex<EventState>>) {
        let mut state = event_state.lock().unwrap_or_else(|e| e.into_inner());
        state.buffers.clear();

        // Enqueue through the per-subscription dispatch channels so the
        // disconnect event is observed after any events already in flight.
        for (sub_id, sender) in state.senders.iter() {
            let event = AppEvent {
                subscription_id: sub_id.clone(),
                event_type: EVENT_TYPE_DISCONNECTED.to_string(),
                app_name: String::new(),
                timestamp: 0,
                sequence: 0,
                data: serde_json::Value::Null,
            };
            let _ = sender.send(event);
        }
    }

    async fn read_loop(
        reader: Arc<dyn MessageReader>,
        mut stop_rx: watch::Receiver<bool>,
        pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>,
        event_state: Arc<std::sync::Mutex<EventState>>,
        running: Arc<AtomicBool>,
    ) {
        debug!("MessageDemuxer: read loop started");

        loop {
            // Check for stop signal (non-blocking)
            if *stop_rx.borrow() {
                break;
            }

            let result = tokio::select! {
                r = reader.read_message() => r,
                _ = stop_rx.changed() => break,
            };

            match result {
                Ok(Some(data)) if !data.is_empty() => {
                    match ResponseMessage::deserialize(&data) {
                        Ok(resp) => {
                            if resp.request_uri == EVENT_URI {
                                Self::dispatch_event(&resp, &event_state);
                            } else {
                                Self::dispatch_response(resp, &pending).await;
                            }
                        }
                        Err(e) => {
                            warn!("MessageDemuxer: failed to deserialize message: {}", e);
                        }
                    }
                }
                Ok(_) => {
                    // Empty data or None means connection closed
                    debug!("MessageDemuxer: connection closed");
                    break;
                }
                Err(e) => {
                    error!("MessageDemuxer: read error: {}", e);
                    break;
                }
            }
        }

        // Only broadcast if stop() hasn't already done so
        if running.swap(false, Ordering::SeqCst) {
            Self::broadcast_disconnect(&event_state);
        }

        let mut map = pending.lock().await;
        map.clear();

        debug!("MessageDemuxer: read loop exited");
    }

    fn dispatch_event(resp: &ResponseMessage, event_state: &Arc<std::sync::Mutex<EventState>>) {
        let event: AppEvent = match serde_json::from_slice(&resp.body) {
            Ok(e) => e,
            Err(e) => {
                warn!("MessageDemuxer: failed to parse event: {}", e);
                return;
            }
        };

        let mut sub_id = event.subscription_id.clone();
        if sub_id.is_empty() {
            if let Some(id) = resp.headers.get("X-Subscription-Id") {
                sub_id = id.clone();
            }
        }

        let mut state = event_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(sender) = state.senders.get(&sub_id) {
            debug!("MessageDemuxer: event matched sub_id={}", sub_id);
            // Unbounded send never blocks; the dispatch worker preserves order.
            let _ = sender.send(event);
        } else if !sub_id.is_empty() {
            // Race: event arrived before its callback registered (e.g. atomic
            // add_app(subscribe_events) on a fast app). Buffer it (bounded) so
            // register_event_callback can flush it instead of dropping it.
            Self::buffer_event(&mut state, &sub_id, event);
        } else {
            warn!("MessageDemuxer: event dropped, empty sub_id");
        }
    }

    /// Hold an event whose callback has not registered yet (caller holds the lock).
    fn buffer_event(state: &mut EventState, sub_id: &str, event: AppEvent) {
        let buf = match state.buffers.get_mut(sub_id) {
            Some(buf) => buf,
            None => {
                if state.buffers.len() >= MAX_BUFFERED_SUBS {
                    debug!("MessageDemuxer: event sub_id={} dropped, buffer cap reached", sub_id);
                    return; // cap distinct unregistered subs to bound memory
                }
                state.buffers.entry(sub_id.to_string()).or_default()
            }
        };
        if buf.len() >= MAX_BUFFERED_EVENTS_PER_SUB {
            buf.pop_front(); // drop-oldest
        }
        buf.push_back(event);
    }

    async fn dispatch_response(
        resp: ResponseMessage,
        pending: &Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>,
    ) {
        let uuid = resp.uuid.clone();
        let tx = {
            let mut map = pending.lock().await;
            map.remove(&uuid)
        };

        if let Some(sender) = tx {
            if sender.send(resp).is_err() {
                debug!("MessageDemuxer: receiver dropped for uuid {}", uuid);
            }
        } else {
            debug!("MessageDemuxer: no pending request for uuid {}", uuid);
        }
    }
}

impl Drop for MessageDemuxer {
    fn drop(&mut self) {
        // Best-effort stop without spawning
        self.running.store(false, Ordering::SeqCst);
        if let Some(tx) = self.stop_tx.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Scripted mock transport: messages are fed through a channel; closing the
    /// channel reads as transport EOF.
    struct ScriptedReader {
        rx: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
    }

    #[async_trait]
    impl MessageReader for ScriptedReader {
        async fn read_message(&self) -> Result<Option<Vec<u8>>, AppMeshError> {
            Ok(self.rx.lock().await.recv().await)
        }
    }

    fn response_bytes(uuid: &str, request_uri: &str, body: &[u8]) -> Vec<u8> {
        let resp = ResponseMessage {
            uuid: uuid.to_string(),
            request_uri: request_uri.to_string(),
            http_status: 200,
            body: body.to_vec(),
            ..Default::default()
        };
        // Struct-map encoding, matching the daemon wire format
        // (see RequestMessage::serialize).
        rmp_serde::to_vec_named(&resp).expect("serialize response")
    }

    // Conformance: S7 (partial) — pending waiter registered before the response
    // arrives is routed by UUID; see docs/source/SDKContract.md.
    #[tokio::test]
    async fn conformance_s7_response_routed_to_pre_registered_waiter() {
        let (tx, rx) = mpsc::unbounded_channel();
        let demuxer = MessageDemuxer::new();
        demuxer.start(Arc::new(ScriptedReader { rx: Mutex::new(rx) }));

        let waiter = demuxer.register_request("req-s7").await;
        tx.send(response_bytes("req-s7", "/appmesh/app/test", b"{}")).unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("timed out waiting for response")
            .expect("waiter channel failed");
        assert_eq!(resp.uuid, "req-s7");
        assert_eq!(resp.http_status, 200);
        demuxer.stop();
    }

    // Conformance: S2 (demuxer) — transport EOF broadcasts the synthetic
    // __disconnected__ event to every registered callback and fails pending
    // request waiters instead of leaving them hanging; see
    // docs/source/SDKContract.md.
    #[tokio::test]
    async fn conformance_s2_disconnect_broadcast_unblocks() {
        let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let demuxer = MessageDemuxer::new();
        demuxer.start(Arc::new(ScriptedReader { rx: Mutex::new(rx) }));

        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        demuxer.register_event_callback(
            "sub-s2",
            Arc::new(move |event: AppEvent| {
                let _ = event_tx.send(event);
            }),
        );
        let waiter = demuxer.register_request("req-s2").await;

        drop(tx); // transport EOF

        let event = tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("timed out waiting for disconnect broadcast")
            .expect("dispatch worker dropped");
        assert_eq!(event.event_type, EVENT_TYPE_DISCONNECTED);
        assert_eq!(event.subscription_id, "sub-s2");

        // Pending waiter is woken with an error (disconnect), never "slow request".
        let result = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("pending waiter not woken on disconnect");
        assert!(result.is_err());
    }
}
