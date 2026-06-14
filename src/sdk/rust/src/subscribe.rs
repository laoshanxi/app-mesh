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
use tokio::sync::{oneshot, watch, Mutex};

use crate::constants::{EVENT_TYPE_DISCONNECTED, EVENT_URI};
use crate::error::AppMeshError;
use crate::models::AppEvent;
use crate::tcp_messages::ResponseMessage;

/// Callback invoked for each received event.  Invocations are spawned on a
/// separate tokio task so they never block the reader loop.
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

/// State protected together by a single mutex so the callback map and the
/// pre-registration event buffer stay consistent (events buffered while a
/// callback is absent are flushed atomically on registration, preserving order
/// vs. concurrent live events).
struct EventState {
    callbacks: HashMap<String, EventCallback>,
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
                callbacks: HashMap::new(),
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
        {
            let mut guard = self.stop_tx.lock().expect("stop_tx lock poisoned");
            *guard = Some(stop_tx);
        }

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
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
            }
        }

        // Drop all pending senders so waiters get a RecvError
        let pending = self.pending.clone();
        tokio::spawn(async move {
            let mut map = pending.lock().await;
            map.clear();
        });
    }

    /// Register a pending request and return the receiver end.
    ///
    /// The caller should `await` the receiver; the read loop will send the
    /// matching `ResponseMessage` when it arrives.
    pub async fn register_request(&self, uuid: &str) -> oneshot::Receiver<ResponseMessage> {
        let (tx, rx) = oneshot::channel();
        let mut map = self.pending.lock().await;
        map.insert(uuid.to_string(), tx);
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
        // Take buffered events under the lock so they precede later live events,
        // then spawn the dispatches after releasing it (callbacks may run long).
        let buffered = {
            let mut state = self.event_state.lock().expect("event_state lock poisoned");
            state.callbacks.insert(sub_id.to_string(), callback.clone());
            state.buffers.remove(sub_id)
        };

        if let Some(buffered) = buffered {
            for event in buffered {
                let cb = callback.clone();
                tokio::spawn(async move {
                    cb(event);
                });
            }
        }
    }

    /// Remove an event callback and discard any events buffered for it.
    pub fn unregister_event_callback(&self, sub_id: &str) {
        let mut state = self.event_state.lock().expect("event_state lock poisoned");
        state.callbacks.remove(sub_id);
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
        let entries: Vec<(String, EventCallback)> = {
            let mut state = event_state.lock().expect("event_state lock poisoned");
            state.buffers.clear();
            state.callbacks.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };

        for (sub_id, callback) in entries {
            let event = AppEvent {
                subscription_id: sub_id,
                event_type: EVENT_TYPE_DISCONNECTED.to_string(),
                app_name: String::new(),
                timestamp: 0,
                sequence: 0,
                data: serde_json::Value::Null,
            };
            tokio::spawn(async move {
                callback(event);
            });
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

        let cb = {
            let mut state = event_state.lock().expect("event_state lock poisoned");
            if let Some(cb) = state.callbacks.get(&sub_id) {
                debug!("MessageDemuxer: event matched sub_id={}", sub_id);
                Some(cb.clone())
            } else if !sub_id.is_empty() {
                // Race: event arrived before its callback registered (e.g. atomic
                // add_app(subscribe_events) on a fast app). Buffer it (bounded) so
                // register_event_callback can flush it instead of dropping it.
                Self::buffer_event(&mut state, &sub_id, event);
                return;
            } else {
                warn!("MessageDemuxer: event dropped, empty sub_id");
                return;
            }
        };

        if let Some(callback) = cb {
            tokio::spawn(async move {
                callback(event);
            });
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
        if let Ok(mut guard) = self.stop_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(true);
            }
        }
    }
}
