// subscribe.rs
//! Message demuxer for routing TCP/WSS responses and event notifications.
//!
//! When a subscription is active the background reader owns the transport's
//! read side.  Incoming messages are routed by inspecting `request_uri`:
//!   - `/appmesh/event` -> dispatched to the registered event callback
//!   - anything else    -> dispatched to the pending oneshot channel by UUID

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, error, warn};
use tokio::sync::{oneshot, watch, Mutex};

use crate::constants::EVENT_URI;
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

/// Routes incoming messages to pending request channels or event callbacks.
pub struct MessageDemuxer {
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>,
    event_callbacks: Arc<std::sync::Mutex<HashMap<String, EventCallback>>>,
    stop_tx: std::sync::Mutex<Option<watch::Sender<bool>>>,
    running: Arc<AtomicBool>,
}

impl MessageDemuxer {
    /// Create a new (stopped) demuxer.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            event_callbacks: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
        let event_callbacks = Arc::clone(&self.event_callbacks);
        let running = Arc::clone(&self.running);

        tokio::spawn(async move {
            Self::read_loop(reader, stop_rx, pending, event_callbacks, running).await;
        });
    }

    /// Stop the background reader and fail all pending requests.
    pub fn stop(&self) {
        if !self.running.swap(false, Ordering::SeqCst) {
            return; // already stopped
        }

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

    /// Register an event callback for a subscription id.
    pub fn register_event_callback(&self, sub_id: &str, callback: EventCallback) {
        let mut map = self.event_callbacks.lock().expect("event_callbacks lock poisoned");
        map.insert(sub_id.to_string(), callback);
    }

    /// Remove an event callback.
    pub fn unregister_event_callback(&self, sub_id: &str) {
        let mut map = self.event_callbacks.lock().expect("event_callbacks lock poisoned");
        map.remove(sub_id);
    }

    /// Whether the background reader is currently running.
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    // -- internal -------------------------------------------------------------

    async fn read_loop(
        reader: Arc<dyn MessageReader>,
        mut stop_rx: watch::Receiver<bool>,
        pending: Arc<Mutex<HashMap<String, oneshot::Sender<ResponseMessage>>>>,
        event_callbacks: Arc<std::sync::Mutex<HashMap<String, EventCallback>>>,
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
                                Self::dispatch_event(&resp, &event_callbacks);
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

        running.store(false, Ordering::SeqCst);

        // Close all pending channels so waiters get an error
        let mut map = pending.lock().await;
        map.clear();

        debug!("MessageDemuxer: read loop exited");
    }

    fn dispatch_event(
        resp: &ResponseMessage,
        event_callbacks: &Arc<std::sync::Mutex<HashMap<String, EventCallback>>>,
    ) {
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
            let map = event_callbacks.lock().expect("event_callbacks lock poisoned");
            map.get(&sub_id).cloned()
        };

        if let Some(callback) = cb {
            // Invoke callback in a separate task to avoid blocking the reader
            tokio::spawn(async move {
                callback(event);
            });
        }
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
