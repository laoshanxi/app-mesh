"""Event subscription support for TCP and WSS transports."""
__all__ = ["AppEvent", "SubscriptionResult", "EVENT_TYPE_DISCONNECTED"]

import json
import queue
import threading
import logging
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .exceptions import AppMeshTimeoutError
from .tcp_messages import ResponseMessage

logger = logging.getLogger(__name__)

EVENT_URI = "/appmesh/event"

# Synthetic event_type pushed to every registered callback when the demuxer
# stops or the underlying transport disconnects. Lets long-running waits
# (e.g. wait_for_async_run) unblock instead of hanging forever.
EVENT_TYPE_DISCONNECTED = "__disconnected__"


@dataclass
class AppEvent:
    """Represents a server-push event notification."""

    subscription_id: str = ""
    event_type: str = ""
    app_name: str = ""
    timestamp: int = 0
    sequence: int = 0
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubscriptionResult:
    """Server's response to a subscribe request."""

    subscription_id: str = ""
    app_name: str = ""
    events: list = field(default_factory=list)


EventCallback = Callable[[AppEvent], None]


class MessageDemuxer:
    """Reads messages from transport and routes to pending requests or event callbacks."""

    # Sentinel queued to the dispatch worker to make it exit cleanly.
    _DISPATCH_STOP = object()

    # Bound the pre-registration event buffer (atomic-subscribe race window) so a
    # subscription whose callback never registers cannot grow memory without limit.
    _MAX_BUFFERED_SUBS = 64
    _MAX_BUFFERED_EVENTS_PER_SUB = 1000

    def __init__(self, transport):
        self._transport = transport
        self._lock = threading.Lock()
        self._pending: Dict[str, threading.Event] = {}
        self._pending_responses: Dict[str, Optional[ResponseMessage]] = {}
        self._event_callbacks: Dict[str, EventCallback] = {}
        # Events that arrive between server-side subscription and the client
        # registering its callback (e.g. atomic add_app(subscribe_events) on a fast
        # app, whose output is pushed before add_app returns). Held per sub_id and
        # flushed on register_event_callback so no events are lost.
        self._event_buffers: Dict[str, "deque[AppEvent]"] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False
        # Single-worker FIFO queue serializes user callbacks so events arrive in
        # transport order, and bounds thread usage to 1 regardless of event rate.
        self._dispatch_queue: "queue.Queue[Any]" = queue.Queue()
        self._dispatch_thread: Optional[threading.Thread] = None

    def start(self):
        """Start the background reader and dispatch threads."""
        if self._running:
            return
        self._running = True
        self._dispatch_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
        self._dispatch_thread.start()
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def stop(self):
        """Signal the demuxer to stop and wake all pending waiters and event subscribers."""
        # Flip _running before draining _pending: send_and_receive's locked check
        # relies on this ordering to avoid registering a never-woken waiter.
        self._running = False
        # Fan out a synthetic disconnect event to every registered callback so
        # long-running waits (wait_for_async_run, custom subscribers) unblock.
        self._broadcast_disconnect()
        # Then drain pending request waiters.
        with self._lock:
            for evt in self._pending.values():
                evt.set()
            self._pending.clear()
            self._pending_responses.clear()
            self._event_buffers.clear()  # drop events buffered for never-registered subs
        # Stop the dispatch worker last so the disconnect event has been delivered.
        self._dispatch_queue.put(self._DISPATCH_STOP)

    def join(self, timeout: float = 5.0):
        """Wait for the reader and dispatch threads to finish."""
        if self._reader_thread:
            self._reader_thread.join(timeout=timeout)
            self._reader_thread = None
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=timeout)
            self._dispatch_thread = None

    def _broadcast_disconnect(self):
        """Push a synthetic disconnect event to every registered callback."""
        with self._lock:
            entries = list(self._event_callbacks.items())
        for sub_id, cb in entries:
            self._dispatch_queue.put((cb, AppEvent(subscription_id=sub_id, event_type=EVENT_TYPE_DISCONNECTED)))

    def send_and_receive(self, uuid: str, data: bytes, timeout: Optional[float] = None) -> Optional[ResponseMessage]:
        """Send a request and wait for the matching response via the demuxer.

        ``timeout=None`` waits indefinitely (long-blocking calls like ``run_app_sync`` can
        exceed any fixed cap); ``stop()`` wakes all pending waiters on disconnect."""
        evt = threading.Event()
        with self._lock:
            # Race with stop(): stop() flips _running before locking to drain _pending,
            # so a locked check observing True guarantees the drain will set this event.
            if not self._running:
                return None
            self._pending[uuid] = evt
            self._pending_responses[uuid] = None

        self._transport.send_message(data)

        evt.wait(timeout=timeout)

        with self._lock:
            self._pending.pop(uuid, None)
            resp = self._pending_responses.pop(uuid, None)

        return resp

    def register_event_callback(self, sub_id: str, callback: EventCallback):
        """Register a callback for a subscription ID, flushing any events that
        arrived before registration (atomic-subscribe race)."""
        with self._lock:
            self._event_callbacks[sub_id] = callback
            buffered = self._event_buffers.pop(sub_id, None)
            # Enqueue under the lock so buffered events precede later live events.
            if buffered:
                for event in buffered:
                    self._dispatch_queue.put((callback, event))

    def unregister_event_callback(self, sub_id: str):
        """Remove a callback for a subscription ID."""
        with self._lock:
            self._event_callbacks.pop(sub_id, None)
            self._event_buffers.pop(sub_id, None)

    def _read_loop(self):
        """Background thread: continuously reads and routes messages."""
        while self._running:
            try:
                resp_data = self._transport.receive_message()
                if not resp_data:
                    continue

                resp = ResponseMessage.from_bytes(resp_data)

                if resp.request_uri == EVENT_URI:
                    self._dispatch_event(resp)
                else:
                    self._dispatch_response(resp)

            except AppMeshTimeoutError:
                # Idle timeout (no events arrived within transport recv timeout) — keep reading
                continue
            except Exception as e:
                if self._running:
                    logger.warning("MessageDemuxer read error: %s", e)
                    self.stop()
                    break

    def _dispatch_event(self, resp: ResponseMessage):
        """Route event push to matching subscription callback (via dispatch queue)."""
        try:
            body = resp.body if isinstance(resp.body, str) else resp.body.decode("utf-8", errors="replace")
            event_data = json.loads(body)
            event = AppEvent(
                subscription_id=event_data.get("subscription_id", ""),
                event_type=event_data.get("event_type", ""),
                app_name=event_data.get("app_name", ""),
                timestamp=event_data.get("timestamp", 0),
                sequence=event_data.get("sequence", 0),
                data=event_data.get("data", {}),
            )

            sub_id = event.subscription_id or resp.headers.get("X-Subscription-Id", "")

            with self._lock:
                cb = self._event_callbacks.get(sub_id)
                if cb is None and sub_id:
                    self._buffer_event_locked(sub_id, event)

            if cb:
                self._dispatch_queue.put((cb, event))

        except Exception as e:
            logger.warning("Failed to dispatch event: %s", e)

    def _buffer_event_locked(self, sub_id: str, event: "AppEvent"):
        """Hold an event whose callback has not registered yet (caller holds _lock)."""
        buf = self._event_buffers.get(sub_id)
        if buf is None:
            if len(self._event_buffers) >= self._MAX_BUFFERED_SUBS:
                return  # cap distinct unregistered subs to bound memory
            buf = self._event_buffers[sub_id] = deque(maxlen=self._MAX_BUFFERED_EVENTS_PER_SUB)
        buf.append(event)

    def _dispatch_loop(self):
        """Single worker thread: invokes user callbacks in FIFO order."""
        while True:
            item = self._dispatch_queue.get()
            if item is self._DISPATCH_STOP:
                return
            cb, event = item
            try:
                cb(event)
            except Exception as e:
                logger.warning("Event callback raised: %s", e)

    def _dispatch_response(self, resp: ResponseMessage):
        """Route request response to the matching pending waiter."""
        with self._lock:
            evt = self._pending.get(resp.uuid)
            if evt:
                self._pending_responses[resp.uuid] = resp
                evt.set()
