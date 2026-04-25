"""Event subscription support for TCP and WSS transports."""
__all__ = ["AppEvent", "SubscriptionResult", "EVENT_TYPE_DISCONNECTED"]

import json
import queue
import threading
import logging
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

    def __init__(self, transport):
        self._transport = transport
        self._lock = threading.Lock()
        self._pending: Dict[str, threading.Event] = {}
        self._pending_responses: Dict[str, Optional[ResponseMessage]] = {}
        self._event_callbacks: Dict[str, EventCallback] = {}
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

    def send_and_receive(self, uuid: str, data: bytes, timeout: float = 60.0) -> Optional[ResponseMessage]:
        """Send a request and wait for the matching response via the demuxer."""
        evt = threading.Event()
        with self._lock:
            self._pending[uuid] = evt
            self._pending_responses[uuid] = None

        self._transport.send_message(data)

        evt.wait(timeout=timeout)

        with self._lock:
            self._pending.pop(uuid, None)
            resp = self._pending_responses.pop(uuid, None)

        return resp

    def register_event_callback(self, sub_id: str, callback: EventCallback):
        """Register a callback for a subscription ID."""
        with self._lock:
            self._event_callbacks[sub_id] = callback

    def unregister_event_callback(self, sub_id: str):
        """Remove a callback for a subscription ID."""
        with self._lock:
            self._event_callbacks.pop(sub_id, None)

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

            if cb:
                self._dispatch_queue.put((cb, event))

        except Exception as e:
            logger.warning("Failed to dispatch event: %s", e)

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
