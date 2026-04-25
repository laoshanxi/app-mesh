"""Event subscription support for TCP and WSS transports."""
__all__ = ["AppEvent", "SubscriptionResult"]

import json
import threading
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from .exceptions import AppMeshTimeoutError
from .tcp_messages import ResponseMessage

logger = logging.getLogger(__name__)

EVENT_URI = "/appmesh/event"


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

    def __init__(self, transport):
        self._transport = transport
        self._lock = threading.Lock()
        self._pending: Dict[str, threading.Event] = {}
        self._pending_responses: Dict[str, Optional[ResponseMessage]] = {}
        self._event_callbacks: Dict[str, EventCallback] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._running = False

    def start(self):
        """Start the background reader thread."""
        if self._running:
            return
        self._running = True
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def stop(self):
        """Signal the background reader thread to stop and wake pending waiters."""
        self._running = False
        with self._lock:
            for evt in self._pending.values():
                evt.set()
            self._pending.clear()
            self._pending_responses.clear()

    def join(self, timeout: float = 5.0):
        """Wait for the reader thread to finish after stop() + transport close."""
        if self._reader_thread:
            self._reader_thread.join(timeout=timeout)
            self._reader_thread = None

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
                    self._running = False
                    with self._lock:
                        for evt in self._pending.values():
                            evt.set()
                    break

    def _dispatch_event(self, resp: ResponseMessage):
        """Route event push to matching subscription callback."""
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
                threading.Thread(target=cb, args=(event,), daemon=True).start()

        except Exception as e:
            logger.warning("Failed to dispatch event: %s", e)

    def _dispatch_response(self, resp: ResponseMessage):
        """Route request response to the matching pending waiter."""
        with self._lock:
            evt = self._pending.get(resp.uuid)
            if evt:
                self._pending_responses[resp.uuid] = resp
                evt.set()
