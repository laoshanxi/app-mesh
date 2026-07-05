# transport_mixin.py
"""Shared transport logic for TCP and WSS clients."""

# Standard library imports
import json
import logging
import threading
import uuid
from http import HTTPStatus
from typing import Optional

# Third-party imports
import requests
from requests.structures import CaseInsensitiveDict

# Local imports
from .app import App
from .app_run import OutputHandler
from .client_http import AppMeshClient
from .exceptions import AppMeshAppRemovedError, AppMeshConnectionError
from .subscribe import (
    EVENT_TYPE_DISCONNECTED,
    AppEvent,
    EventCallback,
    MessageDemuxer,
    SubscriptionResult,
)
from .tcp_messages import RequestMessage, ResponseMessage

logger = logging.getLogger(__name__)

# Auth endpoints where the server returns a new access_token in the JSON body.
# Login/auth/totp_validate: apply token only when X-Set-Cookie header is present
_AUTH_SET_COOKIE_PATHS = frozenset({"/appmesh/login", "/appmesh/auth", "/appmesh/totp/validate"})
# Renew/setup: always apply (client already has an active session)
_AUTH_RENEW_PATHS = frozenset({"/appmesh/token/renew", "/appmesh/totp/setup"})
_LOGOFF_PATH = "/appmesh/self/logoff"


class TransportClientMixin:
    """Mixin providing shared request/response logic for TCP and WSS transport clients.

    Design note: TCP/WSS clients deliberately inherit AppMeshClient rather than wrap it —
    every REST method funnels through ``_request_http``, so overriding that one choke point
    with msgpack framing (adapted into a ``requests.Response``) reuses all inherited methods
    and token/cookie persistence unchanged, at the cost of a mostly idle ``requests.Session``
    (which the WSS client reuses for its file-transfer HTTPS data channel).

    Subclasses must define:
        - _transport: the transport object (TCPTransport or WSSTransport)
        - _token: the current access token string
        - _HTTP_USER_AGENT_TRANSPORT: user agent string for this transport
    """

    _ENCODING_UTF8 = "utf-8"

    # Lazily created by _ensure_demuxer(); the class-level default keeps
    # close()/__del__ safe even when a subclass __init__ raised early.
    _demuxer: Optional[MessageDemuxer] = None

    # Persistent-connection transports can deliver app events (see AppMeshClient.supports_events)
    supports_events = True

    def _convert_bytes(self, body) -> bytes:
        """Prepare request body for transmission."""
        if body is None:
            return b""

        if isinstance(body, (bytes, bytearray, memoryview)):
            return bytes(body)

        if isinstance(body, str):
            return body.encode(self._ENCODING_UTF8)

        if isinstance(body, (dict, list)):
            return json.dumps(body).encode(self._ENCODING_UTF8)

        raise TypeError(f"Unsupported body type: {type(body)}")

    def _on_token_changed(self, token: Optional[str]) -> None:
        """Store token locally and delegate to base class."""
        self._token = token
        super()._on_token_changed(token)

    def _get_access_token(self) -> Optional[str]:
        """Get the current access token."""
        return self._token

    def _sync_transport_token(self, response, path: str, request_headers: Optional[dict]) -> None:
        """Extract and apply token from auth endpoint responses (TCP/WSS only).

        HTTP transport relies on Set-Cookie for automatic cookie jar updates;
        TCP/WSS must extract the token from the JSON response body.
        """
        if response.status_code != HTTPStatus.OK:
            return

        if path == _LOGOFF_PATH:
            self._on_token_changed(None)
            return

        # Login/auth/totp_validate: apply only when client requested cookie mode
        if path in _AUTH_SET_COOKIE_PATHS:
            if not request_headers or request_headers.get("X-Set-Cookie") != "true":
                return
        elif path not in _AUTH_RENEW_PATHS:
            return

        # Extract access_token from JSON body
        try:
            token = response.json().get("access_token")
            if token:
                self._on_token_changed(token)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    def _request_http(
        self,
        method: AppMeshClient._Method,
        path: str,
        query: Optional[dict] = None,
        header: Optional[dict] = None,
        body=None,
        raise_on_fail: bool = True,
    ) -> requests.Response:
        """Send HTTP request over transport.

        Args:
            method: HTTP method.
            path: URI path.
            query: Query parameters.
            header: HTTP headers.
            body: Request body.
            raise_on_fail: Raise exception on HTTP error.

        Returns:
            Simulated HTTP response.
        """
        transport = self._transport
        if not transport.connected():
            transport.connect()

        # Prepare request message (ensure no fields are assigned None!)
        appmesh_request = RequestMessage()
        appmesh_request.uuid = str(uuid.uuid4())
        appmesh_request.http_method = method.value
        appmesh_request.request_uri = path
        appmesh_request.client_addr = self._transport_client_addr
        appmesh_request.headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT_TRANSPORT

        # Add authentication token
        token = self._get_access_token()
        if token:
            appmesh_request.headers[self._HTTP_HEADER_KEY_AUTH] = token

        # Add forwarding host
        target_host = self.forward_to
        if target_host:
            appmesh_request.headers[self._HTTP_HEADER_KEY_X_TARGET_HOST] = target_host

        # Add custom headers
        if header:
            appmesh_request.headers.update(header)

        # Add query parameters
        if query:
            appmesh_request.query.update(query)

        # Prepare body
        body_bytes = self._convert_bytes(body)
        if body_bytes:
            appmesh_request.body = body_bytes

        # Send request and receive response
        data = appmesh_request.serialize()

        if self._demuxer and self._demuxer._running:
            # Demuxer is active — route through it to avoid concurrent socket reads.
            # No wait cap: a falsy result means the demuxer stopped (disconnect), not a slow request.
            appmesh_resp = self._demuxer.send_and_receive(appmesh_request.uuid, data)
            if not appmesh_resp:
                transport.close()
                raise AppMeshConnectionError(f"{self._transport_name} connection lost while waiting for response")
        else:
            transport.send_message(data)
            resp_data = transport.receive_message()
            if not resp_data:  # Covers None and empty bytes
                transport.close()
                raise AppMeshConnectionError(f"{self._transport_name} connection broken")
            appmesh_resp = ResponseMessage.from_bytes(resp_data)
        response = requests.Response()
        response.status_code = appmesh_resp.http_status
        response.headers = CaseInsensitiveDict(appmesh_resp.headers)

        # Set response content
        if isinstance(appmesh_resp.body, bytes):
            response._content = appmesh_resp.body
        else:
            response._content = str(appmesh_resp.body).encode(self._ENCODING_UTF8)

        # Set content type
        if appmesh_resp.body_msg_type:
            response.headers["Content-Type"] = appmesh_resp.body_msg_type

        if raise_on_fail and response.status_code != HTTPStatus.PRECONDITION_REQUIRED:
            response.reason = str(response._content)
            response.url = f"{str(transport)}/{path.lstrip('/')}"
            response.raise_for_status()

        # Auto-sync token from auth endpoint responses
        self._sync_transport_token(response, path, header)

        return AppMeshClient._EncodingResponse(response)

    def add_app(self, app: App, subscribe_events: Optional[list] = None, callback: Optional[EventCallback] = None) -> App:
        """Register an app, optionally subscribing atomically and wiring a local callback.

        Reuses the base ``add_app`` for the HTTP round-trip + ``subscription_id`` parsing,
        then registers ``callback`` against the local demuxer keyed by the new subscription.
        """
        result_app = super().add_app(app, subscribe_events=subscribe_events)
        if callback and result_app.subscription_id:
            self._ensure_demuxer()
            self._demuxer.register_event_callback(result_app.subscription_id, callback)
        return result_app

    def subscribe(self, app_name: str, events: Optional[list] = None, callback: Optional[EventCallback] = None) -> SubscriptionResult:
        """Subscribe to app events over the transport connection.

        Args:
            app_name: Application name, or "*" for all apps.
            events: List of event types (e.g. ["START", "EXIT", "STDOUT"]).
            callback: Function called with AppEvent for each received event.

        Returns:
            SubscriptionResult with subscription_id, app_name, and events.
        """
        path = "/appmesh/subscribe"
        if app_name and app_name != "*":
            path = f"/appmesh/app/{app_name}/subscribe"

        query = {}
        if events:
            query["events"] = ",".join(events)

        resp = self._request_http(AppMeshClient._Method.POST, path=path, query=query)
        result_data = resp.json()
        result = SubscriptionResult(
            subscription_id=result_data.get("subscription_id", ""),
            app_name=result_data.get("app_name", ""),
            events=result_data.get("events", []),
        )

        if callback and result.subscription_id:
            self._ensure_demuxer()
            self._demuxer.register_event_callback(result.subscription_id, callback)

        return result

    def unsubscribe(self, subscription_id: str) -> None:
        """Remove an event subscription.

        Args:
            subscription_id: The subscription ID returned by subscribe().
        """
        query = {"subscription_id": subscription_id}
        self._request_http(AppMeshClient._Method.DELETE, path="/appmesh/subscribe", query=query)

        if self._demuxer:
            self._demuxer.unregister_event_callback(subscription_id)

    def _ensure_demuxer(self) -> None:
        """Start the message demuxer if not already running."""
        if self._demuxer:
            return
        self._demuxer = MessageDemuxer(self._transport)
        self._demuxer.start()

    def wait_for_async_run(self, run, stdout_handler: Optional[OutputHandler] = None, timeout: int = 0) -> Optional[int]:
        """Override: use subscribe-based streaming on TCP/WSS instead of polling.

        Subscribes to ``STDOUT`` + ``EXIT`` + ``REMOVED``, then does a
        one-shot ``get_app_output`` to backfill bytes emitted before the subscribe
        took effect. Stdout events whose ``position`` is already covered by an
        earlier delivery are deduped (partial overlap → prefix trimmed).

        Returns:
            Exit code if the process finished, or ``None`` when ``timeout`` elapsed first.

        Raises:
            AppMeshAppRemovedError: If the app was removed before its exit was observed.
            AppMeshConnectionError: If the transport disconnected while waiting, or the
                daemon delivered an unparseable exit code.
        """
        if not run or not run.app_name:
            return None

        wait_timeout: Optional[float] = None if timeout in (0, None) else float(timeout)

        # Failure signaling (no sentinel exit codes — contract item 6):
        #   exit_code None + failure None → caller-side timeout (returns None)
        #   failure set → raised after cleanup
        exit_code: Optional[int] = None
        failure: Optional[Exception] = None
        disconnected = False  # transport died — skip cleanup (SDKContract cleanup policy)
        delivered_until = 0  # next-byte offset already passed to stdout_handler
        done = threading.Event()
        lock = threading.Lock()

        def deliver(chunk, pos: int) -> None:
            nonlocal delivered_until
            if not chunk:
                return
            chunk_bytes = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
            with lock:
                end = pos + len(chunk_bytes)
                if end <= delivered_until:
                    return
                start_pos = pos
                if pos < delivered_until:
                    chunk_bytes = chunk_bytes[delivered_until - pos:]
                    start_pos = delivered_until
                delivered_until = end
            if stdout_handler is not None:
                try:
                    stdout_handler(chunk_bytes.decode("utf-8", errors="replace"), start_pos)
                except Exception:
                    pass

        def on_event(event: AppEvent) -> None:
            nonlocal exit_code, failure, disconnected
            if event.event_type == "STDOUT":
                try:
                    pos = int(event.data.get("position", 0))
                except (TypeError, ValueError):
                    pos = 0
                deliver(event.data.get("output", ""), pos)
            elif event.event_type == "EXIT":
                try:
                    exit_code = int(event.data.get("exit_code"))
                except (TypeError, ValueError):
                    failure = AppMeshConnectionError(f"EXIT event for '{run.app_name}' carried an unparseable exit_code: {event.data.get('exit_code')!r}")
                done.set()
            elif event.event_type == "REMOVED":
                if exit_code is None and failure is None:
                    failure = AppMeshAppRemovedError(f"app '{run.app_name}' was removed before its exit was observed")
                done.set()
            elif event.event_type == EVENT_TYPE_DISCONNECTED:
                disconnected = True
                if exit_code is None and failure is None:
                    failure = AppMeshConnectionError(f"transport disconnected while waiting for '{run.app_name}' to exit")
                done.set()

        sub = self.subscribe(run.app_name, ["STDOUT", "EXIT", "REMOVED"], callback=on_event)

        try:
            # Backfill bytes emitted before subscribe took effect; also catches
            # the case where the process already exited.
            try:
                backfill = self.get_app_output(
                    app_name=run.app_name,
                    stdout_position=0,
                    stdout_index=0,
                    process_uuid=run.process_uuid,
                    timeout=0,
                )
                if backfill.output:
                    deliver(backfill.output, 0)
                if backfill.exit_code is not None and exit_code is None:
                    exit_code = backfill.exit_code
                    done.set()
            except Exception as exc:
                logger.warning("backfill failed for %s: %s", run.app_name, exc)

            done.wait(timeout=wait_timeout)
        finally:
            # Cleanup policy: after a disconnect the transport is dead — an unsubscribe would
            # silently reconnect and register a never-answered waiter.
            if not disconnected:
                try:
                    if sub.subscription_id:
                        self.unsubscribe(sub.subscription_id)
                except Exception:
                    pass
                # Best-effort delete on a real exit. On REMOVED/disconnect failures the
                # daemon already lost track or the app is gone — don't try to delete.
                if exit_code is not None and failure is None:
                    try:
                        self.delete_app(run.app_name)
                    except Exception:
                        pass

        if failure is not None:
            raise failure
        return exit_code
