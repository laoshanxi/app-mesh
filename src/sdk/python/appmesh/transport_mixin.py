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
from .exceptions import AppMeshAppRemovedError, AppMeshAuthError, AppMeshConnectionError
from .subscribe import (
    EVENT_TYPE_DISCONNECTED,
    AppEvent,
    EventCallback,
    MessageDemuxer,
    SubscriptionResult,
)
from .tcp_messages import RequestMessage, ResponseMessage

logger = logging.getLogger(__name__)

class TransportClientMixin:
    """Mixin providing shared request/response logic for TCP and WSS transport clients.

    Design note: TCP/WSS clients deliberately inherit AppMeshClient rather than wrap it —
    every REST method funnels through ``_request_http``, so overriding that one choke point
    with msgpack framing (adapted into a ``requests.Response``) reuses all inherited methods
    and bearer-token injection unchanged, at the cost of a mostly idle ``requests.Session``
    (which the WSS client reuses for its file-transfer HTTPS data channel).

    Subclasses must define:
        - _transport: the transport object (TCPTransport or WSSTransport)
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
        body_bytes = self._convert_bytes(body)
        caller_manages_auth = bool(
            header and any(key.lower() == self._HTTP_HEADER_KEY_AUTH.lower() for key in header)
        )
        provider = None if caller_manages_auth else self._token_provider
        rejected_token = None

        for attempt in range(2):
            transport = self._transport

            token = None
            if provider is not None:
                token = self._get_bearer_token(
                    force_refresh=attempt == 1,
                    rejected_token=rejected_token,
                )
            elif header:
                authorization = next(
                    (value for key, value in header.items() if key.lower() == self._HTTP_HEADER_KEY_AUTH.lower()),
                    None,
                )
                if authorization and authorization.lower().startswith("bearer "):
                    token = authorization[7:].strip()

            set_handshake_token = getattr(transport, "set_bearer_token", None)
            if set_handshake_token:
                set_handshake_token(token)
            if not transport.connected():
                transport.connect()

            # Prepare request message (ensure no fields are assigned None!)
            appmesh_request = RequestMessage()
            appmesh_request.uuid = str(uuid.uuid4())
            appmesh_request.http_method = method.value
            appmesh_request.request_uri = path
            appmesh_request.client_addr = self._transport_client_addr
            appmesh_request.headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT_TRANSPORT

            if provider is not None:
                # WSS authenticates once during upgrade; TCP has no handshake
                # and therefore carries the bearer in each request envelope.
                if token and not set_handshake_token:
                    appmesh_request.headers[self._HTTP_HEADER_KEY_AUTH] = f"Bearer {token}"

            target_host = self.forward_to
            if target_host:
                appmesh_request.headers[self._HTTP_HEADER_KEY_X_TARGET_HOST] = target_host
                # WSS authenticates the gateway during upgrade. A forwarded
                # request is a new hop, so the target must also receive and
                # validate the current bearer. TCP already follows this rule.
                if token:
                    appmesh_request.headers[self._HTTP_HEADER_KEY_AUTH] = f"Bearer {token}"
            if header:
                appmesh_request.headers.update(header)
            if query:
                appmesh_request.query.update(query)
            if body_bytes:
                appmesh_request.body = body_bytes

            data = appmesh_request.serialize()
            if self._demuxer and self._demuxer._running:
                # Demuxer is active — route through it to avoid concurrent socket reads.
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
            if isinstance(appmesh_resp.body, bytes):
                response._content = appmesh_resp.body
            else:
                response._content = str(appmesh_resp.body).encode(self._ENCODING_UTF8)
            if appmesh_resp.body_msg_type:
                response.headers["Content-Type"] = appmesh_resp.body_msg_type

            if (
                response.status_code == HTTPStatus.UNAUTHORIZED
                and attempt == 0
                and provider is not None
                and provider.can_refresh
            ):
                rejected_token = token
                continue

            if raise_on_fail:
                response.reason = str(response._content)
                response.url = f"{str(transport)}/{path.lstrip('/')}"
                if response.status_code in (HTTPStatus.UNAUTHORIZED, HTTPStatus.FORBIDDEN):
                    raise AppMeshAuthError(
                        f"HTTP {response.status_code}: {response.reason}",
                        response.status_code,
                    )
                response.raise_for_status()

            return AppMeshClient._EncodingResponse(response)

        raise AppMeshAuthError("TokenProvider failed to replace a rejected access token", HTTPStatus.UNAUTHORIZED)

    def add_app(self, app: App, subscribe_events: Optional[list] = None, callback: Optional[EventCallback] = None) -> App:
        """Register an app, optionally subscribing atomically and wiring a local callback.

        Reuses the base ``add_app`` for the HTTP round-trip + ``subscription_id`` parsing,
        then registers ``callback`` against the local demuxer keyed by the new subscription.
        """
        # The daemon creates the subscription before starting the app, so START can be
        # pushed before the add_app response on the same connection. Give the demuxer
        # ownership of the read side before sending the request; otherwise the synchronous
        # request path can consume that event frame as if it were the response.
        if subscribe_events:
            self._ensure_demuxer()
        result_app = super().add_app(app, subscribe_events=subscribe_events)
        if callback and result_app.subscription_id:
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
        # Once the server installs the subscription, an event may race its response.
        # Start the sole socket reader first so request replies and pushed events are
        # always separated by UUID/URI rather than by arrival order.
        self._ensure_demuxer()

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
        if self._demuxer and self._demuxer._running:
            return
        transport = self._transport
        set_handshake_token = getattr(transport, "set_bearer_token", None)
        if set_handshake_token:
            set_handshake_token(self._get_bearer_token())
        if not transport.connected():
            transport.connect()
        self._demuxer = MessageDemuxer(transport)
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
