# transport_mixin.py
"""Shared transport logic for TCP and WSS clients."""

# Standard library imports
import json
import uuid
from http import HTTPStatus
from typing import Optional

# Third-party imports
import requests
from requests.structures import CaseInsensitiveDict

# Local imports
from .app import App
from .client_http import AppMeshClient
from .exceptions import AppMeshConnectionError
from .subscribe import AppEvent, EventCallback, MessageDemuxer, SubscriptionResult
from .tcp_messages import RequestMessage, ResponseMessage

# Auth endpoints where the server returns a new access_token in the JSON body.
# Login/auth/totp_validate: apply token only when X-Set-Cookie header is present
_AUTH_SET_COOKIE_PATHS = frozenset({"/appmesh/login", "/appmesh/auth", "/appmesh/totp/validate"})
# Renew/setup: always apply (client already has an active session)
_AUTH_RENEW_PATHS = frozenset({"/appmesh/token/renew", "/appmesh/totp/setup"})
_LOGOFF_PATH = "/appmesh/self/logoff"


class TransportClientMixin:
    """Mixin providing shared request/response logic for TCP and WSS transport clients.

    Subclasses must define:
        - _transport: the transport object (TCPTransport or WSSTransport)
        - _token: the current access token string
        - _HTTP_USER_AGENT_TRANSPORT: user agent string for this transport
    """

    _ENCODING_UTF8 = "utf-8"

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

        if hasattr(self, "_demuxer") and self._demuxer and self._demuxer._running:
            # Demuxer is active — route through it to avoid concurrent socket reads
            appmesh_resp = self._demuxer.send_and_receive(appmesh_request.uuid, data, timeout=60.0)
            if not appmesh_resp:
                transport.close()
                raise AppMeshConnectionError(f"{self._transport_name} demuxer response timeout")
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
        """Register an app, optionally subscribing atomically with the same call.

        When ``subscribe_events`` and ``callback`` are both supplied, the subscription is registered
        on the server before the app spawns, so no events are missed; the callback is wired into the
        local demuxer keyed by the returned subscription_id (also attached to the App as
        ``app.subscription_id``).
        """
        query = {}
        if subscribe_events:
            query["subscribe_events"] = ",".join(subscribe_events)
        resp = self._request_http(AppMeshClient._Method.PUT, path=f"/appmesh/app/{app.name}", query=query or None, body=app.to_dict())
        result_data = resp.json()
        result_app = App(result_data)
        sub_id = result_data.get("subscription_id", "") if isinstance(result_data, dict) else ""
        if sub_id:
            result_app.subscription_id = sub_id
            if callback:
                self._ensure_demuxer()
                self._demuxer.register_event_callback(sub_id, callback)
        return result_app

    def subscribe(self, app_name: str, events: Optional[list] = None, callback: Optional[EventCallback] = None) -> SubscriptionResult:
        """Subscribe to app events over the transport connection.

        Args:
            app_name: Application name, or "*" for all apps.
            events: List of event types (e.g. ["process_start", "process_exit", "stdout"]).
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

        if hasattr(self, "_demuxer") and self._demuxer:
            self._demuxer.unregister_event_callback(subscription_id)

    def _ensure_demuxer(self) -> None:
        """Start the message demuxer if not already running."""
        if hasattr(self, "_demuxer") and self._demuxer:
            return
        self._demuxer = MessageDemuxer(self._transport)
        self._demuxer.start()
