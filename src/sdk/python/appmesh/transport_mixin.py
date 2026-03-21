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
from .client_http import AppMeshClient
from .exceptions import AppMeshConnectionError
from .tcp_messages import RequestMessage, ResponseMessage


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

        # Send request
        data = appmesh_request.serialize()
        transport.send_message(data)

        # Receive response
        resp_data = transport.receive_message()
        if not resp_data:  # Covers None and empty bytes
            transport.close()
            raise AppMeshConnectionError(f"{self._transport_name} connection broken")

        # Parse response
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

        return AppMeshClient._EncodingResponse(response)
