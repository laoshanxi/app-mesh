# client_wss.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
from http import HTTPStatus
import json
from pathlib import Path
import uuid
from typing import Optional, Tuple, Union

# Third-party imports
from urllib import parse
import requests
from requests.structures import CaseInsensitiveDict

# Local imports
from .client_http import AppMeshClient
from .tcp_messages import RequestMessage, ResponseMessage
from .wss_transport import WSSTransport


class AppMeshClientWSS(AppMeshClient):
    """Client SDK for interacting with the App Mesh service over WebSocket Secure (WSS).

    The `AppMeshClientWSS` class extends the functionality of `AppMeshClient` by offering a WSS-based communication layer
    for the App Mesh REST API. It overrides the file download and upload methods to support large file transfers with
    improved performance, leveraging WebSocket for lower latency and higher throughput compared to HTTP.

    This client is suitable for applications requiring efficient bidirectional data transfers and high-throughput operations
    within the App Mesh ecosystem, while maintaining compatibility with all other attributes and methods from `AppMeshClient`.

    Attributes:
        Inherits all attributes from `AppMeshClient`, including TLS secure connections and JWT-based authentication.

    Methods:
        - download_file()
        - upload_file()
        - Inherits all other methods from `AppMeshClient`, providing a consistent interface for managing applications within App Mesh.

    Example:
        >>> from appmesh import AppMeshClientWSS
        >>> client = AppMeshClientWSS()
        >>> client.login("your-name", "your-password")
        >>> client.download_file("/tmp/os-release", "os-release")
    """

    # WSS-optimized chunk size
    _WSS_BLOCK_SIZE = 64 * 1024
    _ENCODING_UTF8 = "utf-8"
    _HTTP_USER_AGENT_WSS = "appmesh/python/wss"

    def __init__(
        self,
        wss_address: Tuple[str, int] = ("127.0.0.1", 6058),
        ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        """Construct an App Mesh client WSS object to communicate securely with an App Mesh server over TLS.

        Args:
            wss_address: Server address as (host, port) tuple, defaults to ("127.0.0.1", 6058).
            ssl_verify: SSL certificate verification behavior. Can be True, False, or a path to CA bundle.
              - True: Use system CA certificates (e.g., /etc/ssl/certs/ on Linux)
              - False: Disable verification (insecure)
              - str: Path to custom CA bundle or directory
            ssl_client_cert: SSL client certificate:
              - str: Path to single PEM with cert+key
              - tuple: (cert_path, key_path)

        Note:
            WSS connections require an explicit full-chain CA specification for certificate validation,
            unlike HTTP, which can retrieve intermediate certificates automatically.
        """
        self.wss_transport = WSSTransport(address=wss_address, ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert)
        self._token = ""
        # http and websocket share same address
        host, port = wss_address
        super().__init__(rest_url=f"https://{host}:{port}", ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert)

    def close(self) -> None:
        """Close the connection and release resources."""
        if hasattr(self, "wss_transport") and self.wss_transport:
            self.wss_transport.close()
            self.wss_transport = None
        return super().close()

    def __del__(self):
        """Ensure resources are properly released when the object is garbage collected."""
        try:
            self.close()
        except Exception:
            pass  # Never raise in __del__

    def _covert_bytes(self, body) -> bytes:
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

    def _handle_token_update(self, token: Optional[str]) -> None:
        """Handle post action when token updated"""
        self._token = token
        super()._handle_token_update(token)

    def _get_access_token(self) -> Optional[str]:
        """Get the current access token."""
        return self._token

    def download_file(self, remote_file: str, local_file: str, preserve_permissions: bool = True) -> None:
        """Copy a remote file to local, preserving file attributes if requested.

        Args:
            remote_file: Remote file path.
            local_file: Local destination path.
            preserve_permissions: Apply remote file permissions/ownership locally.
        """
        header = {AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file}
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/file/download", header=header)
        if self._HTTP_HEADER_KEY_AUTH not in resp.headers:
            raise ValueError(f"Server did not respond with file transfer autentication: " f"{self._HTTP_HEADER_KEY_AUTH}")

        # Use requests to GET file
        local_path = Path(local_file)
        header = {
            AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
            AppMeshClient._HTTP_HEADER_KEY_AUTH: resp.headers[self._HTTP_HEADER_KEY_AUTH],
        }
        path = "/appmesh/file/download/ws"
        rest_url = parse.urljoin(self.base_url, path)
        r = requests.get(url=rest_url, stream=True, timeout=120, headers=header, verify=self.ssl_verify)
        if r.status_code == HTTPStatus.OK:
            # Write file in chunks
            with local_path.open("wb") as fp:
                for chunk in r.iter_content(chunk_size=self._WSS_BLOCK_SIZE):
                    if chunk:
                        fp.write(chunk)

            # Apply file attributes if requested
            if preserve_permissions:
                AppMeshClient._apply_file_attributes(local_path, r.headers)  # TODO
        else:
            r.raise_for_status()

    def upload_file(self, local_file: str, remote_file: str, preserve_permissions: bool = True) -> None:
        """Upload a local file to remote server, preserving file attributes if requested.

        Args:
            local_file: Local file path.
            remote_file: Remote destination path.
            preserve_permissions: Upload file permissions/ownership metadata.
        """
        header = {AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file}
        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/file/upload", header=header)
        if self._HTTP_HEADER_KEY_AUTH not in resp.headers:
            raise ValueError(f"Server did not respond with file transfer autentication: " f"{self._HTTP_HEADER_KEY_AUTH}")

        local_path = Path(local_file)
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_file}")

        # Upload file with http
        path = "/appmesh/file/upload/ws"
        header = {
            AppMeshClient._HTTP_HEADER_KEY_AUTH: resp.headers[self._HTTP_HEADER_KEY_AUTH],
            AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
        }
        if preserve_permissions:
            header.update(AppMeshClient._get_file_attributes(local_path))  # TODO
        rest_url = parse.urljoin(self.base_url, path)

        with local_path.open("rb") as fp:
            r = requests.post(url=rest_url, stream=True, data=fp, timeout=120, headers=header, verify=self.ssl_verify)
            r.raise_for_status()

    def _request_http(
        self,
        method: AppMeshClient._Method,
        path: str,
        query: Optional[dict] = None,
        header: Optional[dict] = None,
        body=None,
        raise_on_fail: bool = True,
    ) -> requests.Response:
        """Send HTTP request over WSS transport.

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

        # Check for unsupported features
        if super().forward_to:
            raise RuntimeError("Forward request is not supported in WSS mode")

        if not self.wss_transport.connected():
            self.wss_transport.connect()

        # Prepare request message (ensure no fields are assigned None!)
        appmesh_request = RequestMessage()
        appmesh_request.uuid = str(uuid.uuid1())
        appmesh_request.http_method = method.value
        appmesh_request.request_uri = path
        appmesh_request.client_addr = "wss-client"
        appmesh_request.headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT_WSS

        # Add authentication token
        token = self._get_access_token()
        if token:
            appmesh_request.headers[self._HTTP_HEADER_KEY_AUTH] = token

        # Add custom headers
        if header:
            appmesh_request.headers.update(header)

        # Add query parameters
        if query:
            appmesh_request.query.update(query)

        # Prepare body
        body_bytes = self._covert_bytes(body)
        if body_bytes:
            appmesh_request.body = body_bytes

        # Send request
        data = appmesh_request.serialize()
        self.wss_transport.send_message(data)

        # Receive response
        resp_data = self.wss_transport.receive_message()
        if not resp_data:  # Covers None and empty bytes
            self.wss_transport.close()
            raise ConnectionError("WebSocket connection broken")

        # Parse response
        appmesh_resp = ResponseMessage().deserialize(resp_data)
        response = requests.Response()
        response.status_code = appmesh_resp.http_status
        response.headers = CaseInsensitiveDict(appmesh_resp.headers)

        # Set response content
        # response.encoding = self._ENCODING_UTF8 # only need when charset not in appmesh_resp.body_msg_type
        if isinstance(appmesh_resp.body, bytes):
            response._content = appmesh_resp.body
        else:
            response._content = str(appmesh_resp.body).encode(self._ENCODING_UTF8)

        # Set content type
        if appmesh_resp.body_msg_type:
            response.headers["Content-Type"] = appmesh_resp.body_msg_type

        if raise_on_fail and response.status_code != HTTPStatus.PRECONDITION_REQUIRED:
            response.reason = str(response._content)
            response.url = f"{str(self.wss_transport)}/{path.lstrip('/')}"
            response.raise_for_status()

        return AppMeshClient._EncodingResponse(response)
