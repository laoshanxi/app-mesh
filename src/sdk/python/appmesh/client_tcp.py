# client_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import json
from pathlib import Path
import socket
import uuid
from typing import Optional, Tuple, Union

# Third-party imports
import requests

# Local imports
from .client_http import AppMeshClient
from .tcp_messages import RequestMessage, ResponseMessage
from .tcp_transport import TCPTransport


class AppMeshClientTCP(AppMeshClient):
    """Client SDK for interacting with the App Mesh service over TCP.

    The `AppMeshClientTCP` class extends the functionality of `AppMeshClient` by offering a TCP-based communication layer
    for the App Mesh REST API. It overrides the file download and upload methods to support large file transfers with
    improved performance, leveraging TCP for lower latency and higher throughput compared to HTTP.

    This client is suitable for applications requiring efficient data transfers and high-throughput operations within the
    App Mesh ecosystem, while maintaining compatibility with all other attributes and methods from `AppMeshClient`.

    Attributes:
        Inherits all attributes from `AppMeshClient`, including TLS secure connections and JWT-based authentication.

    Methods:
        - download_file()
        - upload_file()
        - Inherits all other methods from `AppMeshClient`, providing a consistent interface for managing applications within App Mesh.

    Example:
        >>> from appmesh import AppMeshClientTCP
        >>> client = AppMeshClientTCP()
        >>> client.login("your-name", "your-password")
        >>> client.download_file("/tmp/os-release", "os-release")
    """

    # TLS-optimized chunk size, leaves room for TLS overhead within the 16 KB limit
    _TCP_BLOCK_SIZE = 16 * 1024 - 128
    _ENCODING_UTF8 = "utf-8"
    _HTTP_USER_AGENT_TCP = "appmesh/python/tcp"
    _HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = "X-Send-File-Socket"
    _HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = "X-Recv-File-Socket"

    def __init__(
        self,
        rest_ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        tcp_address: Tuple[str, int] = ("127.0.0.1", 6059),
    ):
        """Construct an App Mesh client TCP object to communicate securely with an App Mesh server over TLS.

        Args:
            rest_ssl_verify: SSL certificate verification behavior. Can be True, False, or a path to CA bundle.
              - True: Use system CA certificates (e.g., /etc/ssl/certs/ on Linux)
              - False:  Disable verification (insecure)
              - str: Path to custom CA bundle or directory
            ssl_client_cert: SSL client certificate:
              - str: Path to single PEM with cert+key
              - tuple: (cert_path, key_path)
            tcp_address: Server address as (host, port) tuple, defaults to ("127.0.0.1", 6059).

        Note:
            TCP connections require an explicit full-chain CA specification for certificate validation,
            unlike HTTP, which can retrieve intermediate certificates automatically.
        """
        self.tcp_transport = TCPTransport(address=tcp_address, ssl_verify=rest_ssl_verify, ssl_client_cert=rest_ssl_client_cert)
        self._token = ""
        super().__init__(rest_ssl_verify=rest_ssl_verify, rest_ssl_client_cert=rest_ssl_client_cert)

    def close(self) -> None:
        """Close the connection and release resources."""
        if hasattr(self, "tcp_transport") and self.tcp_transport:
            self.tcp_transport.close()
            self.tcp_transport = None
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
            return body

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

    def _request_http(self, method: AppMeshClient._Method, path: str, query: Optional[dict] = None, header: Optional[dict] = None, body=None) -> requests.Response:
        """Send HTTP request over TCP transport.

        Args:
            method: HTTP method.
            path: URI path.
            query: Query parameters.
            header: HTTP headers.
            body: Request body.

        Returns:
            Simulated HTTP response.
        """

        # Check for unsupported features
        if super().forward_to:
            raise RuntimeError("Forward request is not supported in TCP mode")

        if not self.tcp_transport.connected():
            self.tcp_transport.connect()

        # Prepare request message (ensure no fields are assigned None!)
        appmesh_request = RequestMessage()
        appmesh_request.uuid = str(uuid.uuid1())
        appmesh_request.http_method = method.value
        appmesh_request.request_uri = path
        appmesh_request.client_addr = socket.gethostname()
        appmesh_request.headers[self._HTTP_HEADER_KEY_USER_AGENT] = self._HTTP_USER_AGENT_TCP

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
        self.tcp_transport.send_message(data)

        # Receive response
        resp_data = self.tcp_transport.receive_message()
        if not resp_data:  # Covers None and empty bytes
            self.tcp_transport.close()
            raise ConnectionError("Socket connection broken")

        # Parse response
        appmesh_resp = ResponseMessage().deserialize(resp_data)
        response = requests.Response()
        response.status_code = appmesh_resp.http_status
        response.headers = appmesh_resp.headers

        # Set response content
        # response.encoding = self._ENCODING_UTF8 # only need when charset not in appmesh_resp.body_msg_type
        if isinstance(appmesh_resp.body, bytes):
            response._content = appmesh_resp.body
        else:
            response._content = str(appmesh_resp.body).encode(self._ENCODING_UTF8)

        # Set content type
        if appmesh_resp.body_msg_type:
            response.headers["Content-Type"] = appmesh_resp.body_msg_type

        return AppMeshClient._EncodingResponse(response)

    def download_file(self, remote_file: str, local_file: str, preserve_permissions: bool = True) -> None:
        """Copy a remote file to local, preserving file attributes if requested.

        Args:
            remote_file: Remote file path.
            local_file: Local destination path.
            preserve_permissions: Apply remote file permissions/ownership locally.
        """
        header = {
            AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
            self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
        }

        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/file/download", header=header)
        resp.raise_for_status()

        if self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET not in resp.headers:
            raise ValueError(f"Server did not respond with socket transfer option: " f"{self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET}")

        # Download file chunks
        local_path = Path(local_file)
        with local_path.open("wb") as fp:
            while True:
                chunk_data = self.tcp_transport.receive_message()
                if not chunk_data:
                    break
                fp.write(chunk_data)

        # Apply file attributes if requested
        if preserve_permissions:
            AppMeshClient._apply_file_attributes(local_path, resp.headers)

    def upload_file(self, local_file: str, remote_file: str, preserve_permissions: bool = True) -> None:
        """Upload a local file to remote server, preserving file attributes if requested.

        Args:
            local_file: Local file path.
            remote_file: Remote destination path.
            preserve_permissions: Upload file permissions/ownership metadata.
        """
        local_path = Path(local_file)
        if not local_path.exists():
            raise FileNotFoundError(f"Local file not found: {local_file}")

        # Prepare headers
        header = {
            AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
            "Content-Type": "application/octet-stream",
            self._HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: "true",
        }
        if preserve_permissions:
            header.update(AppMeshClient._get_file_attributes(local_path))

        # Initiate upload
        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/file/upload", header=header)
        resp.raise_for_status()

        if self._HTTP_HEADER_KEY_X_SEND_FILE_SOCKET not in resp.headers:
            raise ValueError(f"Server did not respond with socket transfer option: " f"{self._HTTP_HEADER_KEY_X_SEND_FILE_SOCKET}")

        # Upload file chunks
        with local_path.open("rb") as fp:
            while True:
                chunk_data = fp.read(self._TCP_BLOCK_SIZE)
                if not chunk_data:
                    self.tcp_transport.send_message([])  # EOF signal
                    break
                self.tcp_transport.send_message(chunk_data)
