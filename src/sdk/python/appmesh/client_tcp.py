# client_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import socket
from pathlib import Path
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient
from .tcp_transport import TCPTransport
from .transport_mixin import TransportClientMixin


class AppMeshClientTCP(TransportClientMixin, AppMeshClient):
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
    _HTTP_USER_AGENT_TRANSPORT = "appmesh/python/tcp"
    _HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = "X-Send-File-Socket"
    _HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = "X-Recv-File-Socket"

    # Polling interval for wait_for_async_run (seconds)
    _POLL_INTERVAL = 1

    def __init__(
        self,
        tcp_address: Tuple[str, int] = ("127.0.0.1", 6059),
        ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        """Construct a TCP transport client that reuses the standard App Mesh client API.

        Args:
            tcp_address: Server address as (host, port) tuple, defaults to ("127.0.0.1", 6059).
            ssl_verify: SSL certificate verification behavior. Can be True, False, or a path to CA bundle.
              - True: Use system CA certificates (e.g., /etc/ssl/certs/ on Linux)
              - False:  Disable verification (insecure)
              - str: Path to custom CA bundle or directory
            ssl_client_cert: SSL client certificate:
              - str: Path to single PEM with cert+key
              - tuple: (cert_path, key_path)

        Note:
            TCP connections require an explicit full-chain CA specification for certificate validation,
            unlike HTTP, which can retrieve intermediate certificates automatically.
        """
        self.tcp_transport = TCPTransport(address=tcp_address, ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert)
        self._token = ""
        self._transport_client_addr = socket.gethostname()
        self._transport_name = "Socket"
        super().__init__(ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert)

    @property
    def _transport(self):
        """Return the TCP transport instance."""
        return self.tcp_transport

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
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # suppress all exceptions

    def download_file(self, remote_file: str, local_file: str, preserve_permissions: bool = True) -> None:
        """Copy a remote file to local through the TCP file-socket side channel.

        Args:
            remote_file: Remote file path.
            local_file: Local destination path.
            preserve_permissions: Apply remote file permissions/ownership locally on a best-effort basis.
        """
        header = {
            AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
            self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
        }

        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/file/download", header=header)

        if self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET not in resp.headers:
            raise ValueError(
                f"Server did not respond with socket transfer option: " f"{self._HTTP_HEADER_KEY_X_RECV_FILE_SOCKET}"
            )

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
        """Upload a local file to the remote server through the TCP file-socket side channel.

        Args:
            local_file: Local file path.
            remote_file: Remote destination path.
            preserve_permissions: Send local file permissions/ownership metadata when available.
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

        if self._HTTP_HEADER_KEY_X_SEND_FILE_SOCKET not in resp.headers:
            raise ValueError(
                f"Server did not respond with socket transfer option: " f"{self._HTTP_HEADER_KEY_X_SEND_FILE_SOCKET}"
            )

        # Upload file chunks
        with local_path.open("rb") as fp:
            while True:
                chunk_data = fp.read(self._TCP_BLOCK_SIZE)
                if not chunk_data:
                    self.tcp_transport.send_message([])  # EOF signal
                    break
                self.tcp_transport.send_message(chunk_data)
