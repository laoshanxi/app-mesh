# client_wss.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
from http import HTTPStatus
from pathlib import Path
from typing import Optional, Tuple, Union
from urllib import parse

# Third-party imports
import requests

# Local imports
from .client_http import AppMeshClient
from .wss_transport import WSSTransport
from .transport_mixin import TransportClientMixin


class AppMeshClientWSS(TransportClientMixin, AppMeshClient):
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
    _HTTP_USER_AGENT_TRANSPORT = "appmesh/python/wss"

    # Polling interval for wait_for_async_run (seconds)
    _POLL_INTERVAL = 1

    def __init__(
        self,
        wss_address: Tuple[str, int] = ("127.0.0.1", 6058),
        ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        """Construct a WSS transport client that reuses the standard App Mesh client API.

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
        self._transport_client_addr = "wss-client"
        self._transport_name = "WebSocket"
        # http and websocket share same address
        host, port = wss_address
        super().__init__(base_url=f"https://{host}:{port}", ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert)

    @property
    def _transport(self):
        """Return the WSS transport instance."""
        return self.wss_transport

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

    def download_file(self, remote_file: str, local_file: str, preserve_permissions: bool = True) -> None:
        """Copy a remote file to local through the WSS control channel plus HTTPS data channel.

        Args:
            remote_file: Remote file path.
            local_file: Local destination path.
            preserve_permissions: Apply remote file permissions/ownership locally on a best-effort basis.
        """
        header = {AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file}
        resp = self._request_http(AppMeshClient._Method.GET, path="/appmesh/file/download", header=header)
        if self._HTTP_HEADER_KEY_AUTH not in resp.headers:
            raise ValueError(f"Server did not respond with file transfer authentication: {self._HTTP_HEADER_KEY_AUTH}")

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
                AppMeshClient._apply_file_attributes(local_path, r.headers)
        else:
            r.raise_for_status()

    def upload_file(self, local_file: str, remote_file: str, preserve_permissions: bool = True) -> None:
        """Upload a local file through the WSS control channel plus HTTPS data channel.

        Args:
            local_file: Local file path.
            remote_file: Remote destination path.
            preserve_permissions: Send local file permissions/ownership metadata when available.
        """
        header = {AppMeshClient._HTTP_HEADER_KEY_X_FILE_PATH: remote_file}
        resp = self._request_http(AppMeshClient._Method.POST, path="/appmesh/file/upload", header=header)
        if self._HTTP_HEADER_KEY_AUTH not in resp.headers:
            raise ValueError(f"Server did not respond with file transfer authentication: {self._HTTP_HEADER_KEY_AUTH}")

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
            header.update(AppMeshClient._get_file_attributes(local_path))
        rest_url = parse.urljoin(self.base_url, path)

        with local_path.open("rb") as fp:
            r = requests.post(url=rest_url, stream=True, data=fp, timeout=120, headers=header, verify=self.ssl_verify)
            r.raise_for_status()
