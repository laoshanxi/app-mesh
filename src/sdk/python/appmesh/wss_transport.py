# wss_transport.py
"""WebSocket Secure (WSS) Transport layer handling WebSocket connections."""
__all__ = []

import ssl
import socket
from pathlib import Path
from typing import Optional, Union, Tuple

try:
    from websocket import create_connection, WebSocketException, WebSocketTimeoutException
except ImportError as exc:
    raise ImportError(
        "websocket-client library is required for WSS support. Install it with: pip install websocket-client"
    ) from exc


class WSSTransport:
    """WebSocket Secure (WSS) Transport layer with TLS support using synchronous websocket-client library."""

    # Maximum message size: 100 MB
    WSS_MAX_BLOCK_SIZE = 100 * 1024 * 1024
    # Default connect timeout in seconds
    WSS_CONNECT_TIMEOUT = 30
    # Default message timeout in seconds
    WSS_MESSAGE_TIMEOUT = 60

    def __init__(
        self,
        address: Tuple[str, int],
        ssl_verify: Union[bool, str],
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        """
        Initialize WebSocket Secure (WSS) transport with TLS configuration.

        Args:
            address: Server address as (host, port) tuple.
            ssl_verify: SSL server verification mode:
                - True: Use system CA certificates
                - False: Disable verification (insecure)
                - str: Path to custom CA bundle or directory
            ssl_client_cert: SSL client certificate:
                - str: Path to PEM file with cert and key
                - tuple: (cert_path, key_path)

        Note:
            This implementation uses synchronous blocking sockets for WebSocket connections.
            No threading or asyncio is involved for simplicity and reliability.
        """
        self.address = address
        self.ssl_verify = ssl_verify
        self.ssl_client_cert = ssl_client_cert
        self._websocket = None
        self._connect_timeout = self.WSS_CONNECT_TIMEOUT
        self._message_timeout = self.WSS_MESSAGE_TIMEOUT

    def __enter__(self):
        """Context manager entry."""
        if not self.connected():
            self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # suppress all exceptions

    def __str__(self) -> str:
        """Return WSS URI representation."""
        host, port = self.address
        scheme = "wss" if self.ssl_verify else "ws"
        return f"{scheme}://{host}:{port}"

    def connect(self) -> None:
        """Establish WSS connection to server."""
        if self.connected():
            return

        uri = f"{self}/"
        sslopt: dict = {}

        # Prepare SSL options for websocket-client library
        if self.ssl_verify is not False:
            sslopt["cert_reqs"] = ssl.CERT_REQUIRED
            if isinstance(self.ssl_verify, str):
                # Use custom CA bundle or directory
                path = Path(self.ssl_verify)
                if path.is_file():
                    sslopt["ca_certs"] = str(path)
                elif path.is_dir():
                    sslopt["ca_certs"] = str(path)
                else:
                    raise ValueError(f"ssl_verify path '{self.ssl_verify}' is invalid")
        else:
            # Disable verification (insecure)
            sslopt["cert_reqs"] = ssl.CERT_NONE
            sslopt["check_hostname"] = False

        # Add client certificate if provided
        if self.ssl_client_cert:
            if isinstance(self.ssl_client_cert, tuple):
                sslopt["certfile"] = self.ssl_client_cert[0]
                sslopt["keyfile"] = self.ssl_client_cert[1]
            else:
                sslopt["certfile"] = self.ssl_client_cert

        try:
            # Create WebSocket connection using websocket-client library
            self._websocket = create_connection(
                uri,
                timeout=self._connect_timeout,
                subprotocols=["appmesh-ws"],
                sslopt=sslopt if sslopt else None,
            )
            # Set receive timeout for blocking recv calls
            self._websocket.settimeout(self._message_timeout)

        except (socket.timeout, socket.error, ssl.SSLError) as e:
            self._websocket = None
            raise RuntimeError(f"Failed to connect to {self.address}: {e}") from e

    def close(self) -> None:
        """Close WebSocket connection."""
        if self._websocket:
            try:
                self._websocket.close()
            except Exception:  # pylint: disable=broad-exception-caught
                pass
            finally:
                self._websocket = None

    def connected(self) -> bool:
        """Check if WebSocket is connected."""
        if self._websocket is None:
            return False
        try:
            # For websocket-client library, check the connected property
            if hasattr(self._websocket, "connected"):
                return self._websocket.connected
            # Fallback: if object exists, assume it's connected
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            return False

    def send_message(self, data: Union[bytes, bytearray, list]) -> None:
        """
        Send a message over WebSocket.

        Args:
            data: Message data to send, or empty list for EOF signal.

        Note:
            WebSocket handles message framing automatically,
            so we don't need to add a length header. Just send msgpack-serialized data directly.
        """
        if not self._websocket:
            raise RuntimeError("Cannot send message: not connected")

        try:
            # Convert empty list to empty bytes for EOF signal
            message_data = bytes(data) if data else b""
            self._websocket.send_binary(message_data)

        except socket.timeout as e:
            self.close()
            raise TimeoutError(f"Message send timeout after {self._message_timeout}s") from e
        except (ConnectionError, WebSocketException) as e:
            self.close()
            raise ConnectionError(f"WebSocket connection closed: {e}") from e
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.close()
            raise RuntimeError(f"Error sending message: {e}") from e

    def receive_message(self) -> Optional[bytearray]:
        """
        Receive a message from WebSocket.

        Returns:
            Message data as bytearray, or None for EOF signal (empty bytes).

        Note:
            WebSocket frames are already separated by the protocol, so we don't need
            to parse a length header like in TCP transport.
        """
        if not self._websocket:
            raise RuntimeError("Cannot receive message: not connected")

        try:
            # Receive frame directly to handle both text and binary frames
            frame = self._websocket.recv_frame()

            if not frame:
                return bytearray()

            # Get the frame data
            data = frame.data

            # Handle empty data (EOF signal)
            if not data:
                return bytearray()

            # Handle both text and binary frames
            if isinstance(data, str):
                # Text frame - convert to bytes
                return bytearray(data.encode("utf-8"))
            elif isinstance(data, bytes):
                # Binary frame - convert to bytearray
                return bytearray(data)
            else:
                raise TypeError(f"Unexpected data type from WebSocket: {type(data)}")

        except socket.timeout as e:
            self.close()
            raise TimeoutError(f"Message receive timeout after {self._message_timeout}s") from e
        except WebSocketTimeoutException as e:
            self.close()
            raise TimeoutError(f"WebSocket timeout: {e}") from e
        except (ConnectionError, WebSocketException) as e:
            self.close()
            raise ConnectionError(f"WebSocket connection closed: {e}") from e
        except Exception as e:  # pylint: disable=broad-exception-caught
            self.close()
            raise RuntimeError(f"Error receiving message: {e}") from e
