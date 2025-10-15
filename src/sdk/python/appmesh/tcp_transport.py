# tcp_transport.py
"""TCP Transport layer handling socket connections."""
__all__ = []

import socket
import ssl
import struct
from pathlib import Path
from typing import Optional, Union, Tuple


class TCPTransport:
    """TCP Transport layer with TLS support."""

    # Number of bytes used for the message length header
    # Must match the C++ service implementation which uses uint32_t (4 bytes)
    # Format: Big-endian unsigned 32-bit integer
    TCP_MESSAGE_HEADER_LENGTH = 8
    TCP_MESSAGE_MAGIC = 0x07C707F8  # Magic number
    TCP_MAX_BLOCK_SIZE = 100 * 1024 * 1024  # 100 MB

    def __init__(
        self,
        address: Tuple[str, int],
        ssl_verify: Union[bool, str],
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
    ):
        """
        Initialize TCP transport with TLS configuration.

        Args:
            address: Server address as (host, port) tuple.
            ssl_verify: SSL server verification mode:
                - True: Use system CA certificates
                - False:  Disable verification (insecure)
                - str: Path to custom CA bundle or directory
            ssl_client_cert: SSL client certificate:
                - str: Path to PEM file with cert and key
                - tuple: (cert_path, key_path)

        Note:
            TCP connections require an explicit full-chain CA specification for certificate validation,
            unlike HTTP, which can retrieve intermediate certificates automatically.
        """
        self.address = address
        self.ssl_verify = ssl_verify
        self.ssl_client_cert = ssl_client_cert
        self._socket: Optional[ssl.SSLSocket] = None

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
        except Exception:
            pass  # suppress all exceptions

    def connect(self) -> None:
        """Establish TLS connection to server."""
        context = self._create_ssl_context()
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(True)
        # sock.settimeout(30)  # Connection timeout set to 30 seconds

        try:
            # Wrap the socket with SSL/TLS
            ssl_socket = context.wrap_socket(sock, server_hostname=self.address[0])
            ssl_socket.connect(self.address)
            # Disable Nagle's algorithm
            ssl_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # After connecting, set separate timeout for recv/send
            # ssl_socket.settimeout(20)  # 20 seconds for recv/send
            self._socket = ssl_socket
        except (socket.error, ssl.SSLError) as e:
            sock.close()
            raise RuntimeError(f"Failed to connect to {self.address}: {e}") from e

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create and configure SSL context."""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

        # Set minimum TLS version
        if hasattr(context, "minimum_version"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1

        # Configure SSL verification
        if not self.ssl_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification
            context.load_default_certs()  # Load system's default CA certificates

            if isinstance(self.ssl_verify, str):
                path = Path(self.ssl_verify)
                if path.is_file():
                    # Load custom CA certificate file
                    context.load_verify_locations(cafile=str(path))
                elif path.is_dir():
                    # Load CA certificates from directory
                    context.load_verify_locations(capath=str(path))
                else:
                    raise ValueError(f"ssl_verify path '{self.ssl_verify}' is invalid")

        # Load client certificate if provided
        if self.ssl_client_cert:
            if isinstance(self.ssl_client_cert, tuple):
                # Separate cert and key files
                context.load_cert_chain(certfile=self.ssl_client_cert[0], keyfile=self.ssl_client_cert[1])
            else:
                # Cert and key in the same PEM file
                context.load_cert_chain(certfile=self.ssl_client_cert)

        return context

    def close(self) -> None:
        """Close socket"""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
            finally:
                self._socket = None

    def connected(self) -> bool:
        """Socket is connected or not"""
        return self._socket is not None

    def send_message(self, data: Union[bytes, bytearray, list]) -> None:
        """
        Send a message with prefixed header.

        Args:
            data: Message data to send, or empty list for EOF signal.
        """
        if not self._socket:
            raise RuntimeError("Cannot send message: not connected")

        try:
            length = len(data) if data else 0
            # Pack the header into 8 bytes using big-endian format
            header = struct.pack("!II", self.TCP_MESSAGE_MAGIC, length)
            self._socket.sendall(header)

            if length > 0:
                self._socket.sendall(data)
        except (socket.error, ssl.SSLError) as e:
            self.close()
            raise RuntimeError(f"Error sending message: {e}") from e

    def receive_message(self) -> Optional[bytearray]:
        """
        Receive a message with prefixed header.

        Returns:
            Message data, or None for EOF signal.
        """
        if not self._socket:
            raise RuntimeError("Cannot receive message: not connected")

        try:
            # Unpack the data (big-endian format)
            magic, length = struct.unpack("!II", self._recvall(self.TCP_MESSAGE_HEADER_LENGTH))

            if magic != self.TCP_MESSAGE_MAGIC:
                raise ValueError(f"Invalid magic number: 0x{magic:X}")

            if length > self.TCP_MAX_BLOCK_SIZE:
                raise ValueError(f"Message size {length} exceeds maximum {self.TCP_MAX_BLOCK_SIZE}")

            return self._recvall(length) if length > 0 else None

        except (socket.error, ssl.SSLError) as e:
            self.close()
            raise RuntimeError(f"Error receiving message: {e}") from e

    def _recvall(self, length: int) -> bytes:
        """
        Receive exactly `length` bytes from socket.
        https://stackoverflow.com/questions/64466530/using-a-custom-socket-recvall-function-works-only-if-thread-is-put-to-sleep

        Args:
            length: Number of bytes to receive.

        Returns:
            Received data.

        Raises:
            EOFError: If connection closes before receiving all data.
            ValueError: If length is not positive.
        """
        if length <= 0:
            raise ValueError(f"Invalid length: {length}")

        # Pre-allocate buffer
        buffer = bytearray(length)
        view = memoryview(buffer)
        bytes_received = 0

        while bytes_received < length:
            try:
                # Receive directly into buffer
                remaining = length - bytes_received
                chunk_size = self._socket.recv_into(view, remaining)

                if chunk_size == 0:
                    raise EOFError("Connection closed by peer")

                view = view[chunk_size:]  # advance memoryview
                bytes_received += chunk_size

            except InterruptedError:
                continue
            except socket.timeout as e:
                raise socket.timeout(f"Socket timed out after receiving {bytes_received}/{length} bytes") from e

        return bytes(buffer)
