# tcp_transport.py

import os
import socket
import ssl
import struct
from typing import Optional, Tuple, Union


class TCPTransport:
    """TCP Transport layer handling socket connections"""

    # Number of bytes used for the message length header
    # Must match the C++ service implementation which uses uint32_t (4 bytes)
    # Format: Big-endian unsigned 32-bit integer
    TCP_MESSAGE_HEADER_LENGTH = 8
    TCP_MESSAGE_MAGIC = 0x07C707F8  # Magic number
    TCP_MAX_BLOCK_SIZE = 1024 * 1024 * 100  # 100 MB message size limit

    def __init__(self, address: Tuple[str, int], ssl_verify: Union[bool, str], ssl_client_cert: Union[str, Tuple[str, str]]):
        """Construct an TCPTransport object to send and recieve TCP data.

        Args:
            ssl_verify (Union[bool, str], optional): Specifies SSL certificate verification behavior. Can be:
                - `True`: Uses the system's default CA certificates to verify the server's identity.
                - `False`: Disables SSL certificate verification (insecure, intended for development).
                - `str`: Specifies a custom CA bundle or directory for server certificate verification. If a string is provided,
                it should either be a file path to a custom CA certificate (CA bundle) or a directory path containing multiple
                certificates (CA directory).

                **Note**: Unlike HTTP requests, TCP connections cannot automatically retrieve intermediate or public CA certificates.
                When `rest_ssl_verify` is a path, it explicitly identifies a CA issuer to ensure certificate validation.

            ssl_client_cert (Union[str, Tuple[str, str]], optional): Path to the SSL client certificate and key. If a `str`,
                it should be the path to a PEM file containing both the client certificate and private key. If a `tuple`, it should
                be a pair of paths: (`cert`, `key`), where `cert` is the client certificate file and `key` is the private key file.

            tcp_address (Tuple[str, int], optional): Address and port for establishing a TCP connection to the server.
                Defaults to `("localhost", 6059)`.
        """
        self.tcp_address = address
        self.ssl_verify = ssl_verify
        self.ssl_client_cert = ssl_client_cert
        self._socket = None

    def __enter__(self):
        """Context manager entry"""
        if not self.connected():
            self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    def __del__(self) -> None:
        """De-construction"""
        self.close()

    def connect(self) -> None:
        """Establish tcp connection"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        # Set minimum TLS version
        if hasattr(context, "minimum_version"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        # Configure SSL verification
        if not self.ssl_verify:
            context.verify_mode = ssl.CERT_NONE
        else:
            context.verify_mode = ssl.CERT_REQUIRED  # Require certificate verification
            context.load_default_certs()  # Load system's default CA certificates
            if isinstance(self.ssl_verify, str):
                if os.path.isfile(self.ssl_verify):
                    # Load custom CA certificate file
                    context.load_verify_locations(cafile=self.ssl_verify)
                elif os.path.isdir(self.ssl_verify):
                    # Load CA certificates from directory
                    context.load_verify_locations(capath=self.ssl_verify)
                else:
                    raise ValueError(f"ssl_verify path '{self.ssl_verify}' is neither a file nor a directory")

        if self.ssl_client_cert is not None:
            # Load client-side certificate and private key
            context.load_cert_chain(certfile=self.ssl_client_cert[0], keyfile=self.ssl_client_cert[1])

        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(True)
        sock.settimeout(30)  # Connection timeout set to 30 seconds
        # Wrap the socket with SSL/TLS
        ssl_socket = context.wrap_socket(sock, server_hostname=self.tcp_address[0])
        # Connect to the server
        ssl_socket.connect(self.tcp_address)
        # Disable Nagle's algorithm
        ssl_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # After connecting, set separate timeout for recv/send
        # ssl_socket.settimeout(20)  # 20 seconds for recv/send
        self._socket = ssl_socket

    def close(self) -> None:
        """Close socket connection"""
        if self._socket:
            try:
                self._socket.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
            finally:
                self._socket = None

    def connected(self) -> bool:
        """Check whether socket is connected"""
        return self._socket is not None

    def send_message(self, data) -> None:
        """Send a message with a prefixed header indicating its length"""
        length = len(data)
        # Pack the header into 8 bytes using big-endian format
        self._socket.sendall(struct.pack("!II", self.TCP_MESSAGE_MAGIC, length))
        if length > 0:
            self._socket.sendall(data)

    def receive_message(self) -> Optional[bytearray]:
        """Receive a message with a prefixed header indicating its length and validate it"""
        # Unpack the data (big-endian format)
        magic, length = struct.unpack("!II", self._recvall(self.TCP_MESSAGE_HEADER_LENGTH))
        if magic != self.TCP_MESSAGE_MAGIC:
            raise ValueError(f"Invalid message: incorrect magic number 0x{magic:X}.")
        if length > self.TCP_MAX_BLOCK_SIZE:
            raise ValueError(f"Message size {length} exceeds the maximum allowed size of {self.TCP_MAX_BLOCK_SIZE} bytes.")
        if length > 0:
            return self._recvall(length)
        return None

    def _recvall(self, length: int) -> bytearray:
        """socket recv data with fixed length
           https://stackoverflow.com/questions/64466530/using-a-custom-socket-recvall-function-works-only-if-thread-is-put-to-sleep
        Args:
            length (int): data length to be received

        Returns:
            bytearray: Received data

        Raises:
            EOFError: If connection closes prematurely
            ValueError: If length is invalid
        """
        if length <= 0:
            raise ValueError(f"Invalid length: {length}")

        # Pre-allocate buffer of exact size needed
        buffer = bytearray(length)
        view = memoryview(buffer)
        bytes_received = 0

        while bytes_received < length:
            # Use recv_into to read directly into our buffer
            chunk_size = self._socket.recv_into(view[bytes_received:], length - bytes_received)

            if chunk_size == 0:
                raise EOFError("Connection closed by peer")

            bytes_received += chunk_size

        return buffer
