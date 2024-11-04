"""Application output information"""

# pylint: disable=line-too-long,broad-exception-raised,	,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import json
import os
import socket
import ssl
import uuid

# Third-party imports
import requests
import msgpack

# Local application-specific imports
from .appmesh_client import AppMeshClient


class AppMeshClientTCP(AppMeshClient):
    """
    Client SDK for interacting with the App Mesh service over TCP, with enhanced support for large file transfers.

    The `AppMeshClientTCP` class extends the functionality of `AppMeshClient` by offering a TCP-based communication layer
    for the App Mesh REST API. It overrides the file download and upload methods to support large file transfers with
    improved performance, leveraging TCP for lower latency and higher throughput compared to HTTP.

    This client is suitable for applications requiring efficient data transfers and high-throughput operations within the
    App Mesh ecosystem, while maintaining compatibility with all other attributes and methods from `AppMeshClient`.

    Dependency:
        - Install the required package for message serialization:
            pip3 install msgpack

    Usage:
        - Import the client module:
            from appmesh import appmesh_client

    Example:
        client = appmesh_client.AppMeshClientTCP()
        client.login("your-name", "your-password")
        client.file_download("/tmp/os-release", "os-release")

    Attributes:
        - Inherits all attributes from `AppMeshClient`, including TLS secure connections and JWT-based authentication.
        - Optimized for TCP-based communication to provide better performance for large file transfers.

    Methods:
        - file_download()
        - file_upload()
        - Inherits all other methods from `AppMeshClient`, providing a consistent interface for managing applications within App Mesh.
    """

    TCP_BLOCK_SIZE = 16 * 1024 - 128  # TLS-optimized chunk size, leaves some room for TLS overhead (like headers) within the 16 KB limit.
    TCP_HEADER_LENGTH = 4
    ENCODING_UTF8 = "utf-8"
    HTTP_USER_AGENT_TCP = "appmesh/python/tcp"
    HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = "X-Send-File-Socket"
    HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = "X-Recv-File-Socket"

    def __init__(
        self,
        rest_ssl_verify=AppMeshClient.DEFAULT_SSL_CA_CERT_PATH if os.path.exists(AppMeshClient.DEFAULT_SSL_CA_CERT_PATH) else False,
        rest_ssl_client_cert=None,
        jwt_token=None,
        tcp_address=("localhost", 6059),
    ):
        """Construct an App Mesh client TCP object to communicate securely with an App Mesh server over TLS.

        Args:
            rest_ssl_verify (Union[bool, str], optional): Specifies SSL certificate verification behavior. Can be:
                - `True`: Uses the system’s default CA certificates to verify the server’s identity.
                - `False`: Disables SSL certificate verification (insecure, intended for development).
                - `str`: Specifies a custom CA bundle or directory for server certificate verification. If a string is provided,
                it should either be a file path to a custom CA certificate (CA bundle) or a directory path containing multiple
                certificates (CA directory).

                **Note**: Unlike HTTP requests, TCP connections cannot automatically retrieve intermediate or public CA certificates.
                When `rest_ssl_verify` is a path, it explicitly identifies a CA issuer to ensure certificate validation.

            rest_ssl_client_cert (Union[str, Tuple[str, str]], optional): Path to the SSL client certificate and key. If a `str`,
                it should be the path to a PEM file containing both the client certificate and private key. If a `tuple`, it should
                be a pair of paths: (`cert`, `key`), where `cert` is the client certificate file and `key` is the private key file.

            jwt_token (str, optional): JWT token for authentication. Used in methods requiring login and user authorization.

            tcp_address (Tuple[str, int], optional): Address and port for establishing a TCP connection to the server.
                Defaults to `("localhost", 6059)`.
        """
        self.tcp_address = tcp_address
        self.__socket_client = None
        super().__init__(rest_ssl_verify=rest_ssl_verify, rest_ssl_client_cert=rest_ssl_client_cert, jwt_token=jwt_token)

    def __del__(self) -> None:
        """De-construction"""
        self.__close_socket()

    def __connect_socket(self) -> ssl.SSLSocket:
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
        return ssl_socket

    def __close_socket(self) -> None:
        """Close socket connection"""
        if self.__socket_client:
            try:
                self.__socket_client.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
            finally:
                self.__socket_client = None

    def __recvall(self, length: int) -> bytearray:
        """socket recv data with fixed length
           https://stackoverflow.com/questions/64466530/using-a-custom-socket-recvall-function-works-only-if-thread-is-put-to-sleep
        Args:
            length (bytes): data length to be received

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
            chunk_size = self.__socket_client.recv_into(view[bytes_received:], length - bytes_received)

            if chunk_size == 0:
                raise EOFError("Connection closed by peer")

            bytes_received += chunk_size

        return buffer

    def _request_http(self, method: AppMeshClient.Method, path: str, query: dict = None, header: dict = None, body=None) -> requests.Response:
        """TCP API

        Args:
            method (Method): AppMeshClient.Method.
            path (str): URI patch str.
            query (dict, optional): HTTP query parameters.
            header (dict, optional): HTTP headers.
            body (_type_, optional): object to send in the body of the :class:`Request`.

        Returns:
            requests.Response: HTTP response
        """

        if self.__socket_client is None:
            self.__socket_client = self.__connect_socket()

        appmesh_request = RequestMsg()
        if super().jwt_token:
            appmesh_request.headers["Authorization"] = "Bearer " + super().jwt_token
        if super().forwarding_host and len(super().forwarding_host) > 0:
            raise Exception("Not support forward request in TCP mode")
        appmesh_request.headers[self.HTTP_HEADER_KEY_USER_AGENT] = self.HTTP_USER_AGENT_TCP
        appmesh_request.uuid = str(uuid.uuid1())
        appmesh_request.http_method = method.value
        appmesh_request.request_uri = path
        appmesh_request.client_addr = socket.gethostname()
        if body:
            if isinstance(body, dict) or isinstance(body, list):
                appmesh_request.body = bytes(json.dumps(body, indent=2), self.ENCODING_UTF8)
            elif isinstance(body, str):
                appmesh_request.body = bytes(body, self.ENCODING_UTF8)
            elif isinstance(body, bytes):
                appmesh_request.body = body
            else:
                raise Exception(f"UnSupported body type: {type(body)}")
        if header:
            for k, v in header.items():
                appmesh_request.headers[k] = v
        if query:
            for k, v in query.items():
                appmesh_request.querys[k] = v
        data = appmesh_request.serialize()
        self.__socket_client.sendall(len(data).to_bytes(self.TCP_HEADER_LENGTH, byteorder="big", signed=False))
        self.__socket_client.sendall(data)

        # https://developers.google.com/protocol-buffers/docs/pythontutorial
        # https://stackoverflow.com/questions/33913308/socket-module-how-to-send-integer
        resp_data = self.__recvall(int.from_bytes(self.__recvall(self.TCP_HEADER_LENGTH), byteorder="big", signed=False))
        if resp_data is None or len(resp_data) == 0:
            self.__close_socket()
            raise Exception("socket connection broken")
        appmesh_resp = ResponseMsg().desirialize(resp_data)
        response = requests.Response()
        response.status_code = appmesh_resp.http_status
        response.encoding = self.ENCODING_UTF8
        response._content = appmesh_resp.body.encode(self.ENCODING_UTF8)
        response.headers = appmesh_resp.headers
        if appmesh_resp.body_msg_type:
            response.headers["Content-Type"] = appmesh_resp.body_msg_type
        return response

    ########################################
    # File management
    ########################################
    def file_download(self, remote_file: str, local_file: str, apply_file_attributes: bool = True) -> None:
        """Copy a remote file to local, the local file will have the same permission as the remote file

        Args:
            remote_file (str): the remote file path.
            local_file (str): the local file path to be downloaded.
            apply_file_attributes (bool): whether to apply file attributes (permissions, owner, group) to the local file.
        """
        header = {"File-Path": remote_file}
        header[self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET] = "true"
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header=header)

        resp.raise_for_status()
        if self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET not in resp.headers:
            raise ValueError(f"Server did not respond with socket transfer option: {self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET}")

        with open(local_file, "wb") as fp:
            chunk_data = bytes()
            chunk_size = int.from_bytes(self.__recvall(self.TCP_HEADER_LENGTH), byteorder="big", signed=False)
            while chunk_size > 0:
                chunk_data = self.__recvall(chunk_size)
                if chunk_data is None or len(chunk_data) == 0:
                    self.__close_socket()
                    raise Exception("socket connection broken")
                fp.write(chunk_data)
                chunk_size = int.from_bytes(self.__recvall(self.TCP_HEADER_LENGTH), byteorder="big", signed=False)

        if apply_file_attributes:
            if "File-Mode" in resp.headers:
                os.chmod(path=local_file, mode=int(resp.headers["File-Mode"]))
            if "File-User" in resp.headers and "File-Group" in resp.headers:
                file_uid = int(resp.headers["File-User"])
                file_gid = int(resp.headers["File-Group"])
                try:
                    os.chown(path=local_file, uid=file_uid, gid=file_gid)
                except PermissionError:
                    print(f"Warning: Unable to change owner/group of {local_file}. Operation requires elevated privileges.")

    def file_upload(self, local_file: str, remote_file: str, apply_file_attributes: bool = True) -> None:
        """Upload a local file to the remote server, the remote file will have the same permission as the local file

        Dependency:
            sudo apt install python3-pip
            pip3 install requests_toolbelt

        Args:
            local_file (str): the local file path.
            remote_file (str): the target remote file to be uploaded.
            apply_file_attributes (bool): whether to upload file attributes (permissions, owner, group) along with the file.
        """
        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file not found: {local_file}")

        with open(file=local_file, mode="rb") as fp:
            header = {"File-Path": remote_file, "Content-Type": "text/plain"}
            header[self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET] = "true"

            if apply_file_attributes:
                file_stat = os.stat(local_file)
                header["File-Mode"] = str(file_stat.st_mode & 0o777)  # Mask to keep only permission bits
                header["File-User"] = str(file_stat.st_uid)
                header["File-Group"] = str(file_stat.st_gid)

            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/file/upload", header=header)

            resp.raise_for_status()
            if self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET not in resp.headers:
                raise ValueError(f"Server did not respond with socket transfer option: {self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET}")

            chunk_size = self.TCP_BLOCK_SIZE
            while True:
                chunk_data = fp.read(chunk_size)
                if not chunk_data:
                    self.__socket_client.sendall((0).to_bytes(self.TCP_HEADER_LENGTH, byteorder="big", signed=False))
                    break
                self.__socket_client.sendall(len(chunk_data).to_bytes(self.TCP_HEADER_LENGTH, byteorder="big", signed=False))
                self.__socket_client.sendall(chunk_data)


class RequestMsg:
    """HTTP request message"""

    uuid: str = ""
    request_uri: str = ""
    http_method: str = ""
    client_addr: str = ""
    body: bytes = b""
    headers: dict = {}
    querys: dict = {}

    def serialize(self) -> bytes:
        """Serialize request message to bytes"""
        # http://www.cnitblog.com/luckydmz/archive/2019/11/20/91959.html
        self_dict = vars(self)
        self_dict["headers"] = self.headers
        self_dict["querys"] = self.querys
        return msgpack.dumps(self_dict)


class ResponseMsg:
    """HTTP response message"""

    uuid: str = ""
    request_uri: str = ""
    http_status: int = 0
    body_msg_type: str = ""
    body: str = ""
    headers: dict = {}

    def desirialize(self, buf: bytes):
        """Deserialize response message"""
        dic = msgpack.unpackb(buf)
        for k, v in dic.items():
            setattr(self, k, v)
        return self
