# client_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

import json
import os
import socket
import uuid
import requests
from .client_http import AppMeshClient
from .tcp_transport import TCPTransport
from .tcp_messages import RequestMessage, ResponseMessage


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
            from appmesh import AppMeshClientTCP

    Example:
        client = AppMeshClientTCP()
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
        self.tcp_transport = TCPTransport(address=tcp_address, ssl_verify=rest_ssl_verify, ssl_client_cert=rest_ssl_client_cert)
        super().__init__(rest_ssl_verify=rest_ssl_verify, rest_ssl_client_cert=rest_ssl_client_cert, jwt_token=jwt_token)

    def close(self):
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
        super().__del__()

    def _request_http(self, method: AppMeshClient.Method, path: str, query: dict = None, header: dict = None, body=None) -> requests.Response:
        """Send HTTP request over TCP transport.

        Args:
            method (Method): HTTP method.
            path (str): URI path.
            query (dict, optional): Query parameters.
            header (dict, optional): HTTP headers.
            body: Request body.

        Returns:
            requests.Response: Simulated HTTP response.
        """
        if not self.tcp_transport.connected():
            self.tcp_transport.connect()

        appmesh_request = RequestMessage()
        if super().jwt_token:
            appmesh_request.headers["Authorization"] = "Bearer " + super().jwt_token
        if super().forward_to and len(super().forward_to) > 0:
            raise Exception("Not support forward request in TCP mode")
        appmesh_request.headers[self.HTTP_HEADER_KEY_USER_AGENT] = self.HTTP_USER_AGENT_TCP
        appmesh_request.uuid = str(uuid.uuid1())
        appmesh_request.http_method = method.value
        appmesh_request.request_uri = path
        appmesh_request.client_addr = socket.gethostname()

        if body:
            if isinstance(body, (dict, list)):
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
        self.tcp_transport.send_message(data)

        resp_data = self.tcp_transport.receive_message()
        if not resp_data:  # Covers None and empty bytes
            self.tcp_transport.close()
            raise Exception("socket connection broken")

        appmesh_resp = ResponseMessage().deserialize(resp_data)
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
    def download_file(self, remote_file: str, local_file: str, apply_file_attributes: bool = True) -> None:
        """Copy a remote file to local, preserving file attributes if requested.

        Args:
            remote_file (str): Remote file path.
            local_file (str): Local destination path.
            apply_file_attributes (bool): Apply remote file permissions/ownership locally.
        """
        header = {
            AppMeshClient.HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
            self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET: "true",
        }
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header=header)
        resp.raise_for_status()

        if self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET not in resp.headers:
            raise ValueError(f"Server did not respond with socket transfer option: {self.HTTP_HEADER_KEY_X_RECV_FILE_SOCKET}")

        with open(local_file, "wb") as fp:
            while True:
                chunk_data = self.tcp_transport.receive_message()
                if not chunk_data:
                    break
                fp.write(chunk_data)

        if apply_file_attributes:
            if "X-File-Mode" in resp.headers:
                os.chmod(path=local_file, mode=int(resp.headers["X-File-Mode"]))
            if "X-File-User" in resp.headers and "X-File-Group" in resp.headers:
                file_uid = int(resp.headers["X-File-User"])
                file_gid = int(resp.headers["X-File-Group"])
                try:
                    os.chown(path=local_file, uid=file_uid, gid=file_gid)
                except PermissionError:
                    print(f"Warning: Unable to change owner/group of {local_file}. Operation requires elevated privileges.")

    def upload_file(self, local_file: str, remote_file: str, apply_file_attributes: bool = True) -> None:
        """Upload a local file to remote server, preserving file attributes if requested.

        Args:
            local_file (str): Local file path.
            remote_file (str): Remote destination path.
            apply_file_attributes (bool): Upload file permissions/ownership metadata.
        """
        if not os.path.exists(local_file):
            raise FileNotFoundError(f"Local file not found: {local_file}")

        with open(file=local_file, mode="rb") as fp:
            header = {
                AppMeshClient.HTTP_HEADER_KEY_X_FILE_PATH: remote_file,
                "Content-Type": "text/plain",
                self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET: "true",
            }

            if apply_file_attributes:
                file_stat = os.stat(local_file)
                header["X-File-Mode"] = str(file_stat.st_mode & 0o777)  # Mask to keep only permission bits
                header["X-File-User"] = str(file_stat.st_uid)
                header["X-File-Group"] = str(file_stat.st_gid)

            resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/file/upload", header=header)
            resp.raise_for_status()

            if self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET not in resp.headers:
                raise ValueError(f"Server did not respond with socket transfer option: {self.HTTP_HEADER_KEY_X_SEND_FILE_SOCKET}")

            chunk_size = self.TCP_BLOCK_SIZE
            while True:
                chunk_data = fp.read(chunk_size)
                if not chunk_data:
                    self.tcp_transport.send_message([])  # EOF signal
                    break
                self.tcp_transport.send_message(chunk_data)
