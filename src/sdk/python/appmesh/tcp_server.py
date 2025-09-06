# TCP-based App Mesh Server
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

import os
from .http_client import AppMeshClient
from .tcp_client import AppMeshClientTCP
from .http_server import AppMeshServer


class AppMeshServerTCP(AppMeshServer):
    """
    Server SDK for interacting with the local App Mesh service over TCP.

    Attributes:
        - Inherits all attributes from `AppMeshServer`.

    Methods:
        - Inherits all methods from `AppMeshServer`.
    """

    def __init__(
        self,
        rest_ssl_verify=AppMeshClient.DEFAULT_SSL_CA_CERT_PATH if os.path.exists(AppMeshClient.DEFAULT_SSL_CA_CERT_PATH) else False,
        rest_ssl_client_cert=None,
        tcp_address=("localhost", 6059),
    ):
        """Construct an App Mesh server TCP object to communicate securely with an App Mesh server over TLS.

        Args:
            follows the same parameters as `AppMeshClientTCP`.
        """
        object.__init__(self)
        self._client = AppMeshClientTCP(rest_ssl_verify=rest_ssl_verify, rest_ssl_client_cert=rest_ssl_client_cert, tcp_address=tcp_address)
