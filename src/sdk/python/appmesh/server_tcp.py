# server_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import logging
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient
from .client_tcp import AppMeshClientTCP
from .server_http import AppMeshServer

logger = logging.getLogger(__name__)


class AppMeshServerTCP(AppMeshServer):
    """Server SDK for interacting with the local App Mesh service over TCP (TLS)."""

    def __init__(
        self,
        rest_ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        tcp_address: Tuple[str, int] = ("127.0.0.1", 6059),
        *,
        logger_: Optional[logging.Logger] = None,
    ):
        """Construct an App Mesh server TCP object to communicate securely with an App Mesh server over TLS.

        Args:
            follows the same parameters as `AppMeshClientTCP`.
        """
        # Deliberately avoid calling super().__init__ to inject a TCP client while keeping the same public API.
        object.__init__(self)
        self._client = AppMeshClientTCP(rest_ssl_verify=rest_ssl_verify, rest_ssl_client_cert=rest_ssl_client_cert, tcp_address=tcp_address)
        self._logger = logger_ or logger
