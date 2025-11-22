# server_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import logging
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient
from .client_wss import AppMeshClientWSS
from .server_http import AppMeshServer

logger = logging.getLogger(__name__)


class AppMeshServerWSS(AppMeshServer):
    """Server SDK for interacting with the local App Mesh service over WebSockets (WSS)."""

    def __init__(
        self,
        wss_address: Tuple[str, int] = ("127.0.0.1", 6058),
        ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        *,
        logger_: Optional[logging.Logger] = None,
    ):
        """Construct an App Mesh server WSS object to communicate securely with an App Mesh server over TLS.

        Args:
            follows the same parameters as `AppMeshClientWSS`.
        """
        # Deliberately avoid calling super().__init__ to inject a WSS client while keeping the same public API.
        object.__init__(self)
        self._client = AppMeshClientWSS(ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert, wss_address=wss_address)
        self._logger = logger_ or logger
