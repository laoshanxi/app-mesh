# server_wss.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import logging
from typing import Optional, Tuple, Union

# Local imports
from .client_wss import AppMeshClientWSS
from .server_http import AppMeshWorker

logger = logging.getLogger(__name__)


class AppMeshWorkerWSS(AppMeshWorker):
    """Worker SDK for interacting with the local App Mesh service over WebSockets (WSS).

    Example:
        >>> worker = AppMeshWorkerWSS(wss_address=("127.0.0.1", 6058))
        >>> payload = worker.fetch_task()
    """

    def __init__(
        self,
        wss_address: Tuple[str, int] = ("127.0.0.1", 6058),
        ssl_verify: Union[bool, str, None] = None,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        *,
        logger: Optional[logging.Logger] = None,  # pylint: disable=redefined-outer-name
    ):
        """Construct an App Mesh worker WSS object to communicate securely with an App Mesh server over TLS.

        Note:
            Positional order is ``(wss_address, ssl_verify, ssl_client_cert)`` — differs from
            ``AppMeshWorkerTCP`` (``ssl_verify`` first); prefer keyword arguments.

        Args:
            wss_address: Server address as (host, port) tuple, defaults to ("127.0.0.1", 6058).
            ssl_verify: SSL server verification mode; same semantics as `AppMeshClientWSS`.
            ssl_client_cert: SSL client certificate file(s); same semantics as `AppMeshClientWSS`.
            logger: Optional logger instance.
        """
        wss_client = AppMeshClientWSS(ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert, wss_address=wss_address, auto_refresh_token=False)  # Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        super().__init__(client=wss_client, logger=logger)
