# worker_tcp.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

# Standard library imports
import logging
from typing import Optional, Tuple, Union

# Local imports
from .client_tcp import AppMeshClientTCP
from .worker_http import AppMeshWorker

logger = logging.getLogger(__name__)


class AppMeshWorkerTCP(AppMeshWorker):
    """Worker SDK for interacting with the local App Mesh service over TCP (TLS).

    Example:
        >>> worker = AppMeshWorkerTCP(tcp_address=("127.0.0.1", 6059))
        >>> payload = worker.fetch_task()
    """

    def __init__(
        self,
        ssl_verify: Union[bool, str, None] = None,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        tcp_address: Tuple[str, int] = ("127.0.0.1", 6059),
        *,
        logger: Optional[logging.Logger] = None,  # pylint: disable=redefined-outer-name
    ):
        """Construct an App Mesh worker TCP object to communicate securely with an App Mesh server over TLS.

        Note:
            Positional order is ``(ssl_verify, ssl_client_cert, tcp_address)`` — differs from
            ``AppMeshClientTCP`` (address first); prefer keyword arguments.

        Args:
            ssl_verify: SSL server verification mode; same semantics as `AppMeshClientTCP`.
            ssl_client_cert: SSL client certificate file(s); same semantics as `AppMeshClientTCP`.
            tcp_address: Server address as (host, port) tuple, defaults to ("127.0.0.1", 6059).
            logger: Optional logger instance.
        """
        tcp_client = AppMeshClientTCP(ssl_verify=ssl_verify, ssl_client_cert=ssl_client_cert, tcp_address=tcp_address, auto_refresh_token=False)  # Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        super().__init__(client=tcp_client, logger=logger)
