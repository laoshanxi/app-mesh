# server_http.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

"""HTTP server SDK implementation for App Mesh."""

# Standard library imports
import logging
import os
import time
from http import HTTPStatus
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient
from .exceptions import AppMeshError

logger = logging.getLogger(__name__)


class AppMeshServer:
    """Server SDK for App Mesh application interacting with the local App Mesh REST service over HTTPS.

    Build-in runtime environment variables required:
      - APP_MESH_PROCESS_KEY
      - APP_MESH_APPLICATION_NAME

    Methods:
        - task_fetch(): fetch invocation payloads
        - task_return(): return results to the invoking client

    Example:
        context = appmesh.AppMeshServer()
        payload = context.task_fetch()
        result = do_something_with(payload)
        context.task_return(result)
    """

    _RETRY_DELAY_SECONDS = 0.1

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        rest_timeout: Tuple[float, float] = (60, 300),
        *,
        client: Optional[AppMeshClient] = None,
        logger_: Optional[logging.Logger] = None,
    ):
        """Initialize a server-side helper for task fetch/return.

        Args:
            rest_url: The server's base URI. Defaults to "https://127.0.0.1:6060".
            ssl_verify: SSL server verification mode.
            ssl_client_cert: SSL client certificate file(s).
            rest_timeout: Timeouts `(connect_timeout, read_timeout)` in seconds.
            client: Pre-configured AppMeshClient instance (used by TCP/WSS subclasses so all
                transports share the same task API).
            logger_: Optional logger instance.
        """
        self._client = client or AppMeshClient(rest_url, ssl_verify, ssl_client_cert, rest_timeout)
        self._logger = logger_ or logger

    @staticmethod
    def _get_runtime_env() -> Tuple[str, str]:
        """Read and validate required runtime environment variables."""
        process_key = os.getenv("APP_MESH_PROCESS_KEY")
        app_name = os.getenv("APP_MESH_APPLICATION_NAME")

        if not process_key:
            raise AppMeshError("Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.")
        if not app_name:
            raise AppMeshError("Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.")
        return process_key, app_name

    def task_fetch(self, max_retries: int = 0, timeout: float = 0) -> Union[str, bytes]:
        """Fetch task data in the currently running App Mesh application process.

        Used by App Mesh application process to obtain the payload from App Mesh service
        that a client pushed to it.

        Args:
            max_retries: Maximum number of retry attempts. 0 means retry forever (default).
            timeout: Maximum total time in seconds to keep retrying. 0 means no timeout (default).

        Returns:
            The payload bytes provided by the invoking client.

        Raises:
            TimeoutError: If timeout is reached before a successful fetch.
            AppMeshError: If max_retries is exceeded without a successful fetch.
        """
        pkey, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"
        query_params = {"process_key": pkey}

        attempts = 0
        start_time = time.time()

        while True:
            attempt_start = time.monotonic()
            try:
                resp = self._client._request_http(
                    AppMeshClient._Method.GET,
                    path=path,
                    query=query_params,
                    raise_on_fail=False,
                )

                if resp.status_code == HTTPStatus.OK:
                    return resp.content

                self._logger.warning("task_fetch failed with status %d: %s, retrying...", resp.status_code, resp.text)
            except Exception as ex:
                self._logger.warning("task_fetch request failed: %s, retrying...", ex)

            attempts += 1
            if max_retries > 0 and attempts >= max_retries:
                raise AppMeshError(f"task_fetch failed after {attempts} attempts")
            if timeout > 0 and (time.time() - start_time) >= timeout:
                raise TimeoutError(f"task_fetch timed out after {timeout}s")

            remaining = self._RETRY_DELAY_SECONDS - (time.monotonic() - attempt_start)
            if remaining > 0:
                time.sleep(remaining)

    def task_return(self, result: Union[str, bytes]) -> None:
        """Return the result of a server-side invocation back to the original client.

        Used by App Mesh application process to post the `result` to App Mesh service
        after processing payload data so the invoking client can retrieve it.

        Args:
            result: Result payload to be delivered back to the client exactly as provided.
        """
        pkey, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"
        query_params = {"process_key": pkey}

        resp = self._client._request_http(
            AppMeshClient._Method.PUT,
            path=path,
            query=query_params,
            body=result,
        )

        if resp.status_code != HTTPStatus.OK:
            msg = f"task_return failed with status {resp.status_code}: {resp.text}"
            self._logger.error(msg)
            raise AppMeshError(msg)
