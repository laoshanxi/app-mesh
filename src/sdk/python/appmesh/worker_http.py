# worker_http.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

"""HTTP worker SDK implementation for App Mesh (task fetch/return loop)."""

# Standard library imports
import logging
import os
import threading
import time
from http import HTTPStatus
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient
from .exceptions import AppMeshError, AppMeshProcessSupersededError

logger = logging.getLogger(__name__)


class AppMeshWorker:
    """Worker SDK for an App Mesh application interacting with the local App Mesh REST service over HTTPS.

    Despite running inside the managed application, this is a client-side task-loop helper:
    it polls the daemon for task payloads and returns results.

    Build-in runtime environment variables required:
      - APP_MESH_PROCESS_KEY
      - APP_MESH_APPLICATION_NAME

    Methods:
        - fetch_task(): fetch invocation payloads
        - send_task_result(): return results to the invoking client

    Example:
        context = appmesh.AppMeshWorker()
        payload = context.fetch_task()
        result = do_something_with(payload)
        context.send_task_result(result)
    """

    _RETRY_DELAY_SECONDS = 0.1

    def __init__(
        self,
        base_url: str = "https://127.0.0.1:6060",
        ssl_verify: Union[bool, str, None] = None,
        ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        request_timeout: Tuple[float, float] = (60, 300),
        *,
        client: Optional[AppMeshClient] = None,
        logger: Optional[logging.Logger] = None,  # pylint: disable=redefined-outer-name
    ):
        """Initialize a worker-side helper for task fetch/return.

        Args:
            base_url: The server's base URI. Defaults to "https://127.0.0.1:6060".
            ssl_verify: SSL server verification mode (None = auto: App Mesh CA bundle if installed, else system CAs).
            ssl_client_cert: SSL client certificate file(s).
            request_timeout: Timeouts `(connect_timeout, read_timeout)` in seconds.
            client: Pre-configured AppMeshClient instance (used by TCP/WSS subclasses so all
                transports share the same task API). Takes precedence: when provided, the
                connection parameters (`base_url`, `ssl_verify`, `ssl_client_cert`,
                `request_timeout`) are ignored.
            logger: Optional logger instance.
        """
        self._client = client or AppMeshClient(base_url, ssl_verify, ssl_client_cert, request_timeout, auto_refresh_token=False)  # Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        self._logger = logger or logging.getLogger(__name__)

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

    def fetch_task(self, *, stop_event: Optional[threading.Event] = None, max_retries: Optional[int] = None) -> Union[str, bytes]:
        """Fetch task data in the currently running App Mesh application process.

        Used by an App Mesh application process to obtain the payload from the App Mesh
        service that a client pushed to it. By default retries indefinitely until successful.
        If a request fails within 100ms, sleeps briefly before retrying; otherwise retries immediately.

        Args:
            stop_event: Optional cancellation event checked between attempts; when set,
                fetching stops and ``AppMeshError`` is raised.
            max_retries: Optional cap on retries after a failed attempt (``N`` allows up to
                ``N + 1`` attempts); when exhausted ``AppMeshError`` is raised.
                ``None`` (default) retries forever.

        Returns:
            The payload bytes provided by the invoking client.

        Raises:
            AppMeshProcessSupersededError: The daemon reported HTTP 412 — this process key was
                superseded by a newer process instance; the caller should stop serving.
            AppMeshError: Cancelled via ``stop_event`` or ``max_retries`` exhausted.
        """
        pkey, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"
        query_params = {"process_key": pkey}
        failed_attempts = 0

        while True:
            if stop_event is not None and stop_event.is_set():
                raise AppMeshError("fetch_task cancelled via stop_event")

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

                if resp.status_code == HTTPStatus.PRECONDITION_FAILED:
                    self._logger.error("Process key mismatch (412): this process has been superseded")
                    raise AppMeshProcessSupersededError("Process key mismatch (412): this process has been superseded by a newer instance")

                self._logger.warning("fetch_task failed with status %d: %s, retrying...", resp.status_code, resp.text)
            except AppMeshProcessSupersededError:
                raise
            except Exception as ex:
                self._logger.warning("fetch_task request failed: %s, retrying...", ex)

            failed_attempts += 1
            if max_retries is not None and failed_attempts > max_retries:
                raise AppMeshError(f"fetch_task failed after {failed_attempts} attempts (max_retries={max_retries})")

            remaining = self._RETRY_DELAY_SECONDS - (time.monotonic() - attempt_start)
            if remaining > 0:
                if stop_event is not None:
                    if stop_event.wait(remaining):
                        raise AppMeshError("fetch_task cancelled via stop_event")
                else:
                    time.sleep(remaining)

    def send_task_result(self, result: Union[str, bytes]) -> None:
        """Send the result of a server-side invocation back to the original client.

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
            msg = f"send_task_result failed with status {resp.status_code}: {resp.text}"
            self._logger.error(msg)
            raise AppMeshError(msg)
