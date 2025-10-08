# server_http.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

"""HTTP server SDK implementation for App Mesh."""

# Standard library imports
import abc
import logging
import os
import time
from http import HTTPStatus
from typing import Optional, Tuple, Union

# Local imports
from .client_http import AppMeshClient

logger = logging.getLogger(__name__)


class AppMeshServer(metaclass=abc.ABCMeta):
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
        rest_ssl_verify: Union[bool, str] = AppMeshClient._DEFAULT_SSL_CA_CERT_PATH,
        rest_ssl_client_cert: Optional[Union[str, Tuple[str, str]]] = None,
        rest_timeout: Tuple[float, float] = (60, 300),
        *,
        logger_: Optional[logging.Logger] = None,
    ):
        """Initialize an App Mesh HTTP client for interacting with the App Mesh server via secure HTTPS.

        Args:
            follows the same parameters as `AppMeshClient`.
        """
        self._client = AppMeshClient(rest_url, rest_ssl_verify, rest_ssl_client_cert, rest_timeout)
        self._logger = logger_ or logger

    @staticmethod
    def _get_runtime_env() -> Tuple[str, str]:
        """Read and validate required runtime environment variables."""
        process_key = os.getenv("APP_MESH_PROCESS_KEY")
        app_name = os.getenv("APP_MESH_APPLICATION_NAME")

        if not process_key:
            raise Exception("Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.")
        if not app_name:
            raise Exception("Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.")
        return process_key, app_name

    def task_fetch(self) -> Union[str, bytes]:
        """Fetch task data in the currently running App Mesh application process.

        Used by App Mesh application process to obtain the payload from App Mesh service
        that a client pushed to it.

        Returns:
            The payload provided by the client as returned by the service.
        """
        pkey, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"
        query_params = {"process_key": pkey}

        while True:
            resp = self._client._request_http(
                AppMeshClient._Method.GET,
                path=path,
                query=query_params,
            )

            if resp.status_code == HTTPStatus.OK:
                return resp.content

            self._logger.warning("task_fetch failed with status %d: %s, retrying...", resp.status_code, resp.text)
            time.sleep(self._RETRY_DELAY_SECONDS)

    def task_return(self, result: Union[str, bytes]) -> None:
        """Return the result of a server-side invocation back to the original client.

        Used by App Mesh application process to post the `result` to App Mesh service
        after processing payload data so the invoking client can retrieve it.

        Args:
            result: Result payload to be delivered back to the client.
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
            raise Exception(msg)
