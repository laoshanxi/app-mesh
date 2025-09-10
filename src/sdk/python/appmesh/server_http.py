# server_http.py
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

import abc
import logging
import os
import time
from typing import Optional, Tuple
from http import HTTPStatus
from .client_http import AppMeshClient

logger = logging.getLogger(__name__)


class AppMeshServer(metaclass=abc.ABCMeta):
    """
    Server SDK for App Mesh application interacting with the local App Mesh REST service over HTTPS.

    Build-in runtime environment variables required:
      - APP_MESH_PROCESS_ID
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

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify=AppMeshClient.DEFAULT_SSL_CA_CERT_PATH if os.path.exists(AppMeshClient.DEFAULT_SSL_CA_CERT_PATH) else False,
        rest_ssl_client_cert=(
            (
                AppMeshClient.DEFAULT_SSL_CLIENT_CERT_PATH,
                AppMeshClient.DEFAULT_SSL_CLIENT_KEY_PATH,
            )
            if os.path.exists(AppMeshClient.DEFAULT_SSL_CLIENT_CERT_PATH)
            else None
        ),
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
        process_id = os.getenv("APP_MESH_PROCESS_ID")
        app_name = os.getenv("APP_MESH_APPLICATION_NAME")
        if not process_id:
            raise Exception("Missing environment variable: APP_MESH_PROCESS_ID. This must be set by App Mesh service.")
        if not app_name:
            raise Exception("Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.")
        return process_id, app_name

    def task_fetch(self) -> str:
        """Fetch task data in the currently running App Mesh application process.

        Used by App Mesh application process to obtain the payload from App Mesh service
        that a client pushed to it.


        Returns:
            str: The payload provided by the client as returned by the service.
        """
        process_id, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"

        while True:
            resp = self._client._request_http(
                AppMeshClient.Method.GET,
                path=path,
                query={"process_uuid": process_id},
            )

            if resp.status_code != HTTPStatus.OK:
                self._logger.warning(f"task_fetch failed with status {resp.status_code}: {resp.text}, retrying...")
                time.sleep(0.1)
                continue

            return resp.text

    def task_return(self, result: str) -> None:
        """Return the result of a server-side invocation back to the original client.

        Used by App Mesh application process to posts the `result` to App Mesh service
        after processed payload data so the invoking client can retrieve it.

        Args:
            result (str): Result payload to be delivered back to the client.
        """
        process_id, app_name = self._get_runtime_env()
        path = f"/appmesh/app/{app_name}/task"

        resp = self._client._request_http(
            AppMeshClient.Method.PUT,
            path=path,
            query={"process_uuid": process_id},
            body=result,
        )

        if resp.status_code != HTTPStatus.OK:
            msg = f"task_return failed with status {resp.status_code}: {resp.text}"
            self._logger.error(msg)
            raise Exception(msg)
