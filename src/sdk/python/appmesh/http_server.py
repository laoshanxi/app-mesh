# TCP-based App Mesh Server
# pylint: disable=line-too-long,broad-exception-raised,broad-exception-caught,import-outside-toplevel,protected-access

import abc
import os
import time
from http import HTTPStatus
from .http_client import AppMeshClient


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
        server = AppMeshServer()
        payload = server.task_fetch()
        server.task_return(result)
    """

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify=AppMeshClient.DEFAULT_SSL_CA_CERT_PATH if os.path.exists(AppMeshClient.DEFAULT_SSL_CA_CERT_PATH) else False,
        rest_ssl_client_cert=(AppMeshClient.DEFAULT_SSL_CLIENT_CERT_PATH, AppMeshClient.DEFAULT_SSL_CLIENT_KEY_PATH) if os.path.exists(AppMeshClient.DEFAULT_SSL_CLIENT_CERT_PATH) else None,
        rest_timeout=(60, 300),
    ):
        """Initialize an App Mesh HTTP client for interacting with the App Mesh server via secure HTTPS.

        Args:
            follows the same parameters as `AppMeshClient`.
        """
        self._client = AppMeshClient(rest_url, rest_ssl_verify, rest_ssl_client_cert, rest_timeout)

    def task_fetch(self) -> str:
        """Fetch invocation data in the currently running App Mesh application process.

        This helper is intended to be called by an application process running from App Mesh
        to obtain the payload that a client pushed to it. It reads two required
        environment variables set by the runtime:

        - APP_MESH_PROCESS_ID: the process UUID for this invocation
        - APP_MESH_APPLICATION_NAME: the application name

        Returns:
            str: The payload provided by the client as returned by the service.
        """
        process_uuid = os.environ["APP_MESH_PROCESS_ID"]
        app_name = os.environ["APP_MESH_APPLICATION_NAME"]
        while True:
            resp = self._client._request_http(
                AppMeshClient.Method.GET,
                path=f"/appmesh/app/{app_name}/task",
                query={"process_uuid": process_uuid},
            )
            if resp.status_code != HTTPStatus.OK:
                time.sleep(0.1)
                continue

            return resp.text

    def task_return(self, result: str) -> None:
        """Return the result of a server-side invocation back to the original client.

        The method posts the `result` associated with the current process UUID so
        the invoking client can retrieve it. The same environment variables used by
        `task_fetch` are required to identify the target process.

        Args:
            result (str): Result payload to be delivered back to the client.
        """
        process_uuid = os.environ["APP_MESH_PROCESS_ID"]
        app_name = os.environ["APP_MESH_APPLICATION_NAME"]
        resp = self._client._request_http(
            AppMeshClient.Method.PUT,
            path=f"/appmesh/app/{app_name}/task",
            query={"process_uuid": process_uuid},
            body=result,
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
