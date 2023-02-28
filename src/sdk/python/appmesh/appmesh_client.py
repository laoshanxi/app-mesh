#!/usr/bin/python3
"""App Mesh Python SDK"""
import abc
import aniso8601
import base64
import json
import os
import socket
import ssl
import uuid

from enum import Enum
from http import HTTPStatus
from urllib import parse
from datetime import datetime
import requests


DEFAULT_TOKEN_EXPIRE_SECONDS = "P1W"          # 7 days
DEFAULT_RUN_APP_TIMEOUT_SECONDS = "PT1H"      # 1 hour
DEFAULT_RUN_APP_LIFECYCLE_SECONDS = "PT10H"   # 10 hours
REST_TEXT_MESSAGE_JSON_KEY = "message"
MESSAGE_ENCODING_UTF8 = "utf-8"
TCP_MESSAGE_HEADER_LENGTH = 4
_SSL_CA_PEM_FILE = "/opt/appmesh/ssl/ca.pem"



class AppMeshClient(metaclass=abc.ABCMeta):
    """
    Client object used to access App Mesh REST Service

    - install pip package: python3 -m pip install --upgrade appmesh
    - import module: from appmesh import appmesh_client
    """

    class Method(Enum):
        """REST methods"""
        GET = "GET"
        PUT = "PUT"
        POST = "POST"
        DELETE = "DELETE"
        POST_STREAM = "POST_STREAM"


    def __init__(
        self,
        auth_enable: bool = True,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify=_SSL_CA_PEM_FILE,
        rest_timeout=(60, 300),
    ):
        """Construct an App Mesh client object

        Args:
            auth_enable (bool, optional): server enabled JWT authentication or not.
            rest_url (str, optional): server URI string.
            rest_ssl_verify (str, optional): SSL CA certification file path or False to disable SSL verification.
            rest_timeout (tuple, optional): HTTP timeout, Defaults to 60 seconds for connect timeout and 300 seconds for read timeout
        """
        self.server_url = rest_url
        self.jwt_auth_enable = auth_enable
        self.__jwt_token = None
        self.ssl_verify = rest_ssl_verify
        self.rest_timeout = rest_timeout

    @property
    def jwt_token(self) -> str:
        """property for jwt_token

        Returns:
            str: _description_
        """
        return self.__jwt_token

    @jwt_token.setter
    def jwt_token(self, token: str) -> None:
        """setter for jwt_token

        Args:
            token (str): _description_
        """
        self.__jwt_token = token

    ########################################
    # Security
    ########################################
    def login(self, user_name: str, user_pwd: str, timeout_seconds = DEFAULT_TOKEN_EXPIRE_SECONDS) -> str:
        """Login with user name and password

        Args:
            user_name (str): the name of the user.
            user_pwd (str): the password of the user.
            timeout_seconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').

        Returns:
            str: JWT token if verify success, otherwise return None.
        """
        self.jwt_token = None
        if self.jwt_auth_enable:
            resp = self._request_http(
                AppMeshClient.Method.POST,
                path="/appmesh/login",
                header={
                    "Username": base64.b64encode(user_name.encode()),
                    "Password": base64.b64encode(user_pwd.encode()),
                    "Expire-Seconds": self._parse_duration(timeout_seconds),
                },
            )
            if resp.status_code == HTTPStatus.OK:
                if "Access-Token" in resp.json():
                    self.jwt_token = resp.json()["Access-Token"]
            else:
                print(resp.text)
                # resp.raise_for_status()
        return self.jwt_token

    def authentication(self, token: str, permission=None) -> bool:
        """Login with token and verify permission when specified

        Args:
            token (str): JWT token returned from login().
            permission (str, optional): the permission ID used to verify the token user
                permission ID can be:
                - pre-defined by App Mesh from security.json (e.g 'app-view', 'app-delete')
                - defined by input from role_update() or security.json

        Returns:
            bool: authentication success or failure.
        """
        if self.jwt_auth_enable:
            self.jwt_token = token
            headers = {}
            if permission is not None:
                headers["Auth-Permission"] = permission
            resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/auth", header=headers)
            if resp.status_code == HTTPStatus.OK:
                return True
            else:
                # resp.raise_for_status()
                print(resp.text)
                return False
        return True

    ########################################
    # Application view
    ########################################
    def app_view(self, app_name: str):
        """Get application information in JSON format

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
            dict: the application JSON both contain static configuration and runtime information.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/app/{app_name}")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def app_view_all(self):
        """Get all applications in JSON format

        Returns:
            bool: success or failure.
            dict: the application JSON both contain static configuration and runtime information, only return applications that the user has permissions.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/applications")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def app_output(self, app_name: str, stdout_position: int = 0, stdout_index: int = 0, stdout_maxsize: int = 10240, process_uuid: str = "", timeout: int = 0):
        """Get application stdout/stderr

        Args:
            app_name (str): the application name
            stdout_position (int, optional): start read position, 0 means start from beginning.
            stdout_index (int, optional): index of history process stdout, 0 means get from current running process,
                the stdout number depends on 'stdout_cache_size' of the application.
            stdout_maxsize (int, optional): max buffer size to read.
            process_uuid (str, optional): used to get the specified process.
            timeout (int, optional): wait for the running process for some time(seconds) to get the output.

        Returns:
            bool: success or failure.
            str: output string.
            int or None: current read position.
            int or None: process exit code.
        """
        resp = self._request_http(
            AppMeshClient.Method.GET,
            path=f"/appmesh/app/{app_name}/output",
            query={
                "stdout_position": str(stdout_position),
                "stdout_index": str(stdout_index),
                "stdout_maxsize": str(stdout_maxsize),
                "process_uuid": process_uuid,
                "timeout": str(timeout),
            },
        )
        out_position = None if not resp.headers.__contains__("Output-Position") else int(resp.headers["Output-Position"])
        exit_code = None if not resp.headers.__contains__("Exit-Code") else int(resp.headers["Exit-Code"])
        return (resp.status_code == HTTPStatus.OK), resp.text, out_position, exit_code

    def app_health(self, app_name: str):
        """Get application health status, 0 is health.

        Args:
            app_name (str): the application name.

        Returns:
            str: '0' is heathy, '1' is unhealthy.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/app/{app_name}/health")
        return (resp.status_code == HTTPStatus.OK), resp.text

    ########################################
    # Application manage
    ########################################
    def app_add(self, app_json: dict):
        """Register an application

        Args:
            app_json (dict): the application definition.

        Returns:
            bool: success or failure.
            dict: resigtered application in JSON format.
        """
        resp = self._request_http(AppMeshClient.Method.PUT, path="/appmesh/app/{0}".format(app_json["name"]), body=app_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def app_delete(self, app_name: str):
        """Remove an application.

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
            str: text message.
        """
        resp = self._request_http(AppMeshClient.Method.DELETE, path=f"/appmesh/app/{app_name}")
        return (resp.status_code == HTTPStatus.OK), resp.json()[REST_TEXT_MESSAGE_JSON_KEY]

    def app_enable(self, app_name: str):
        """Enable an application

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
            str: text message.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path=f"/appmesh/app/{app_name}/enable")
        return (resp.status_code == HTTPStatus.OK), resp.json()[REST_TEXT_MESSAGE_JSON_KEY]

    def app_disable(self, app_name: str):
        """Stop and disable an application

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
            str: text message.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path=f"/appmesh/app/{app_name}/disable")
        return (resp.status_code == HTTPStatus.OK), resp.json()[REST_TEXT_MESSAGE_JSON_KEY]

    ########################################
    # Cloud management
    ########################################
    def cloud_app_view_all(self):
        """Get all cloud applications

        Returns:
            bool: success or failure.
            dict: cloud applications in JSON format.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/cloud/applications")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def cloud_app(self, app_name: str):
        """Get an cloud application

        Args:
            app_name (str): the application name.

        Returns:
            bool: success or failure.
            dict: application in JSON format.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/cloud/app/{app_name}")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def cloud_app_output(self, app_name: str, host_name: str, stdout_position: int = 0, stdout_index: int = 0, stdout_maxsize: int = 10240, process_uuid: str = ""):
        """Get cloud application stdout/stderr from master agent

        Args:
            app_name (str): the application name
            host_name (str): the target host name where the application is running
            stdout_position (int, optional): start read position, 0 means start from beginning.
            stdout_index (int, optional): index of history process stdout, 0 means get from current running process,
                the stdout number depends on 'stdout_cache_size' of the application.
            stdout_maxsize (int, optional): max buffer size to read.
            process_uuid (str, optional): used to get the specified process.

        Returns:
            bool: success or failure.
            str: output string.
            int or None: current read position.
            int or None: process exit code.
        """
        resp = self._request_http(
            AppMeshClient.Method.GET,
            path=f"/appmesh/cloud/app/{app_name}/output/{host_name}",
            query={
                "stdout_position": str(stdout_position),
                "stdout_index": str(stdout_index),
                "stdout_maxsize": str(stdout_maxsize),
                "process_uuid": process_uuid,
            },
        )
        out_position = None if not resp.headers.__contains__("Output-Position") else int(resp.headers["Output-Position"])
        exit_code = None if not resp.headers.__contains__("Exit-Code") else int(resp.headers["Exit-Code"])
        return (resp.status_code == HTTPStatus.OK), resp.text, out_position, exit_code

    def cloud_app_delete(self, app_name: str) -> bool:
        """Delete a cloud application

        Args:
            app_name (str): The application name for cloud

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.DELETE, path=f"/appmesh/cloud/app/{app_name}")
        return resp.status_code == HTTPStatus.OK

    def cloud_app_add(self, app_json: dict):
        """Add a cloud application

        Args:
            app_json (dict): the cloud application definition with replication, condition and resource requirement

         Returns:
            bool: success or failure.
            dict: cluster application json.
        """
        resp = self._request_http(AppMeshClient.Method.PUT, path="/appmesh/cloud/app/{0}".format(app_json["content"]["name"]), body=app_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def cloud_nodes(self):
        """Get cluster node list

        Returns:
            bool: success or failure.
            dict: cluster node list json.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/cloud/nodes")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Configuration
    ########################################
    def host_resource(self):
        """Get App Mesh host resource report include CPU, memory and disk

        Returns:
            bool: success or failure.
            dict: the host resource json.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/resources")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def config_view(self):
        """Get App Mesh configuration JSON

        Returns:
            bool: success or failure.
            dict: the configuration json.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/config")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def config_set(self, cfg_json):
        """Update configuration, the format follow 'config.json', support partial update

        Args:
            cfg_json (dict): the new configuration json.

        Returns:
            bool: success or failure.
            dict: the updated configuration json.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/config", body=cfg_json)
        result = resp.json()
        if "Applications" in result:
            result.pop("Applications")
        return (resp.status_code == HTTPStatus.OK), result

    def log_level_set(self, level: str = "DEBUG"):
        """Update App Mesh log level(DEBUG/INFO/NOTICE/WARN/ERROR), a wrapper of config_set()

        Args:
            level (str, optional): log level.

        Returns:
            bool: success or failure.
            dict: the updated configuration json.
        """
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/config", body={"LogLevel": level})
        if resp.status_code == HTTPStatus.OK:
            return True,resp.json()["LogLevel"]
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # User Management
    ########################################
    def user_passwd_update(self, new_password: str, user_name: str = "self"):
        """Change user password

        Args:
            user_name (str): the user name.
            new_password (str):the new password string

        Returns:
            bool: success or failure.
            str: result message.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/passwd",
            header={"New-Password": base64.b64encode(new_password.encode())},
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()[REST_TEXT_MESSAGE_JSON_KEY]

    def user_add(self, user_name: str, user_json: dict) -> bool:
        """Add a new user, not available for LDAP user

        Args:
            user_name (str): the user name.
            user_json (dict): user definition, follow same user format from security.json.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.PUT,
            path=f"/appmesh/user/{user_name}",
            body=user_json,
        )
        return resp.status_code == HTTPStatus.OK

    def user_delete(self, user_name: str) -> bool:
        """Delete a user

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.DELETE,
            path=f"/appmesh/user/{user_name}",
        )
        return resp.status_code == HTTPStatus.OK

    def user_lock(self, user_name: str) -> bool:
        """Lock a user

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/lock",
        )
        return resp.status_code == HTTPStatus.OK

    def user_unlock(self, user_name: str) -> bool:
        """Unlock a user

        Args:
            user_name (str): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path=f"/appmesh/user/{user_name}/unlock",
        )
        return resp.status_code == HTTPStatus.OK

    def user_2fa_active(self) -> bool:
        """Active 2FA for current login user and return MFA URI with JSON body

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.POST,
            path="/appmesh/user/self/mfa",
        )
        return resp.status_code == HTTPStatus.OK

    def user_2fa_deactive(self, user_name: str = "self") -> bool:
        """DeActive 2FA for a user

        Args:
            user_name (str, optional): the user name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.DELETE,
            path=f"/appmesh/user/{user_name}/mfa",
        )
        return resp.status_code == HTTPStatus.OK

    def users_view(self):
        """Get all users

        Returns:
            bool: success or failure.
            dict: all user definition.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/users")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def user_self(self):
        """Get current user infomation

        Returns:
            bool: success or failure.
            dict: user definition.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/self")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def groups_view(self):
        """Get all user groups

        Returns:
            bool: success or failure.
            dict: user group array.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/groups")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def permissions_view(self):
        """Get all available permissions

        Returns:
            bool: success or failure.
            dict: permission array.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/permissions")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def permissions_for_user(self):
        """Get current user permissions

        Returns:
            bool: success or failure.
            dict: user permission array.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/permissions")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def roles_view(self):
        """Get all roles with permission definition

        Returns:
            bool: success or failure.
            dict: all role definition.
        """
        resp = self._request_http(method=AppMeshClient.Method.GET, path="/appmesh/roles")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def role_update(self, role_name: str, role_permission_json: dict) -> bool:
        """Update (or add) a role with defined permissions, the permission ID can be App Mesh pre-defined or other permission ID.

        Args:
            role_name (str): the role name.
            role_permission_json (dict): role permission definition array, e.g
                    [
                        "app-control",
                        "app-delete",
                        "cloud-app-reg",
                        "cloud-app-delete",
                        "app-reg",
                        "config-set",
                        "file-download",
                        "file-upload",
                        "label-delete",
                        "label-set"
                    ]

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(method=AppMeshClient.Method.POST, path=f"/appmesh/role/{role_name}", body=role_permission_json)
        return resp.status_code == HTTPStatus.OK

    def role_delete(self, role_name: str) -> bool:
        """Delete a user role

        Args:
            role_name (str): the role name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            method=AppMeshClient.Method.DELETE,
            path=f"/appmesh/role/{role_name}",
        )
        return resp.status_code == HTTPStatus.OK

    ########################################
    # Tag management
    ########################################
    def tag_add(self, tag_name: str, tag_value: str) -> bool:
        """Add a new label

        Args:
            tag_name (str): the label name.
            tag_value (str): the label value.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            AppMeshClient.Method.PUT,
            query={"value": tag_value},
            path=f"/appmesh/label/{tag_name}",
        )
        return resp.status_code == HTTPStatus.OK

    def tag_delete(self, tag_name: str) -> bool:
        """Delete a label

        Args:
            tag_name (str): the label name.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.DELETE, path=f"/appmesh/label/{tag_name}")
        return resp.status_code == HTTPStatus.OK

    def tag_view(self):
        """Get the server labels

        Returns:
            bool: success or failure.
            dict: label data.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/labels")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Promethus metrics
    ########################################
    def metrics(self):
        """Prometheus metrics (this does not call Prometheus API /metrics, just copy the same metrics data)

        Returns:
            bool: success or failure.
            str: prometheus metrics texts
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/metrics")
        return resp.status_code == HTTPStatus.OK, resp.text

    ########################################
    # File management
    ########################################
    def file_download(self, file_path: str, local_file: str) -> bool:
        """Copy a remote file to local, the local file will have the same permission as the remote file

        Args:
            file_path (str): the remote file path.
            local_file (str): the local file path to be downloaded.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header={"File-Path": file_path})
        if resp.status_code == HTTPStatus.OK:
            with open(local_file, "wb") as fp:
                for chunk in resp.iter_content(chunk_size=512):
                    if chunk:
                        fp.write(chunk)
            if resp.headers.__contains__("File-Mode"):
                os.chmod(path=local_file, mode=int(resp.headers["File-Mode"]))
            if resp.headers.__contains__("File-User") and resp.headers.__contains__("File-Group"):
                file_uid = int(resp.headers["File-User"])
                file_gid = int(resp.headers["File-Group"])
                try:
                    os.chown(path=local_file, uid=file_uid, gid=file_gid)
                except Exception as ex:
                    print(ex)
            return True
        return False

    def file_upload(self, local_file: str, file_path: str):
        """Upload a local file to the remote server, the remote file will have the same permission as the local file

        Dependency:
            sudo apt install python3-pip
            pip3 install requests_toolbelt

        Args:
            local_file (str): the local file path.
            file_path (str): the target remote file to be uploaded.

        Returns:
            bool: success or failure.
            str: text message.
        """
        from requests_toolbelt import MultipartEncoder

        with open(file=local_file, mode="rb") as fp:
            encoder = MultipartEncoder(fields={"filename": os.path.basename(file_path), "file": ("filename", fp, "application/octet-stream")})
            file_stat = os.stat(local_file)
            header = {}
            header["File-Path"] = file_path
            header["File-Mode"] = str(file_stat.st_mode)
            header["File-User"] = str(file_stat.st_uid)
            header["File-Group"] = str(file_stat.st_gid)
            header["Content-Type"] = encoder.content_type
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self._request_http(
                AppMeshClient.Method.POST_STREAM,
                path="/appmesh/file/upload",
                header=header,
                body=encoder,
            )
            if resp.status_code == HTTPStatus.OK:
                return True, ""
            return False, resp.json()[REST_TEXT_MESSAGE_JSON_KEY]

    ########################################
    # Application run
    ########################################
    def _parse_duration(self, timeout) -> str:
        if isinstance(timeout, int):
            return str(timeout)
        elif isinstance(timeout, str):
            return str(int(aniso8601.parse_duration(timeout).total_seconds()))
        else:
            raise TypeError("Invalid timeout type: %s" % str(timeout))

    def run_async(
        self,
        app_json: dict,
        max_time_seconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        life_cycle_seconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS,
    ):
        """Asyncrized run a command remotely, 'name' attribute in app_json dict used to run an existing application
        Asyncrized run will not block process

        Args:
            app_json (dict): application JSON dict.
            max_time_seconds (int | str, optional): max run time for the remote process, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
            life_cycle_seconds (int | str, optional): max lifecycle time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').

        Returns:
            str: app_name, new application name for this run
            str: process_uuid, process UUID for this run
        """
        path = "/appmesh/app/run"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app_json,
            path=path,
            query={"timeout": self._parse_duration(max_time_seconds), "lifecycle": self._parse_duration(life_cycle_seconds)},
        )
        if resp.status_code == HTTPStatus.OK:
            app_name = resp.json()["name"]
            process_uuid = resp.json()["process_uuid"]
            return (app_name, process_uuid)
        else:
            print(resp.text)
        return None

    def run_async_wait(self, async_tuple: tuple, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for an async run to be finished

        Args:
            async_tuple (tuple): asyncrized run result from run_async().
                async_tuple[0] app_name: application name from run_async
                async_tuple[1] process_uuid: process uuid
            stdout_print (bool, optional): print remote stdout to local or not.
            timeout (int, optional): wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            int: return exit code if process finished, return None for timeout or exception.
        """
        exit_code = None
        if async_tuple is not None:
            app_name = async_tuple[0]
            process_uuid = async_tuple[1]
            output_position = 0
            start = datetime.now()
            interval = 1 if self.__class__.__name__ == "AppMeshClient" else 1000
            while len(process_uuid) > 0:
                success, output, position, exit_code = self.app_output(
                    app_name=app_name, stdout_position=output_position, stdout_index=0, process_uuid=process_uuid, timeout=interval
                )
                if output is not None and stdout_print:
                    print(output, end="")
                if position is not None:
                    output_position = position
                if exit_code is not None:
                    # success
                    self.app_delete(app_name)
                    break
                if not success:
                    # failed
                    break
                if timeout > 0 and (datetime.now() - start).seconds > timeout:
                    # timeout
                    break
        return exit_code

    def run_sync(
        self,
        app_json: dict,
        stdout_print: bool = True,
        max_time_seconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        life_cycle_seconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS,
    ) -> int:
        """Block run a command remotely, 'name' attribute in app_json dict used to run an existing application
        The synchronized run will block the process until the remote run is finished then return the result from HTTP response

        Args:
            app_json (dict): application JSON dict.
            stdout_print (bool, optional): whether print remote stdout to local or not. Defaults to True.
            max_time_seconds (int | str, optional): max run time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
            life_cycle_seconds (int | str, optional): max lifecycle time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').

        Returns:
            int: process exit code, return None if no exit code.
        """
        path = "/appmesh/app/syncrun"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app_json,
            path=path,
            query={"timeout": self._parse_duration(max_time_seconds), "lifecycle": self._parse_duration(life_cycle_seconds)},
        )
        exit_code = None
        if resp.status_code == HTTPStatus.OK:
            if stdout_print:
                print(resp.text, end="")
            if resp.headers.__contains__("Exit-Code"):
                exit_code = int(resp.headers.get("Exit-Code"))
        elif stdout_print:
            print(resp.text)
        return exit_code

    def _request_http(self, method: Method, path: str, query: dict = {}, header: dict = {}, body=None) -> requests.Response:
        """REST API

        Args:
            method (Method): AppMeshClient.Method.
            path (str): URI patch str.
            query (dict, optional): HTTP query parameters.
            header (dict, optional): HTTP headers.
            body (_type_, optional): object to send in the body of the :class:`Request`.

        Returns:
            requests.Response: HTTP response
        """
        rest_url = parse.urljoin(self.server_url, path)
        if self.jwt_token is not None:
            header["Authorization"] = "Bearer " + self.jwt_token

        if method is AppMeshClient.Method.GET:
            return requests.get(url=rest_url, params=query, headers=header, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.POST:
            return requests.post(url=rest_url, params=query, headers=header, json=body, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.POST_STREAM:
            return requests.post(
                url=rest_url,
                params=query,
                headers=header,
                data=body,
                verify=False,
                stream=True,
            )
        elif method is AppMeshClient.Method.DELETE:
            return requests.delete(url=rest_url, headers=header, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.PUT:
            return requests.put(url=rest_url, params=query, headers=header, json=body, verify=self.ssl_verify, timeout=self.rest_timeout)
        else:
            raise Exception("Invalid http method", method)


class AppMeshClientTCP(AppMeshClient):
    """Client object used to access App Mesh REST Service over TCP (better performance than AppMeshClient)

    Dependency:
        pip3 install msgpack
    """

    def __init__(
        self,
        tcp_address=("localhost", 6059),
        auth_enable: bool = True,
    ):
        """Construct an App Mesh client TCP object

        Args:
            tcp_address (tuple, optional): TCP connect address.
            auth_enable (bool, optional): server enabled JWT authentication or not.
        """
        super().__init__(auth_enable=auth_enable)
        self.tcp_address = tcp_address
        self.jwt_auth_enable = auth_enable
        self.__socket_client = None

    def __del__(self) -> None:
        """De-construction"""
        self.__close_socket()

    def __connect_socket(self) -> None:
        """Establish tcp connection"""
        sock = socket.create_connection(self.tcp_address)
        sock.setblocking(True)

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.load_verify_locations(_SSL_CA_PEM_FILE)
        self.__socket_client = context.wrap_socket(sock, server_hostname=self.tcp_address[0])

    def __close_socket(self) -> None:
        """Close socket connection"""
        if self.__socket_client:
            try:
                self.__socket_client.close()
                self.__socket_client = None
            except Exception as ex:
                print(ex)

    def __recvall(self, length: int) -> bytes:
        """socket recv data with fixed length
           https://stackoverflow.com/questions/64466530/using-a-custom-socket-recvall-function-works-only-if-thread-is-put-to-sleep
        Args:
            length (bytes): data length to be recieved

        Raises:
            EOFError: _description_

        Returns:
            bytes: socket data
        """
        fragments = []
        while length:
            chunk = self.__socket_client.recv(length)
            if not chunk:
                raise EOFError('socket closed')
            length -= len(chunk)
            fragments.append(chunk)
        return b''.join(fragments)

    def _request_http(self, method: AppMeshClient.Method, path: str, query: dict = {}, header: dict = {}, body=None) -> requests.Response:
        """TCP API

        Args:
            method (Method): AppMeshClient.Method.
            path (str): URI patch str.
            query (dict, optional): HTTP query parameters.
            header (dict, optional): HTTP headers.
            body (_type_, optional): object to send in the body of the :class:`Request`.

        Returns:
            requests.Response: HTTP response
        """
        import msgpack
        class RequestMsg:
            uuid: str = ""
            request_uri: str = ""
            http_method: str = ""
            client_addr: str = ""
            body: bytes = b''
            headers: dict = {}
            querys: dict = {}

            def serialize(self) -> bytes:
                # http://www.cnitblog.com/luckydmz/archive/2019/11/20/91959.html
                self_dict = vars(self)
                self_dict["headers"] = self.headers
                self_dict["querys"] = self.querys
                return msgpack.dumps(self_dict)

        class ResponseMsg:
            uuid: str = ""
            request_uri: str = ""
            http_status: int = 0
            body_msg_type: str = ""
            body: bytes = b''
            headers: dict = {}

            def desirialize(self, buf: bytes):
                dic = msgpack.unpackb(buf)
                for k,v in dic.items():
                    setattr(self, k, v)
                return self


        if super().jwt_token is not None:
            header["Authorization"] = "Bearer " + super().jwt_token
        if self.__socket_client is None:
            self.__connect_socket()
        req_id = str(uuid.uuid1())
        appmesh_requst = RequestMsg()
        appmesh_requst.uuid = req_id
        appmesh_requst.http_method = method.name
        appmesh_requst.request_uri = path
        appmesh_requst.client_addr = socket.gethostname()
        if body:
            if isinstance(body, dict) or isinstance(body, list):
                appmesh_requst.body = bytes(json.dumps(body, indent=2), MESSAGE_ENCODING_UTF8)
            elif isinstance(body, str):
                appmesh_requst.body = bytes(body, MESSAGE_ENCODING_UTF8)
            elif isinstance(body, bytes):
                appmesh_requst.body = body
            else:
                raise Exception("UnSupported body type: %s" % type(body))
        if header:
            for k, v in header.items():
                appmesh_requst.headers[k] = v
        if query:
            for k, v in query.items():
                appmesh_requst.querys[k] = v
        data = appmesh_requst.serialize()
        self.__socket_client.sendall(len(data).to_bytes(TCP_MESSAGE_HEADER_LENGTH, "big", signed=False))
        self.__socket_client.sendall(data)

        # https://developers.google.com/protocol-buffers/docs/pythontutorial
        # https://stackoverflow.com/questions/33913308/socket-module-how-to-send-integer
        resp_data = bytes()
        resp_data = self.__recvall(int.from_bytes(self.__recvall(TCP_MESSAGE_HEADER_LENGTH), "big", signed=False))
        if resp_data is None or len(resp_data) == 0:
            self.__close_socket()
            raise Exception("socket connection broken")
        appmesh_resp = ResponseMsg().desirialize(resp_data)
        http_resp = requests.Response()
        http_resp.status_code = appmesh_resp.http_status
        http_resp._content = appmesh_resp.body if "application/octet-stream" in appmesh_resp.body_msg_type.lower() else appmesh_resp.body.encode("utf8")
        http_resp.headers = appmesh_resp.headers
        http_resp.encoding = MESSAGE_ENCODING_UTF8
        if appmesh_resp.body_msg_type:
            http_resp.headers["Content-Type"] = appmesh_resp.body_msg_type
        assert req_id == appmesh_resp.uuid
        return http_resp

    ########################################
    # File management
    ########################################
    def file_download(self, file_path: str, local_file: str) -> bool:
        """Copy a remote file to local, the local file will have the same permission as the remote file

        Args:
            file_path (str): the remote file path.
            local_file (str): the local file path to be downloaded.

        Returns:
            bool: success or failure.
        """
        resp = self._request_http(
            AppMeshClient.Method.GET, path="/appmesh/file/download", header={"File-Path": file_path})
        if resp.status_code == HTTPStatus.OK:
            with open(local_file, "wb") as fp:
                chunk_data = bytes()
                chunk_size = int.from_bytes(self.__recvall(TCP_MESSAGE_HEADER_LENGTH), "big", signed=False)
                while chunk_size > 0:
                    chunk_data = self.__recvall(chunk_size)
                    if chunk_data is None or len(chunk_data) == 0:
                        self.__close_socket()
                        raise Exception("socket connection broken")
                    fp.write(chunk_data)
                    chunk_size = int.from_bytes(self.__recvall(TCP_MESSAGE_HEADER_LENGTH), "big", signed=False)
            if resp.headers.__contains__("File-Mode"):
                os.chmod(path=local_file, mode=int(resp.headers["File-Mode"]))
            if resp.headers.__contains__("File-User") and resp.headers.__contains__("File-Group"):
                file_uid = int(resp.headers["File-User"])
                file_gid = int(resp.headers["File-Group"])
                try:
                    os.chown(path=local_file, uid=file_uid, gid=file_gid)
                except Exception as ex:
                    print(ex)
            return True
        return False

    def file_upload(self, local_file: str, file_path: str):
        """Upload a local file to the remote server, the remote file will have the same permission as the local file

        Dependency:
            sudo apt install python3-pip
            pip3 install requests_toolbelt

        Args:
            local_file (str): the local file path.
            file_path (str): the target remote file to be uploaded.

        Returns:
            bool: success or failure.
            str: text message.
        """
        with open(file=local_file, mode="rb") as fp:
            file_stat = os.stat(local_file)
            header = {}
            header["File-Path"] = file_path
            header["File-Mode"] = str(file_stat.st_mode)
            header["File-User"] = str(file_stat.st_uid)
            header["File-Group"] = str(file_stat.st_gid)
            header["Content-Type"] = "text/plain"
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/file/upload", header=header)
            if resp.status_code == HTTPStatus.OK:
                chunk_size = 1024*4  # 131072 bytes, default max ssl buffer size
                chunk_data = fp.read(chunk_size)
                while chunk_data:
                    self.__socket_client.sendall(len(chunk_data).to_bytes(TCP_MESSAGE_HEADER_LENGTH, "big", signed=False))
                    self.__socket_client.sendall(chunk_data)
                    chunk_data = fp.read(chunk_size)
                self.__socket_client.sendall(int(0).to_bytes(TCP_MESSAGE_HEADER_LENGTH, "big", signed=False))
                return True, ""
            return False, resp.json()[REST_TEXT_MESSAGE_JSON_KEY]
