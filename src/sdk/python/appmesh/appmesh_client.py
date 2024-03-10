#!/usr/bin/python3
"""App Mesh Python SDK"""
import abc
import aniso8601
import base64
import copy
import json
import os
import socket
import ssl
import uuid

from enum import Enum, unique
from http import HTTPStatus
from urllib import parse
from datetime import datetime
import requests


DEFAULT_TOKEN_EXPIRE_SECONDS = "P1W"  # default 7 day(s)
DEFAULT_RUN_APP_TIMEOUT_SECONDS = "PT1H"  # 1 hour
DEFAULT_RUN_APP_LIFECYCLE_SECONDS = "PT10H"  # 10 hours
REST_TEXT_MESSAGE_JSON_KEY = "message"
MESSAGE_ENCODING_UTF8 = "utf-8"
TCP_MESSAGE_HEADER_LENGTH = 4
_SSL_CA_PEM_FILE = "/opt/appmesh/ssl/ca.pem"
_SSL_CLIENT_PEM_FILE = "/opt/appmesh/ssl/client.pem"
_SSL_CLIENT_PEM_KEY_FILE = "/opt/appmesh/ssl/client-key.pem"
HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
HTTP_USER_AGENT = "appmeshsdk/py"


def _get_str_item(data: dict, key):
    return data[key] if (data and key in data and data[key] and isinstance(data[key], str)) else None


def _get_int_item(data: dict, key):
    return int(data[key]) if (data and key in data and data[key] and isinstance(data[key], int)) else None


def _get_bool_item(data: dict, key):
    return bool(data[key]) if (data and key in data and data[key]) else None


def _get_native_item(data: dict, key):
    return copy.deepcopy(data[key]) if (data and key in data and data[key]) else None


class App(object):
    """
    App object present an application in App Mesh
    """

    @unique
    class Permission(Enum):
        Deny = "1"
        Read = "2"
        Write = "3"

    class Behavior(object):
        """
        Application error handling behavior definition object
        """

        @unique
        class Action(Enum):
            Restart = "restart"
            Standby = "standby"
            Keepalive = "keepalive"
            Remove = "remove"

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)
            # default exit behavior [restart,standby,keepalive,remove]
            self.exit = _get_str_item(data, "exit")
            # exit code behavior (e.g, --control 0:restart --control 1:standby), higher priority than default exit behavior
            self.control = _get_native_item(data, "control") if _get_native_item(data, "control") else dict()

        def set_exit_behavior(self, a: Action) -> None:
            """Set error handling behavior while application exit"""
            self.exit = a.value

        def set_control_behavior(self, control_code: int, a: Action) -> None:
            """Set error handling behavior while application exit with specific return code"""
            self.control[str(control_code)] = a.value

    class DailyLimitation(object):
        """
        Application avialable day time definition object
        """

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)
            # daily start time (e.g., '09:00:00+08')
            self.daily_start = _get_int_item(data, "daily_start")
            # daily end time (e.g., '20:00:00+08')
            self.daily_end = _get_int_item(data, "daily_end")

        def set_daily_range(self, start: datetime, end: datetime) -> None:
            """Set valid day hour range"""
            self.daily_start = int(start.timestamp())
            self.daily_end = int(end.timestamp())

    class ResourceLimitation(object):
        """
        Application cgroup limitation definition object
        """

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)
            # CPU shares (relative weight)
            self.cpu_shares = _get_int_item(data, "cpu_shares")
            # memory limit in MByte
            self.memory_mb = _get_int_item(data, "memory_mb")
            # virtual memory limit in MByte
            self.memory_virt_mb = _get_int_item(data, "memory_virt_mb")

    def __init__(self, data=None):
        """Construct an App Mesh Application object

        Args:
            data (str | dict | json, optional): application definition data
        """

        if isinstance(data, (str, bytes, bytearray)):
            data = json.loads(data)

        # application name
        self.name = _get_str_item(data, "name")
        # full command line with arguments
        self.command = _get_str_item(data, "command")

        # use shell mode, cmd can be more shell commands with string format
        self.shell = _get_bool_item(data, "shell")
        # application description
        self.description = _get_str_item(data, "description")
        # metadata string/JSON (input for application, pass to process stdin)
        self.metadata = _get_native_item(data, "metadata")
        # working directory
        self.working_dir = _get_str_item(data, "working_dir")
        # initial application status (true is enable, false is disabled)
        self.status = _get_int_item(data, "status")
        # docker image which used to run command line (for docker container application)
        self.docker_image = _get_str_item(data, "docker_image")
        # stdout file cache number
        self.stdout_cache_num = _get_int_item(data, "stdout_cache_num")

        # start date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05')
        self.start_time = _get_int_item(data, "start_time")
        # end date time for app (ISO8601 time format, e.g., '2020-10-11T10:22:05')
        self.end_time = _get_int_item(data, "end_time")
        # start interval seconds for short running app, support ISO 8601 durations and cron expression (e.g., 'P1Y2M3DT4H5M6S' 'P5W' '* */5 * * * *')
        self.interval = _get_int_item(data, "interval")
        # indicate interval parameter use cron expression
        self.cron = _get_bool_item(data, "cron")
        self.daily_limitation = App.DailyLimitation(_get_native_item(data, "daily_limitation"))

        # extra timeout seconds for stopping current process, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
        self.retention = _get_str_item(data, "retention")

        # health check script command (e.g., sh -x 'curl host:port/health', return 0 is health)
        self.health_check_cmd = _get_str_item(data, "health_check_cmd")
        # application user permission, value is 2 bit integer: [group & other], each bit can be deny:1, read:2, write: 3.
        self.permission = _get_int_item(data, "permission")
        self.behavior = App.Behavior(_get_native_item(data, "behavior"))

        # environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used to input docker run parameters)
        self.env = dict()
        if data and "env" in data:
            for k, v in data["env"].items():
                self.env[k] = v
        # security environment variables, encrypt in server side with application owner's cipher
        self.sec_env = dict()
        if data and "sec_env" in data:
            for k, v in data["sec_env"].items():
                self.sec_env[k] = v
        # process id used to attach
        self.pid = _get_int_item(data, "pid")
        self.resource_limit = App.ResourceLimitation(_get_native_item(data, "resource_limit"))

        # readonly attributes
        self.owner = _get_str_item(data, "owner")
        self.pstree = _get_str_item(data, "pstree")
        self.container_id = _get_str_item(data, "container_id")
        self.memory = _get_int_item(data, "memory")
        self.cpu = _get_int_item(data, "cpu")
        self.fd = _get_int_item(data, "fd")
        self.last_start_time = _get_int_item(data, "last_start_time")
        self.last_exit_time = _get_int_item(data, "last_exit_time")
        self.health = _get_int_item(data, "health")
        self.version = _get_int_item(data, "version")
        self.return_code = _get_int_item(data, "return_code")

    def set_valid_time(self, start: datetime, end: datetime) -> None:
        """Set avialable time window"""
        self.start_time = int(start.timestamp()) if start else None
        self.end_time = int(end.timestamp()) if end else None

    def set_env(self, k: str, v: str, secure: bool = False) -> None:
        """Set environment variable"""
        if secure:
            self.sec_env[k] = v
        else:
            self.env[k] = v

    def set_permission(self, group_user: Permission, others_user: Permission) -> None:
        self.permission = int(group_user.value + others_user.value)

    def __str__(self) -> str:
        return json.dumps(self.json())

    def json(self):
        output = copy.deepcopy(self.__dict__)
        output["behavior"] = copy.deepcopy(self.behavior.__dict__)
        output["daily_limitation"] = copy.deepcopy(self.daily_limitation.__dict__)
        output["resource_limit"] = copy.deepcopy(self.resource_limit.__dict__)

        def clean_empty_item(data, key) -> None:
            value = data[key]
            if not value:
                del data[key]
            elif isinstance(value, dict) and key != "metadata":
                for k in list(value):
                    clean_empty_item(value, k)

        for k in list(output):
            clean_empty_item(output, k)
        for k in list(output):
            clean_empty_item(output, k)
        return output


class Run(object):
    """
    Application run object indicate to a remote run from run_async()
    """

    def __init__(self, client, app_name: str, process_id: str):
        self.app_name = app_name
        self.proc_uid = process_id
        self.__client = client

    def wait(self, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for an async run to be finished

        Args:
            run (Run): asyncrized run result from run_async().
            stdout_print (bool, optional): print remote stdout to local or not.
            timeout (int, optional): wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            int: return exit code if process finished, return None for timeout or exception.
        """
        return self.__client.run_async_wait(self, stdout_print, timeout)


class AppMeshClient(metaclass=abc.ABCMeta):
    """
    Client object used to access App Mesh REST Service

    - install pip package: python3 -m pip install --upgrade appmesh
    - import module: from appmesh import appmesh_client
    """

    @unique
    class Method(Enum):
        """REST methods"""

        GET = "GET"
        PUT = "PUT"
        POST = "POST"
        DELETE = "DELETE"
        POST_STREAM = "POST_STREAM"

    def __init__(
        self,
        rest_url: str = "https://127.0.0.1:6060",
        rest_ssl_verify=_SSL_CA_PEM_FILE,
        rest_ssl_client_cert=(_SSL_CLIENT_PEM_FILE, _SSL_CLIENT_PEM_KEY_FILE),
        rest_timeout=(60, 300),
        jwt_token=None,
    ):
        """Construct an App Mesh client object

        Args:
            rest_url (str, optional): server URI string.
            rest_ssl_verify (str, optional): SSL CA certification path for verification, True for use system's default certificate store, False to disable SSL verification.
            rest_ssl_client_cert (tuple, optional): SSL client certificate and key pair, None to disable client verification
            rest_timeout (tuple, optional): HTTP timeout, Defaults to 60 seconds for connect timeout and 300 seconds for read timeout
            jwt_token (str, optional): JWT token, provide correct token is same with login() & authenticate().
        """
        self.server_url = rest_url
        self.__jwt_token = jwt_token
        self.ssl_verify = rest_ssl_verify
        self.ssl_client_cert = rest_ssl_client_cert
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
    def login(self, user_name: str, user_pwd: str, timeout_seconds=DEFAULT_TOKEN_EXPIRE_SECONDS) -> str:
        """Login with user name and password

        Args:
            user_name (str): the name of the user.
            user_pwd (str): the password of the user.
            timeout_seconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W').

        Returns:
            str: JWT token if verify success, otherwise return None.
        """
        self.jwt_token = None
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
        self.jwt_token = token
        headers = {}
        if permission:
            headers["Auth-Permission"] = permission
        resp = self._request_http(AppMeshClient.Method.POST, path="/appmesh/auth", header=headers)
        if resp.status_code == HTTPStatus.OK:
            return True
        else:
            # resp.raise_for_status()
            print(resp.text)
            return False

    ########################################
    # Application view
    ########################################
    def app_view(self, app_name: str) -> App:
        """Get one application information

        Args:
            app_name (str): the application name.

        Returns:
            App: the application object both contain static configuration and runtime information.

        Exception:
            failed request or no such application
        """
        resp = self._request_http(AppMeshClient.Method.GET, path=f"/appmesh/app/{app_name}")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return App(resp.json())

    def app_view_all(self):
        """Get all applications

        Returns:
            list: the application object both contain static configuration and runtime information, only return applications that the user has permissions.

        Exception:
            failed request or no such application
        """
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/applications")
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        apps = []
        for app in resp.json():
            apps.append(App(app))
        return apps

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
    def app_add(self, app: App) -> App:
        """Register an application

        Args:
            app (App): the application definition.

        Returns:
            App: resigtered application object.

        Exception:
            failed request
        """
        resp = self._request_http(AppMeshClient.Method.PUT, path="/appmesh/app/{0}".format(app.name), body=app.json())
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return App(resp.json())

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
            return True, resp.json()["LogLevel"]
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
            role_permission_json (dict): role permission definition array, e.g: ["app-control", "app-delete", "cloud-app-reg", "cloud-app-delete"]

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
        app: App,
        max_time_seconds=DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        life_cycle_seconds=DEFAULT_RUN_APP_LIFECYCLE_SECONDS,
    ):
        """Asyncrized run a command remotely, 'name' attribute in app_json dict used to run an existing application
        Asyncrized run will not block process

        Args:
            app (App): application object.
            max_time_seconds (int | str, optional): max run time for the remote process, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
            life_cycle_seconds (int | str, optional): max lifecycle time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').

        Returns:
            str: app_name, new application name for this run
            str: process_uuid, process UUID for this run
        """
        path = "/appmesh/app/run"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app.json(),
            path=path,
            query={"timeout": self._parse_duration(max_time_seconds), "lifecycle": self._parse_duration(life_cycle_seconds)},
        )
        if resp.status_code != HTTPStatus.OK:
            raise Exception(resp.text)
        return Run(self, resp.json()["name"], resp.json()["process_uuid"])

    def run_async_wait(self, run: Run, stdout_print: bool = True, timeout: int = 0) -> int:
        """Wait for an async run to be finished

        Args:
            run (Run): asyncrized run result from run_async().
            stdout_print (bool, optional): print remote stdout to local or not.
            timeout (int, optional): wait max timeout seconds and return if not finished, 0 means wait until finished

        Returns:
            int: return exit code if process finished, return None for timeout or exception.
        """
        exit_code = None
        if run:
            output_position = 0
            start = datetime.now()
            interval = 1 if self.__class__.__name__ == "AppMeshClient" else 1000
            while len(run.proc_uid) > 0:
                success, output, position, exit_code = self.app_output(
                    app_name=run.app_name, stdout_position=output_position, stdout_index=0, process_uuid=run.proc_uid, timeout=interval
                )
                if output and stdout_print:
                    print(output, end="")
                if position is not None:
                    output_position = position
                if exit_code is not None:
                    # success
                    self.app_delete(run.app_name)
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
        app: App,
        stdout_print: bool = True,
        max_time_seconds=DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        life_cycle_seconds=DEFAULT_RUN_APP_LIFECYCLE_SECONDS,
    ) -> int:
        """Block run a command remotely, 'name' attribute in app_json dict used to run an existing application
        The synchronized run will block the process until the remote run is finished then return the result from HTTP response

        Args:
            app (App): application object.
            stdout_print (bool, optional): whether print remote stdout to local or not. Defaults to True.
            max_time_seconds (int | str, optional): max run time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
            life_cycle_seconds (int | str, optional): max lifecycle time for the remote process. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W').

        Returns:
            int: process exit code, return None if no exit code.
        """
        path = "/appmesh/app/syncrun"
        resp = self._request_http(
            AppMeshClient.Method.POST,
            body=app.json(),
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
        if self.jwt_token:
            header["Authorization"] = "Bearer " + self.jwt_token
        header[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT

        if method is AppMeshClient.Method.GET:
            return requests.get(url=rest_url, params=query, headers=header, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.POST:
            return requests.post(url=rest_url, params=query, headers=header, data=json.dumps(body) if type(body) in (dict, list) else body, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.POST_STREAM:
            return requests.post(
                url=rest_url,
                params=query,
                headers=header,
                data=body,
                cert=self.ssl_client_cert,
                verify=self.ssl_verify,
                stream=True,
            )
        elif method is AppMeshClient.Method.DELETE:
            return requests.delete(url=rest_url, headers=header, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
        elif method is AppMeshClient.Method.PUT:
            return requests.put(url=rest_url, params=query, headers=header, json=body, cert=self.ssl_client_cert, verify=self.ssl_verify, timeout=self.rest_timeout)
        else:
            raise Exception("Invalid http method", method)


class AppMeshClientTCP(AppMeshClient):
    """Client object used to access App Mesh REST Service over TCP (better performance than AppMeshClient)

    Dependency:
        pip3 install msgpack
    """

    def __init__(
        self,
        rest_ssl_verify=_SSL_CA_PEM_FILE,
        rest_ssl_client_cert=(_SSL_CLIENT_PEM_FILE, _SSL_CLIENT_PEM_KEY_FILE),
        jwt_token=None,
        tcp_address=("localhost", 6059),
    ):
        """Construct an App Mesh client TCP object

        Args:
            rest_ssl_verify (str, optional): SSL CA certification path for verification, True for use system's default certificate store, False to disable SSL verification.
            rest_ssl_client_cert (tuple, optional): SSL client certificate and key pair, None to disable client verification
            jwt_token (str, optional): JWT token, provide correct token is same with login() & authenticate().

            tcp_address (tuple, optional): TCP connect address.
        """
        super().__init__("", rest_ssl_verify, rest_ssl_client_cert, None, jwt_token)
        self.tcp_address = tcp_address
        self.__socket_client = None

    def __del__(self) -> None:
        """De-construction"""
        self.__close_socket()

    def __connect_socket(self) -> None:
        """Establish tcp connection"""
        sock = socket.create_connection(self.tcp_address)
        sock.setblocking(True)

        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.verify_mode = ssl.CERT_NONE if self.ssl_verify == False else ssl.CERT_REQUIRED
        if isinstance(self.ssl_verify, str):
            context.check_hostname = True
            context.load_verify_locations(self.ssl_verify)
        if self.ssl_client_cert is not None:
            context.load_cert_chain(certfile=self.ssl_client_cert[0], keyfile=self.ssl_client_cert[1])
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
                raise EOFError("socket closed")
            length -= len(chunk)
            fragments.append(chunk)
        return b"".join(fragments)

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
            body: bytes = b""
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
            body: bytes = b""
            headers: dict = {}

            def desirialize(self, buf: bytes):
                dic = msgpack.unpackb(buf)
                for k, v in dic.items():
                    setattr(self, k, v)
                return self

        if super().jwt_token:
            header["Authorization"] = "Bearer " + super().jwt_token
        header[HTTP_USER_AGENT_HEADER_NAME] = HTTP_USER_AGENT
        if self.__socket_client is None:
            self.__connect_socket()
        req_id = str(uuid.uuid1())
        appmesh_requst = RequestMsg()
        appmesh_requst.uuid = req_id
        appmesh_requst.http_method = method.value
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
        resp = self._request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header={"File-Path": file_path})
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
                chunk_size = 1024 * 4  # 131072 bytes, default max ssl buffer size
                chunk_data = fp.read(chunk_size)
                while chunk_data:
                    self.__socket_client.sendall(len(chunk_data).to_bytes(TCP_MESSAGE_HEADER_LENGTH, "big", signed=False))
                    self.__socket_client.sendall(chunk_data)
                    chunk_data = fp.read(chunk_size)
                self.__socket_client.sendall(int(0).to_bytes(TCP_MESSAGE_HEADER_LENGTH, "big", signed=False))
                return True, ""
            return False, resp.json()[REST_TEXT_MESSAGE_JSON_KEY]
