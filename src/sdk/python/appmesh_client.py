#!/usr/bin/python3
"""App Mesh Python SDK"""
# import asyncio  # pip3 install asyncio
import base64
import os
import time
from enum import Enum
from http import HTTPStatus
from urllib import parse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24)  # default 7 days
DEFAULT_RUN_APP_TIMEOUT_SECONDS = 10
DEFAULT_RUN_APP_RETENTION_DURATION = 10


class AppMeshClient:
    """Client object used to access App Mesh REST Service"""

    class Method(Enum):
        """REST methods"""

        GET = "GET"
        PUT = "PUT"
        POST = "POST"
        DELETE = "DELETE"
        GET_STREAM = "GET_STREAM"
        POST_STREAM = "POST_STREAM"

    def __init__(
        self,
        server_url="https://127.0.0.1:6060",
        jwt_auth_enable=True,
    ):
        """Construction function"""
        self.server_url = server_url
        self.jwt_auth_enable = jwt_auth_enable
        self.__jwt_token = None

    ########################################
    # Authentication
    ########################################
    def login(self, user_name, user_pwd, timeout_seconds=DEFAULT_TOKEN_EXPIRE_SECONDS):
        """
        User Login with password

        Parameters
        ----------
            user_name : str
                The name of the user
            user_pwd : str
                The password of the user
            timeout_seconds : int
                Login token expire timeout of seconds, default is 1 week

        Returns
        -------
            UserTokenString
                Return JWT token if JWT enabled and password verify success
                Otherwise return None
        """
        self.__jwt_token = None
        if self.jwt_auth_enable:
            resp = self.__request_http(
                AppMeshClient.Method.POST,
                path="/appmesh/login",
                header={
                    "Username": base64.b64encode(user_name.encode()),
                    "Password": base64.b64encode(user_pwd.encode()),
                    "Expire-Seconds": str(timeout_seconds),
                },
            )
            if resp.status_code == HTTPStatus.OK:
                if "Access-Token" in resp.json():
                    self.__jwt_token = resp.json()["Access-Token"]
            else:
                print(resp.text)
                # resp.raise_for_status()
        return self.__jwt_token

    def authentication(self, token, permission=None):
        """
        Verify User token and permission id

        Parameters
        ----------
            token : str
                JWT token
            permission : str
                The permission ID used to verify for the token user
                Permission ID can be:
                    - Pre-defined by App Mesh from security.json (e.g 'app-view', 'app-delete')
                    - Defined by input from update_role() or security.json

        Returns
        -------
            AuthenticationResult
                Return bool value to indicate the authentication result
        """
        if self.jwt_auth_enable:
            self.__jwt_token = token
            headers = {}
            if permission is not None:
                headers["Auth-Permission"] = permission
            resp = self.__request_http(AppMeshClient.Method.POST, path="/appmesh/auth", header=headers)
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
    def get_app(self, app_name):
        """
        Get application JSON information

        Parameters
        ----------
            app_name : str
                The application name

        Returns
        -------
            Application JSON
                The application JSON both contain static configuration and runtime infomation
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/app/{0}".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_apps(self):
        """
        Get all application JSON information

        Returns
        -------
            Array of application JSON
                The application JSON both contain static configuration and runtime infomation
                Only return applications that the user have permissions
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/applications")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_app_output(self, app_name, output_position=0, stdout_index=0, stdout_maxsize=10240, process_uuid=""):
        """
        Get application stdout

        Parameters
        ----------
            app_name : str
                The application name
            output_position : int
                Output start position, 0 means start from beginning
            stdout_index : str
                Index of history process stdout, 0 means current running process
                The history number depend by 'stdout_cache_num' of a application
            stdout_maxsize : int
                Max buffer size
            process_uuid : str
                Used to lock a process

        Returns
        -------
            Success : bool
            Output Text : str
            Output Position : None or int
            Exit Code : None or int
        """
        resp = self.__request_http(
            AppMeshClient.Method.GET,
            path="/appmesh/app/{0}/output".format(app_name),
            query={
                "stdout_position": str(output_position),
                "stdout_index": str(stdout_index),
                "stdout_maxsize": str(stdout_maxsize),
                "process_uuid": process_uuid,
            },
        )
        out_position = None if not resp.headers.__contains__("Output-Position") else int(resp.headers["Output-Position"])
        exit_code = None if not resp.headers.__contains__("Exit-Code") else int(resp.headers["Exit-Code"])
        return (resp.status_code == HTTPStatus.OK), resp.text, out_position, exit_code

    def get_app_health(self, app_name):
        """
        Get application health status, 0 is health

        Parameters
        ----------
            app_name : str
                The application name
        Returns
        -------
            HeathStatus : str
                0 is heathy, 1 is unhealthy
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/app/{0}/health".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Application manage
    ########################################
    def add_app(self, app_json):
        """
        Register an application

        Parameters
        ----------
            app_json : JSON
                The application definition
        Returns
        -------
            Success : bool
            ApplicationJson : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.PUT, path="/appmesh/app/{0}".format(app_json["name"]), body=app_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def remove_app(self, app_name):
        """
        Remove an application

        Parameters
        ----------
            app_name : str
                The application name
        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.DELETE, path="/appmesh/app/{0}".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def enable_app(self, app_name):
        """
        Enable an application

        Parameters
        ----------
            app_name : str
                The application name
        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.POST, path="/appmesh/app/{0}/enable".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def disable_app(self, app_name):
        """
        Stop and Disable an application

        Parameters
        ----------
            app_name : str
                The application name
        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.POST, path="/appmesh/app/{0}/disable".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Cloud API
    ########################################
    def get_cloud_apps(self):
        """
        Get all cloud applications

        Returns
        -------
            Success : bool
            CloudApplicationsJson : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/cloud/applications")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def remove_cloud_app(self, app_name):
        """
        Delete a cloud application

        Parameters
        ----------
            app_name : str
                The application name for cloud
        Returns
        -------
            Success : bool
        """
        resp = self.__request_http(AppMeshClient.Method.DELETE, path="/appmesh/cloud/app/{0}".format(app_name))
        return resp.status_code == HTTPStatus.OK

    def add_cloud_app(self, app_json):
        """
        Add a cloud application

        Parameters
        ----------
            app_json : JSON
                The cloud application definition with replication, condition and resource requirement
        Returns
        -------
            Success : bool
            CloudApplicationJson : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.PUT, path="/appmesh/cloud/app/{0}".format(app_json["content"]["name"]), body=app_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_cloud_nodes(self):
        """
        Get cluster node list

        Returns
        -------
            Success : bool
            ClusterNodeList : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/cloud/nodes")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Configuration API
    ########################################
    def get_resource(self):
        """
        Get App Mesh host resource report include CPU, memory and disk

        Returns
        -------
            Success : bool
            Resources : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/resources")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_config(self):
        """
        Get App Mesh configuration JSON

        Returns
        -------
            Success : bool
            Resources : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/config")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def set_config(self, cfg_json):
        """
        Update App Mesh configuration, the format follow 'appsvc.json', support update fragment config

        Returns
        -------
            Success : bool
            CurrentConfiguration : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.POST, path="/appmesh/config", body=cfg_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def set_log_level(self, level="DEBUG"):
        """
        Update App Mesh log level(DEBUG/INFO/NOTICE/WARN/ERROR), a wrapper of set_config()

        Returns
        -------
            Success : bool
            CurrentConfiguration : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.POST, path="/appmesh/config", body={"LogLevel": level})
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # User Management
    ########################################
    def change_passwd(self, new_password):
        """
        Change current user password

        Parameters
        ----------
            new_password : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.POST,
            path="/appmesh/user/{0}/passwd".format(new_password),
            header={"New-Password": base64.b64encode(new_password.encode())},
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def add_user(self, user_name, user_json):
        """
        Add a new user, not available for LDAP user

        Parameters
        ----------
            user_name : str
            user_json : json
                User definition, follow same user format from security.json

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.PUT,
            path="/appmesh/user/{0}".format(user_name),
            body=user_json,
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def delete_user(self, user_name):
        """
        Delete an existing user

        Parameters
        ----------
            user_name : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.DELETE,
            path="/appmesh/user/{0}".format(user_name),
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def lock_user(self, user_name):
        """
        Lock an existing user

        Parameters
        ----------
            user_name : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.POST,
            path="/appmesh/user/{0}/lock".format(user_name),
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def unlock_user(self, user_name):
        """
        Unlock an existing user

        Parameters
        ----------
            user_name : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.POST,
            path="/appmesh/user/{0}/unlock".format(user_name),
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_users(self):
        """
        Get all users

        Returns
        -------
            Success : bool
            UserList : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.GET, path="/appmesh/users")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_roles(self):
        """
        Get all roles

        Returns
        -------
            Success : bool
            RoleList : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.GET, path="/appmesh/roles")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_groups(self):
        """
        Get all groups

        Returns
        -------
            Success : bool
            GroupList : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.GET, path="/appmesh/groups")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_permissions(self):
        """
        Get all permissions

        Returns
        -------
            Success : bool
            PermissionIdList : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.GET, path="/appmesh/permissions")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_user_permissions(self):
        """
        Get permissions for current user

        Returns
        -------
            Success : bool
            PermissionIdList : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.GET, path="/appmesh/user/permissions")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def update_role(self, role_name, role_json):
        """
        Update (or add) a role with defined permissions
        The permission ID can be App Mesh pre-defined or other permission ID

        Parameters
        ----------
            role_name : str
            role_json : JSON

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(method=AppMeshClient.Method.POST, path="/appmesh/role/{0}".format(role_name), body=role_json)
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def delete_role(self, role_name):
        """
        Delete an existing role

        Parameters
        ----------
            role_name : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            method=AppMeshClient.Method.DELETE,
            path="/appmesh/role/{0}".format(role_name),
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Tag management API
    ########################################
    def add_tag(self, tag_name, tag_value):
        """
        Add a tag(label) for current logon node

        Parameters
        ----------
            tag_name : str
            tag_value : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(
            AppMeshClient.Method.PUT,
            query={"value": tag_value},
            path="/appmesh/label/{0}".format(tag_name),
        )
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def remove_tag(self, tag_name):
        """
        Delete a tag(label) for current logon node

        Parameters
        ----------
            tag_name : str

        Returns
        -------
            Success : bool
            Message : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.DELETE, path="/appmesh/label/{0}".format(tag_name))
        return (resp.status_code == HTTPStatus.OK), resp.json()

    def get_tags(self):
        """
        Get all tags for current logon node

        Returns
        -------
            Success : bool
            TagJson : JSON
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/labels")
        return (resp.status_code == HTTPStatus.OK), resp.json()

    ########################################
    # Promethus metrics
    ########################################
    def get_metrics(self):
        """
        Get Promethus metrics

        Returns
        -------
            MetricsText : str
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/metrics")
        return resp.status_code == HTTPStatus.OK, resp.text

    ########################################
    # File management
    ########################################
    def download(self, file_path, local_file):
        """
        Copy a remote file to local, local file will have the same permission with remote file

        Parameters
        ----------
            file_path : str
            local_file : str

        Returns
        -------
            Success : bool
        """
        resp = self.__request_http(AppMeshClient.Method.GET, path="/appmesh/file/download", header={"File-Path": file_path})
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
                os.chown(path=local_file, uid=file_uid, gid=file_gid)
            return True
        return False

    def upload(self, file_path, local_file):
        """
        Upload a local file to remote, remote file will have the same permission with local file

        Parameters
        ----------
            file_path : str
            local_file : str

        Returns
        -------
            Success : bool
        """
        with open(file=local_file, mode="rb") as fp:
            file_stat = os.stat(local_file)
            header = {}
            header["File-Path"] = file_path
            header["File-Mode"] = str(file_stat.st_mode)
            header["File-User"] = str(file_stat.st_uid)
            header["File-Group"] = str(file_stat.st_gid)
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self.__request_http(
                AppMeshClient.Method.POST_STREAM,
                path="/appmesh/file/upload",
                header=header,
                body=fp,
            )
            if resp.status_code == HTTPStatus.OK:
                return True, ""
            return False, resp.text

    ########################################
    # Run command or Application and get output
    ########################################
    async def run_asyncio(
        self,
        app_json,
        synchronized=True,
        max_exec_time=DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        async_retention=DEFAULT_RUN_APP_RETENTION_DURATION,
    ):
        """Wrapper of self.run() used for asyncio"""
        return self.run(app_json, synchronized, max_exec_time, async_retention)

    def run(
        self,
        app_json,
        synchronized=True,
        max_exec_time=DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        async_retention=DEFAULT_RUN_APP_RETENTION_DURATION,
    ):
        """
        Run a command remotely, app_json specify 'name' attributes used to run a existing application

        Parameters
        ----------
            app_json : JSON
                Application JSON definition
            synchronized : bool
                Synchronized run will block process until the remote run finished and get result for one REST request
            max_exec_time : int
                Set a max run time for the remote process
            async_retention : int
                Asynchronism run will keep process status for a while for client to fetch

        Returns
        -------
            ProcessExitCode : int
        """
        path = ""
        if synchronized:
            path = "/appmesh/app/syncrun"
        else:
            path = "/appmesh/app/run"
        resp = self.__request_http(
            AppMeshClient.Method.POST,
            body=app_json,
            path=path,
            query={"timeout": str(max_exec_time), "retention": str(async_retention)},
        )
        exit_code = 0
        if resp.status_code == HTTPStatus.OK:
            if synchronized:
                print(resp.text, end="")
                if resp.headers.__contains__("Exit-Code"):
                    exit_code = int(resp.headers.get("Exit-Code"))
            else:
                app_name = resp.json()["name"]
                process_uuid = resp.json()["process_uuid"]
                output_position = 0
                # print(resp.json())
                while len(process_uuid) > 0:
                    success, output, position, exit_code = self.get_app_output(
                        app_name=app_name, output_position=output_position, stdout_index=0, process_uuid=process_uuid
                    )
                    if output is not None:
                        print(resp.text, end="")
                    if position is not None:
                        output_position = position
                    if exit_code is not None:
                        exit_code = exit_code
                    if (exit_code is not None) or (not success):
                        break
                    time.sleep(0.5)
        else:
            print(resp.text)
        return exit_code

    def __request_http(self, method, path, query={}, header={}, body=None):
        """http request"""
        rest_url = parse.urljoin(self.server_url, path)

        if self.__jwt_token is not None:
            header["Authorization"] = "Bearer " + self.__jwt_token

        if method is AppMeshClient.Method.GET:
            return requests.get(url=rest_url, params=query, headers=header, verify=False)
        elif method is AppMeshClient.Method.GET_STREAM:
            return requests.get(url=rest_url, params=query, headers=header, verify=False, stream=True)
        elif method is AppMeshClient.Method.POST:
            return requests.post(url=rest_url, params=query, headers=header, json=body, verify=False)
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
            return requests.delete(url=rest_url, headers=header, verify=False)
        elif method is AppMeshClient.Method.PUT:
            return requests.put(url=rest_url, params=query, headers=header, json=body, verify=False)
        else:
            raise Exception("Invalid http method", method)
