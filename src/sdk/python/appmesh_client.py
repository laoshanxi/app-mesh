#!/usr/bin/python3
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


class Method(Enum):
    """REST methods"""

    GET = "GET"
    PUT = "PUT"
    POST = "POST"
    DELETE = "DELETE"
    GET_STREAM = "GET_STREAM"
    POST_STREAM = "POST_STREAM"


class AppMeshClient:
    """Client object used to access App Mesh Service"""

    def __init__(
        self,
        server_host="127.0.0.1",
        server_port=6060,
        ssl_enable=True,
        jwt_auth_enable=True,
    ):
        """init function"""
        self.server_host = server_host
        self.server_port = server_port
        self.ssl_enable = ssl_enable
        self.jwt_auth_enable = jwt_auth_enable
        self.jwt_token = ""

    def login(self, user_name, user_pwd, timeout_seconds=DEFAULT_TOKEN_EXPIRE_SECONDS):
        """login session"""
        if self.jwt_auth_enable:
            self.jwt_token = ""
            resp = self.__request_http(
                Method.POST,
                path="/appmesh/login",
                header={
                    "Username": base64.b64encode(user_name.encode()),
                    "Password": base64.b64encode(user_pwd.encode()),
                    "Expire-Seconds": str(timeout_seconds)
                },
            )
            if resp.status_code == HTTPStatus.OK:
                self.jwt_token = resp.json()["Access-Token"]
                return True
            else:
                # resp.raise_for_status()
                print(resp.text)
                return False

    def login_with_token(self, token):
        """login session with existing JWT token"""
        if self.jwt_auth_enable:
            self.jwt_token = token
            resp = self.__request_http(
                Method.POST,
                path="/appmesh/auth",
            )
            if resp.status_code == HTTPStatus.OK:
                return True
            else:
                # resp.raise_for_status()
                print(resp.text)
                return False

    def get_app(self, app_name):
        """get application JSON information"""
        resp = self.__request_http(Method.GET, path="/appmesh/app/{0}".format(app_name))
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_app_output(self, app_name):
        """get application output"""
        resp = self.__request_http(Method.GET, path="/appmesh/app/{0}/output".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.text

    def get_apps(self):
        """get all applications"""
        resp = self.__request_http(Method.GET, path="/appmesh/applications")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_cloud_apps(self):
        """get cloud applications"""
        resp = self.__request_http(Method.GET, path="/appmesh/cloud/applications")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def remove_cloud_app(self, app_name):
        """delete cloud application"""
        resp = self.__request_http(Method.DELETE, path="/appmesh/cloud/app/{0}".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.text

    def add_cloud_app(self, app_json):
        """add cloud application"""
        resp = self.__request_http(Method.PUT, path="/appmesh/cloud/app/{0}".format(app_json["content"]["name"]), body=app_json)
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_cloud_nodes(self):
        """get cloud nodes"""
        resp = self.__request_http(Method.GET, path="/appmesh/cloud/nodes")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_app_health(self, app_name):
        """get application health status, 0 is health"""
        resp = self.__request_http(Method.GET, path="/appmesh/app/{0}/health".format(app_name))
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_resource(self):
        """get app mesh host resource status"""
        resp = self.__request_http(Method.GET, path="/appmesh/resources")
        return resp.status_code == HTTPStatus.OK, resp.text == "0"

    def get_config(self):
        """get app mesh configuration JSON"""
        resp = self.__request_http(Method.GET, path="/appmesh/config")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def set_config(self, cfg_json):
        """update app mesh configuration"""
        resp = self.__request_http(Method.POST, path="/appmesh/config")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def add_app(self, app_json):
        """register an application"""
        resp = self.__request_http(Method.PUT, path="/appmesh/app/{0}".format(app_json["name"]), body=app_json)
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def remove_app(self, app_name):
        """remove an application"""
        resp = self.__request_http(Method.DELETE, path="/appmesh/app/{0}".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.text

    def enable_app(self, app_name):
        """enable an application"""
        resp = self.__request_http(Method.POST, path="/appmesh/app/{0}/enable".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.text

    def disable_app(self, app_name):
        """stop and disable an application"""
        resp = self.__request_http(Method.POST, path="/appmesh/app/{0}/disable".format(app_name))
        return (resp.status_code == HTTPStatus.OK), resp.text

    def add_tag(self, tag_name, tag_value):
        """add a tag for app mesh node"""
        resp = self.__request_http(
            Method.PUT,
            query={"value": tag_value},
            path="/appmesh/label/{0}".format(tag_name),
        )
        return resp.status_code == HTTPStatus.OK

    def remove_tag(self, tag_name):
        """remove a tag for app mesh node"""
        resp = self.__request_http(Method.DELETE, path="/appmesh/label/{0}".format(tag_name))
        return resp.status_code == HTTPStatus.OK

    def get_tags(self):
        """get tags for app mesh node"""
        resp = self.__request_http(Method.GET, path="/appmesh/labels")
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_metrics(self):
        """get Promethus metrics"""
        resp = self.__request_http(Method.GET, path="/appmesh/metrics")
        return resp.status_code == HTTPStatus.OK, resp.text

    def download(self, file_path, local_file):
        """download a remote file to local"""
        resp = self.__request_http(Method.GET, path="/appmesh/file/download", header={"File-Path": file_path})
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
        """upload a local file to remote"""
        with open(file=local_file, mode="rb") as fp:
            file_stat = os.stat(local_file)
            header = {}
            header["File-Path"] = file_path
            header["File-Mode"] = str(file_stat.st_mode)
            header["File-User"] = str(file_stat.st_uid)
            header["File-Group"] = str(file_stat.st_gid)
            # https://stackoverflow.com/questions/22567306/python-requests-file-upload
            resp = self.__request_http(
                Method.POST_STREAM,
                path="/appmesh/file/upload",
                header=header,
                body=fp,
            )
            if resp.status_code == HTTPStatus.OK:
                return True, ""
            return False, resp.text

    def run(
        self,
        app_json,
        synchronized=True,
        max_exec_time=DEFAULT_RUN_APP_TIMEOUT_SECONDS,
        async_retention=DEFAULT_RUN_APP_RETENTION_DURATION,
    ):
        """remote run a command"""
        path = ""
        if synchronized:
            path = "/appmesh/app/syncrun"
        else:
            path = "/appmesh/app/run"
        resp = self.__request_http(
            Method.POST,
            body=app_json,
            path=path,
            query={"timeout": str(max_exec_time), "retention": str(async_retention)},
        )
        if resp.status_code == HTTPStatus.OK:
            if synchronized:
                print(resp.text, end="")
            else:
                app_name = resp.json()["name"]
                process_uuid = resp.json()["process_uuid"]
                # print(resp.json())
                while len(process_uuid) > 0:
                    # /app/testapp/run/output?process_uuid=UUID
                    path = "/appmesh/app/{0}/run/output".format(app_name)
                    resp = self.__request_http(Method.GET, path=path, query={"process_uuid": process_uuid})
                    if resp.text is not None:
                        print(resp.text, end="")
                    if resp.headers.__contains__("exit_code") or (resp.status_code != HTTPStatus.OK):
                        break
                    time.sleep(0.5)
        else:
            print(resp.text)

    def __request_http(self, method, path, query={}, header={}, body=None):
        """http request"""
        protocol = ""
        if self.ssl_enable:
            protocol = "https"
        else:
            protocol = "http"

        rest_url = "{0}://{1}:{2}".format(protocol, self.server_host, str(self.server_port))
        rest_url = parse.urljoin(rest_url, path)

        if len(self.jwt_token):
            header["Authorization"] = "Bearer " + self.jwt_token

        if method is Method.GET:
            return requests.get(url=rest_url, params=query, headers=header, verify=False)
        elif method is Method.GET_STREAM:
            return requests.get(url=rest_url, params=query, headers=header, verify=False, stream=True)
        elif method is Method.POST:
            return requests.post(url=rest_url, params=query, headers=header, json=body, verify=False)
        elif method is Method.POST_STREAM:
            return requests.post(
                url=rest_url,
                params=query,
                headers=header,
                data=body,
                verify=False,
                stream=True,
            )
        elif method is Method.DELETE:
            return requests.delete(url=rest_url, headers=header, verify=False)
        elif method is Method.PUT:
            return requests.put(url=rest_url, params=query, headers=header, json=body, verify=False)
        else:
            raise Exception("Invalid http method", method)
