#!/usr/bin/python3
import requests
import json
import base64
import time
import urllib3
from http import HTTPStatus
from enum import Enum
from urllib import parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24)  # default 7 days
DEFAULT_RUN_APP_TIMEOUT_SECONDS = 10
DEFAULT_RUN_APP_RETENTION_DURATION = 10


class Method(Enum):
    GET = "GET"
    PUT = "PUT"
    POST = "POST"
    DELETE = "DELETE"


class AppMeshClient:

    def __init__(self, server_host="127.0.0.1", server_port=6060, ssl_enable=True, jwt_auth_enable=True):
        self.server_host = server_host
        self.server_port = server_port
        self.ssl_enable = ssl_enable
        self.jwt_auth_enable = jwt_auth_enable
        self.jwt_token = ""

    def login(self, user_name, user_pwd, timeout_seconds=DEFAULT_TOKEN_EXPIRE_SECONDS):
        if self.jwt_auth_enable:
            self.jwt_token = ""
            resp = self.__request_http(
                Method.POST,
                path="/appmesh/login",
                header={"UserName": base64.b64encode(user_name.encode()), "Password": base64.b64encode(user_pwd.encode())})
            if resp.status_code == HTTPStatus.OK:
                self.jwt_token = resp.json()["AccessToken"]
                return True
            else:
                # resp.raise_for_status()
                print(resp.text)
                return False

    def get_app(self, app_name):
        resp = self.__request_http(
            Method.GET,
            path="/appmesh/app/{0}".format(app_name)
        )
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_apps(self):
        resp = self.__request_http(
            Method.GET,
            path="/appmesh/applications"
        )
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def get_resource(self):
        resp = self.__request_http(
            Method.GET,
            path="/appmesh/resources"
        )
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def reg_app(self, app_json):
        resp = self.__request_http(
            Method.PUT,
            path="/appmesh/app/{0}".format(app_json["name"])
        )
        if resp.status_code == HTTPStatus.OK:
            return True, resp.json()
        else:
            return False, resp.text

    def remove_app(self, app_name):
        resp = self.__request_http(
            Method.DELETE,
            path="/appmesh/app/{0}".format(app_name)
        )
        return (resp.status_code == HTTPStatus.OK), resp.text

    def enable_app(self, app_name):
        resp = self.__request_http(
            Method.POST,
            path="/appmesh/app/{0}/enable".format(app_name)
        )
        return (resp.status_code == HTTPStatus.OK), resp.text

    def disable_app(self, app_name):
        resp = self.__request_http(
            Method.POST,
            path="/appmesh/app/{0}/disable".format(app_name)
        )
        return (resp.status_code == HTTPStatus.OK), resp.text

    def add_tag(self, tag_name, tag_value):
        resp = self.__request_http(
            Method.PUT,
            query={"value": tag_value},
            path="/appmesh/label/{0}".format(tag_name)
        )
        return (resp.status_code == HTTPStatus.OK)

    def remove_tag(self, tag_name):
        resp = self.__request_http(
            Method.DELETE,
            path="/appmesh/label/{0}".format(tag_name)
        )
        return (resp.status_code == HTTPStatus.OK)

    def get_tags(self):
        resp = self.__request_http(
            Method.GET,
            path="/appmesh/labels"
        )
        return resp.json()

    def run(self, app_json, synchronized=True, max_exec_time=DEFAULT_RUN_APP_TIMEOUT_SECONDS, async_retention=DEFAULT_RUN_APP_RETENTION_DURATION):
        path = ""
        if synchronized:
            path = "/appmesh/app/syncrun"
        else:
            path = "/appmesh/app/run"
        resp = self.__request_http(
            Method.POST,
            body=app_json,
            path=path,
            query={"timeout": str(max_exec_time),
                   "retention": str(async_retention)}
        )
        if resp.status_code == HTTPStatus.OK:
            if synchronized:
                print(resp.text, end='')
            else:
                app_name = resp.json()["name"]
                process_uuid = resp.json()["process_uuid"]
                # print(resp.json())
                while len(process_uuid) > 0:
                    # /app/testapp/run/output?process_uuid=UUID
                    path = "/appmesh/app/{0}/run/output".format(app_name)
                    resp = self.__request_http(Method.GET,
                                               path=path,
                                               query={"process_uuid": process_uuid})
                    if resp.text is not None:
                        print(resp.text, end='')
                    if resp.headers.__contains__("exit_code") or (resp.status_code != HTTPStatus.OK):
                        break
                    time.sleep(0.5)
        else:
            print(resp.text)

    def __request_http(self, methods, path, query={}, header={}, body=None):
        protocol = ""
        if self.ssl_enable:
            protocol = "https"
        else:
            protocol = "http"

        rest_url = "{0}://{1}:{2}".format(
            protocol, self.server_host, str(self.server_port))
        rest_url = parse.urljoin(rest_url, path)

        if len(self.jwt_token):
            header["Authorization"] = "Bearer " + self.jwt_token

        if methods is Method.GET:
            return requests.get(url=rest_url, params=query, headers=header, verify=False)
        elif methods is Method.POST:
            return requests.post(url=rest_url, params=query, headers=header, json=body, verify=False)
        elif methods is Method.DELETE:
            return requests.delete(url=rest_url, param=query)
        elif methods is Method.PUT:
            return requests.put(url=rest_url, params=query, headers=header, json=body, verify=False)
        else:
            raise Exception("Invalid http method", methods)
