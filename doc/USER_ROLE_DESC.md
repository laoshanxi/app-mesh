# User and Role

------

### What is supported:

> * App Mesh REST API have user permission control
> * App Mesh Command Line have user permission control
> * Each REST API have permission definition
> * Role list is configurable 
> * Each user can define a password and some roles
> * All the user/role/permission is defined in json file
> * user/role configuration support dynamic update by `systemctl reload appmesh`
> * User support metadata attributes for special usage
> * User have user group
> * App ownership permission can define group permission and other group permission

### What is **not** supported:
> * N/A

### User and Role configure json sample

```json
 "Security": {
    "Users": {
      "admin": {
        "key": "Admin123",
        "group": "admin",
        "locked": false,
        "roles": [
          "manage",
          "view",
          "usermgr"
        ]
      },
      "user": {
        "key": "User123",
        "group": "user",
        "locked": false,
        "roles": [
          "view",
          "manage"
        ]
      }
    },
    "Roles": {
      "manage": [
        "user-add",
        "app-control",
        "app-delete",
        "app-reg",
        "passwd-change",
        "config-set",
        "config-view",
        "user-delete",
        "file-download",
        "file-upload",
        "user-list",
        "label-delete",
        "label-set",
        "label-view",
        "user-lock",
        "permission-list",
        "role-delete",
        "role-set",
        "role-view",
        "app-run-async",
        "app-run-async-output",
        "app-run-sync",
        "user-unlock",
        "app-view-all",
        "app-view",
        "app-output-view",
        "host-resource-view"
      ],
      "usermgr": [
        "user-add",
        "passwd-change",
        "user-delete",
        "user-list",
        "user-lock",
        "permission-list",
        "role-delete",
        "role-set",
        "role-view",
        "user-unlock"
      ],
      "view": [
        "config-view",
        "label-view",
        "role-view",
        "app-view-all",
        "app-view",
        "app-output-view",
        "host-resource-view"
      ]
    }
  }
```

### Permission list

| REST method        |  PATH   |  Permission Key |
| :--------:   | -----  | ----  |
| GET     | /appmesh/app/app-name |   `view-app`     |
| GET     | /appmesh/app/app-name/output  |   `view-app-output`   |
| GET     | /appmesh/applications |   `view-all-app`     |
| GET     | /appmesh/resources |   `view-host-resource`     |
| PUT     | /appmesh/app/app-name |   `app-reg`     |
| POST    | /appmesh/app/appname/enable |   `app-control`     |
| POST    | /appmesh/app/appname/disable |   `app-control`     |
| DEL     | /appmesh/app/appname |   `app-delete`    |
| POST    | /appmesh/app/syncrun?timeout=5 | `run-app-sync`  |
| POST    | /appmesh/app/run?timeout=5 |   `run-app-async`  |
| GET     | /appmesh/app/app-name/run/output?process_uuid=uuidabc | `run-app-async-output`  |
| GET     | /appmesh/download | `file-download`  |
| POST    | /appmesh/upload | `file-upload`  |
| GET     | /appmesh/labels | `label-view`  |
| PUT     | /appmesh/label/abc?value=123  | `label-set`  |
| DEL     | /appmesh/label/abc | `label-delete`  |
| POST    | /appmesh/config | `config-view`  |
| GET     | /appmesh/config | `config-set`  |
| POST    | /appmesh/user/admin/passwd | `change-passwd`  |
| POST    | /appmesh/user/usera/lock | `lock-user`  |
| POST    | /appmesh/user/usera/unlock | `unlock-user`  |
| DEL     | /appmesh/user/usera | `delete-user`  |
| PUT     | /appmesh/user/usera | `add-user`  |
| GET     | /appmesh/users | `get-users`  |


### Command line authentication

 - Invalid authentication will stop command line

```shell
$ appc view
login failed : Incorrect user password
invalid token supplied
```
 - Use `appc logon` to authenticate from App Mesh

```shell
$ appc logon
User: admin
Password: *********
User <admin> logon to localhost success.

$ appc view
id name        user  status   return pid    memory  start_time          command
1  sleep       root  enabled  0      32646  812 K   2019-10-10 19:25:38 /bin/sleep 60
```

 - Use `appc logoff` to clear authentication infomation

```shell
$ appc logoff
User <admin> logoff from localhost success.

$ appc view
login failed : Incorrect user password
invalid token supplied
```

### REST API authentication

 - Get token from API  `/login`

```shell
$ curl -X POST -k https://127.0.0.1:6060/login -H "username:`echo -n admin | base64`" -H "password:`echo -n Admin123$ | base64`"
{"access_token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzA3MDc3NzYsImlhdCI6MTU3MDcwNzE3NiwiaXNzIjoiYXBwbWdyLWF1dGgwIiwibmFtZSI6ImFkbWluIn0.CF_jXy4IrGpl0HKvM8Vh_T7LsGTGO-K73OkRxQ-BFF8","expire_time":1570707176508714400,"profile":{"auth_time":1570707176508711100,"name":"admin"},"token_type":"Bearer"}
```

 - All other API should add token in header `Authorization:Bearer xxx`
 Use `POST` `/auth/$user-name` to verify token from above:
```shell
$ curl -X POST -k -i -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzA3MDc3NzYsImlhdCI6MTU3MDcwNzE3NiwiaXNzIjoiYXBwbWdyLWF1dGgwIiwibmFtZSI6ImFkbWluIn0.CF_jXy4IrGpl0HKvM8Vh_T7LsGTGO-K73OkRxQ-BFF8" https://127.0.0.1:6060/auth/admin
HTTP/1.1 200 OK
Content-Length: 7
Content-Type: text/plain; charset=utf-8
```