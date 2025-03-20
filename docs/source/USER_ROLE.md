# User and Role

User and Role design for App Mesh.

### Supported Features

* App Mesh REST API supports user permission control.
* App Mesh CLI (based on REST API) supports user permission control.
* Permission keys are defined for each REST API.
* Role list is configurable.
* Each user can define a password and roles.
* All user/role/permissions can be defined in a local YAML file or central Consul service.
* User/role configuration supports dynamic updates via `systemctl reload appmesh`, WebGUI, and CLI.
* Users support metadata attributes for extra usage.
* User groups are defined for users.
* App ownership permissions can define group permissions and other group permissions.

### Unsupported Features

* One user can only belong to one user group.

### User and Role Configuration JSON Sample

```json
{
  "Security": {
    "EncryptKey": false,
    "Roles": {
      "manage": [
        "app-control",
        "app-delete",
        "app-reg",
        "config-set",
        "file-download",
        "file-upload",
        "label-delete",
        "label-set"
      ],
      "usermgr": [
        "user-add",
        "passwd-change-self",
        "passwd-change-user",
        "user-delete",
        "user-lock",
        "role-delete",
        "role-set",
        "user-unlock"
      ],
      "shell": [
        "app-run-async",
        "app-run-sync"
      ],
      "view": [
        "config-view",
        "label-view",
        "role-view",
        "user-list",
        "permission-list",
        "app-view-all",
        "app-view",
        "app-output-view",
        "host-resource-view"
      ]
    },
    "Users": {
      "admin": {
        "key": "admin123",
        "group": "admin",
        "exec_user": "root",
        "locked": false,
        "roles": [
          "manage",
          "view",
          "shell",
          "usermgr"
        ]
      },
      "test": {
        "key": "test123",
        "group": "user",
        "exec_user": "appmesh",
        "locked": false,
        "roles": []
      },
      "mesh": {
        "key": "mesh123",
        "group": "user",
        "exec_user": "appmesh",
        "locked": false,
        "roles": [
          "view",
          "shell"
        ]
      }
    }
  }
}
```

### Permission List

| REST Method | PATH                           | Permission Key       |
| :---------: | ------------------------------ | -------------------- |
|     GET     | /appmesh/app/app-name          | `view-app`           |
|     GET     | /appmesh/app/app-name/output   | `view-app-output`    |
|     GET     | /appmesh/applications          | `view-all-app`       |
|     GET     | /appmesh/resources             | `view-host-resource` |
|     PUT     | /appmesh/app/app-name          | `app-reg`            |
|    POST     | /appmesh/app/app-name/enable   | `app-control`        |
|    POST     | /appmesh/app/app-name/disable  | `app-control`        |
|     DEL     | /appmesh/app/app-name          | `app-delete`         |
|    POST     | /appmesh/app/syncrun?timeout=5 | `run-app-sync`       |
|    POST     | /appmesh/app/run?timeout=5     | `run-app-async`      |
|     GET     | /appmesh/download              | `file-download`      |
|    POST     | /appmesh/upload                | `file-upload`        |
|     GET     | /appmesh/labels                | `label-view`         |
|     PUT     | /appmesh/label/abc?value=123   | `label-set`          |
|     DEL     | /appmesh/label/abc             | `label-delete`       |
|    POST     | /appmesh/config                | `config-view`        |
|     GET     | /appmesh/config                | `config-set`         |
|    POST     | /appmesh/user/admin/passwd     | `change-passwd`      |
|    POST     | /appmesh/user/usera/lock       | `lock-user`          |
|    POST     | /appmesh/user/usera/unlock     | `unlock-user`        |
|     DEL     | /appmesh/user/usera            | `delete-user`        |
|     PUT     | /appmesh/user/usera            | `add-user`           |
|    POST     | /appmesh/totp/secret           | `user-totp-active`   |
|    POST     | /appmesh/totp/setup            | `user-totp-active`   |
|    POST     | /appmesh/token/renew           | `user-token-renew`   |
|    POST     | /appmesh/totp/usera/disable    | `user-totp-disable`  |
|     GET     | /appmesh/users                 | `get-users`          |

### Command Line Authentication

* Invalid authentication will stop command line:

```shell
$ appc ls
login failed : Incorrect user password
invalid token supplied
```

* Use `appc logon` to authenticate from App Mesh:

```shell
$ appc logon
User: admin
Password: *********
User <admin> logon to localhost success.

$ appc ls
id name        user  status   return pid    memory  start_time          command
1  sleep       root  enabled  0      32646  812 K   2019-10-10 19:25:38 /bin/sleep 60
```

* Use `appc logoff` to clear authentication information:

```shell
$ appc logoff
User <admin> logoff from localhost success.

$ appc ls
login failed : Incorrect user password
invalid token supplied
```

### REST API Authentication

* Get token from API `/appmesh/login`:

```shell
$ curl -X POST -k https://127.0.0.1:6060/appmesh/login -H "Authorization:Basic `echo -n admin:admin123 | base64`"
{"Access-Token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzA3MDc3NzYsImlhdCI6MTU3MDcwNzE3NiwiaXNzIjoiYXBwbWdyLWF1dGgwIiwibmFtZSI6ImFkbWluIn0.CF_jXy4IrGpl0HKvM8Vh_T7LsGTGO-K73OkRxQ-BFF8","expire_time":1570707176508714400,"profile":{"auth_time":1570707176508711100,"name":"admin"},"token_type":"Bearer"}
```

* All other APIs should add the token in the header `Authorization:Bearer <JWT_TOKEN>`. Use `POST` `/appmesh/auth` to verify the token:

```shell
$ curl -X POST -k -i -H "Authorization:Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDE4MTM1NzQsImdyb3VwIjoiYWRtaW4iLCJpYXQiOjE2NDEyMDg3NzQsImlzcyI6ImFwcG1lc2gtYXV0aDAiLCJuYW1lIjoiYWRtaW4ifQ.BfiNR2JOk8lB_q3pwwfl8j3PlA3Jxhccrbq2cx-HHtE" https://127.0.0.1:6060/appmesh/auth
HTTP/1.1 200 OK
Content-Length: 7
Content-Type: text/plain; charset=utf-8
```

### Application Permission

Each application can define access permissions for other users (optional). By default, a registered application can be accessed by any user with the specific role permission. Application permission is different from role permission; it defines accessibility for users who did not register the application. The permission is a two-digit integer value:

* Unit Place: defines the same group users' permissions. 1=deny, 2=read, 3=write.
* Tenth Place: defines other group users' permissions. 1=deny, 2=read, 3=write.

For example, 11 indicates all other users cannot access this application, 21 indicates only same group users can read this application.
