# User and Role

------

### What is supported:

> * App Manager REST API have user permission control
> * App Manager Command Line have user permission control
> * Each REST API have permission definition
> * Role list is configurable 
> * Each user can define a password and some roles
> * All the user/role/permission is defined in json file
> * user/role configuration support dynamic update by `systemctl reload appmanager`

### What is **not** supported:
> * The application managed in App Manager have no user ownership
> * No data base introduced

### User and Role configure json sample

```json
 "Security": {
    "Users": {
      "admin": {
        "key": "Admin123",
        "roles": [ "manage", "view", "usermgr" ],
        "locked": false
      },
      "user": {
        "key": "password",
        "roles": [ "view" ],
        "locked": false
      },
      "test": {
        "key": "test",
        "roles": [],
        "locked": true
      }
    },
    "Roles": {
      "manage": [
        "app-reg",
        "app-control",
        "app-delete",
        "run-app-async",
        "run-app-sync",
        "file-download",
        "file-upload",
        "label-view",
        "label-set",
        "label-delete",
        "config-set",
        "passwd-change",
        "user-lock",
        "user-unlock"
      ],
      "view": [
        "app-view",
        "app-output-view",
        "app-view-all",
        "host-resource-view",
        "run-app-async-output",
        "label-view",
        "config-view",
		"user-list"
      ],
      "usermgr": [
        "user-add",
        "user-delete"
      ]
    }
  }
```

### Permission list

| REST method        |  PATH   |  Permission Key |
| :--------:   | -----  | ----  |
| GET     | /app/app-name |   `view-app`     |
| GET        |   /app/app-name/output  |   `view-app-output`   |
| GET     | /app-manager/applications |   `view-all-app`     |
| GET     | /app-manager/resources |   `view-host-resource`     |
| PUT     | /app/app-name |   `app-reg`     |
| POST     | /app/appname/enable |   `app-control`     |
| POST     | /app/appname/disable |   `app-control`     |
| DEL     | /app/appname |   `app-delete`    |
| POST     | /app/syncrun?timeout=5 | `run-app-sync`  |
| POST     | /app/run?timeout=5 |   `run-app-async`  |
| GET     | /app/app-name/run/output?process_uuid=uuidabc | `run-app-async-output`  |
| GET     | /download | `file-download`  |
| POST     | /upload | `file-upload`  |
| GET     | /labels | `label-view`  |
| PUT     | /label/abc?value=123  | `label-set`  |
| DEL     | /label/abc | `label-delete`  |
| POST    | /app-manager/config | `config-view`  |
| GET    | /app-manager/config | `config-set`  |
| POST    | /user/admin/passwd | `change-passwd`  |
| POST    | /user/usera/lock | `lock-user`  |
| POST    | /user/usera/unlock | `unlock-user`  |
| DEL    | /user/usera | `delete-user`  |
| PUT    | /user/usera | `add-user`  |
| GET    | /users | `get-users`  |


### Command line authentication

 - Invalid authentication will stop command line

```shell
$ appc view
login failed : Incorrect user password
invalid token supplied
```
 - Use `appc logon` to authenticate from App Manager

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