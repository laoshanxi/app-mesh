# Development

![block-diagram](https://github.com/laoshanxi/app-mesh/raw/main/docs/source/block_diagram.png)

## REST APIs

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /appmesh/login | Username=base64(USER-NAME) <br> Password=base64(PASSWD) <br> Optional: <br> Expire-Seconds=600 | JWT authenticate login, get JWT token
POST| /appmesh/auth | curl -X POST -k -H "Authorization:Bearer ${MY-JWT-TOKEN}" https://127.0.0.1:6060/appmesh/auth <br> Optional: <br> Auth-Permission=${PERMISSION-ID} | JWT token and permission authenticate
-|-|-|-
GET | /appmesh/app/${APP-NAME} | | Get an application information
GET | /appmesh/app/${APP-NAME}/health | | Get application health status, no authentication required, 0 is health and 1 is unhealthy
GET | /appmesh/app/${APP-NAME}/output?stdout_position=128&stdout_index=0&process_uuid=uuidabc&stdout_maxsize=1024 | | Get app output <br> Optional: <br> stdout_position is the position value return by header 'Output-Position' <br> stdout_index to identify the process start index <br> process_uuid used to explicit lock a process
POST| /appmesh/app/syncrun?timeout=5 | {"command": "/bin/sleep 60", "working_dir": "/tmp", "env": {} } | Remote run application and wait in REST server side, return output in body.
POST| /appmesh/app/run?timeout=5 | {"command": "/bin/sleep 60", "working_dir": "/tmp", "env": {} } | Remote run the defined application, return process_uuid and application name in body.
GET | /appmesh/applications | | Get all application information
PUT | /appmesh/app/${APP-NAME} | {"command": "/bin/sleep 60", "name": "ping", "exec_user": "root", "working_dir": "/tmp" } | Register a new application
POST| /appmesh/app/${APP-NAME}/enable | | Enable an application
POST| /appmesh/app/${APP-NAME}/disable | | Disable an application
DELETE| /appmesh/app/${APP-NAME} | | Deregister an application
-|-|-|-
GET | /appmesh/cloud/applications | | Get cloud applications
GET | /appmesh/cloud/app/${APP-NAME} | | Get a cloud application
GET | /appmesh/cloud/app/${APP-NAME}/output/${HOST-NAME} | | View cloud application output through master
PUT | /appmesh/cloud/app/${APP-NAME} | Body: <br> cloud application definition | Add cloud application
DEL | /appmesh/cloud/app/${APP-NAME} | | Delete cloud application
GET | /appmesh/cloud/nodes | | Get cloud node list
-|-|-|-
GET | /appmesh/file/download | Header: <br> File-Path=/opt/remote/filename | Download a file from REST server and grant permission
POST| /appmesh/file/upload | Header: <br> File-Path=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission
-|-|-|-
GET | /appmesh/labels | { "os": "linux","arch": "x86_64" } | Get labels
POST| /appmesh/labels | { "os": "linux","arch": "x86_64" } | Update labels
PUT | /appmesh/label/abc?value=123 |  | Set a label
DELETE| /appmesh/label/abc |  | Delete a label
-|-|-|-
GET | /appmesh/config |  | Get basic configurations
POST| /appmesh/config |  | Set basic configurations
-|-|-|-
POST| /appmesh/user/admin/passwd | New-Password=base64(passwd) | Change user password
POST| /appmesh/user/user/lock | | admin user to lock a user
POST| /appmesh/user/user/unlock | | admin user to unlock a user
PUT | /appmesh/user/usera | | Add usera to Users
DEL | /appmesh/user/usera | | Delete usera
GET | /appmesh/users | | Get user list
GET | /appmesh/roles | | Get role list
POST| /appmesh/role/roleA | | Update roleA with defined permissions
DELETE| /appmesh/role/roleA | | Delete roleA
GET | /appmesh/user/permissions |  | Get user self permissions, user token is required in header
GET | /appmesh/permissions |  | Get all permissions
GET | /appmesh/user/groups |  | Get all user groups
-|-|-|-
GET | /appmesh/metrics | | Get Prometheus exporter metrics (this is not scrap url for prometheus server)
GET | /appmesh/resources | | Get host resource usage

## How to build App Mesh

See document [Build App Mesh guidance](https://app-mesh.readthedocs.io/en/latest/Build.html).

## How to enable valgrind memory test

App Mesh can test memory issue by valgrind to find potential memory leaks. build `/opt/appmesh/bin/appsvc` binary with debug mode `cmake -DCMAKE_BUILD_TYPE=Debug ..`, use `touch /opt/appmesh/bin/appsvc.valgrind` to enable and restart `/opt/appmesh/bin/appsvc` to run some cases, use `touch /opt/appmesh/bin/appsvc.valgrind.stop` to finish memory test and check memory report in dir `/opt/appmesh/bin/`.

## Mind diagram

![mind-diagram](https://github.com/laoshanxi/app-mesh/raw/main/docs/source/mind.png)
