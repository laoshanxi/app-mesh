## Development

- Application state machine
<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/state_machine.jpg" width=400 height=400 align=center /></div>

- REST APIs

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /appmesh/login | UserName=base64(uname) <br> Password=base64(passwd) <br> Optional: <br> ExpireSeconds=600 | JWT authenticate login
POST| /appmesh/auth | curl -X POST -k -H "Authorization:Bearer ZWrrpKI" https://127.0.0.1:6060/appmesh/auth <br> Optional: <br> AuthPermission=permission_id | JWT token authenticate
GET | /appmesh/app/$app-name | | Get an application information
GET | /appmesh/app/$app-name/health | | Get application health status, no authentication required, 0 is health and 1 is unhealthy
GET | /appmesh/app/$app-name/output?keep_history=1 | | Get app output (app should define cache_lines)
GET | /appmesh/app/$app-name/output/2 | | Get app output with cached index
POST| /appmesh/app/run?timeout=5?retention=8 | {"command": "/bin/sleep 60", "working_dir": "/tmp", "env": {} } | Remote run the defined application, return process_uuid and application name in body.
GET | /appmesh/app/$app-name/run/output?process_uuid=uuidabc | | Get the stdout and stderr for the remote run
POST| /appmesh/app/syncrun?timeout=5 | {"command": "/bin/sleep 60", "working_dir": "/tmp", "env": {} } | Remote run application and wait in REST server side, return output in body.
GET | /appmesh/applications | | Get all application information
GET | /appmesh/resources | | Get host resource usage
PUT | /appmesh/app/$app-name | {"command": "/bin/sleep 60", "name": "ping", "exec_user": "root", "working_dir": "/tmp" } | Register a new application
POST| /appmesh/app/$app-name/enable | | Enable an application
POST| /appmesh/app/$app-name/disable | | Disable an application
DELETE| /appmesh/app/$app-name | | Deregister an application
GET | /appmesh/cloud/applications | | Get cloud applications
GET | /appmesh/file/download | Header: <br> FilePath=/opt/remote/filename | Download a file from REST server and grant permission
POST| /appmesh/file/upload | Header: <br> FilePath=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission
GET | /appmesh/labels | { "os": "linux","arch": "x86_64" } | Get labels
POST| /appmesh/labels | { "os": "linux","arch": "x86_64" } | Update labels
PUT | /appmesh/label/abc?value=123 |  | Set a label
DELETE| /appmesh/label/abc |  | Delete a label
POST| /appmesh/loglevel?level=DEBUG | level=DEBUG/INFO/NOTICE/WARN/ERROR | Set log level
GET | /appmesh/config |  | Get basic configurations
POST| /appmesh/config |  | Set basic configurations
POST| /appmesh/user/admin/passwd | NewPassword=base64(passwd) | Change user password
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
GET | /appmesh/metrics | | Get Prometheus exporter metrics (this is not scrap url for prometheus server)

- How to build App Mesh

See document [Build App Mesh guidance](https://github.com/laoshanxi/app-mesh/blob/main/docs/source/Build.md).

- valgrind memory test

App Mesh can test memory issue by valgrind to find potential memory leaks. build `/opt/appmesh/appsvc` binary with debug mode `cmake -DCMAKE_BUILD_TYPE=Debug ..`, use `touch /opt/appmesh/appsvc.valgrind` to enable and restart `/opt/appmesh/appsvc` to run some cases, use `touch /opt/appmesh/appsvc.valgrind.stop` to finish memory test and check memory report in dir `/opt/appmesh/`.

- Thread model
<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/threadmodel.jpg" width=400 height=282 align=center /></div>
