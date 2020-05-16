[![language.badge]][language.url] [![standard.badge]][standard.url] [![release.badge]][release.url]

[Web UI for App Mesh](https://github.com/laoshanxi/app-mesh-ui)

# App Mesh

### Introduction
App Mesh is a Cloud Native Microservice management middleware to manage different types of microservice applications, the application can be local or microservice cluster level [microservice cluster level app](https://github.com/laoshanxi/app-mesh/blob/master/doc/CONSUL.md "microservice cluster level app") , each application can be a specific micro service, the app-mesh will make sure all defined applications running on-time with defined behavior. Provide REST APIs and command-line.

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/master/doc/diagram.png" width=600 height=400 align=center /></div>

Features  | Behavior
---|---
Basic applications | Long running <br> Short running <br> Periodic long running
Microservice application | ⚡️ [Consul micro-service cluster management](https://github.com/laoshanxi/app-mesh/blob/master/doc/CONSUL.md) 
Application behavior | Application support initial and cleanup command <br> Application can define available time range in a day <br> Application can define environment variables <br> Application can define health check command <br> Application can define resource (memory & CPU) limitation (cgroup on Linux) <br> Docker container app support
Security |  SSL support (ECDH and secure ciphers) <br> ⚡️ [JWT authentication](https://github.com/laoshanxi/app-mesh/blob/master/doc/JWT_DESC.md) <br> ⚡️ [Role based permission control](https://github.com/laoshanxi/app-mesh/blob/master/doc/USER_ROLE_DESC.md)
Cloud native | ⚡️ [Provide Prometheus Exporter](https://github.com/laoshanxi/app-mesh/blob/master/doc/PROMETHEUS.md) <br> REST service with IPv6 support
Extra Features | Collect host/app resource usage <br> Remote run shell commands <br> Download/Upload files <br> Hot-update support `systemctl reload appmesh` <br> Bash completion <br> Reverse proxy <br> Web GUI

### How to install
**CentOS**:
```text
# centos7
yum install -y appmesh-1.8.1-1.x86_64.rpm

# centos8
rpm -ivh appmesh-1.8.1-1.x86_64.rpm --force
```
Note:
1. On windows WSL ubuntu, use `service appmesh start` to force service start, WSL VM does not have full init.d and systemd
2. Use env `export APPMGR_FRESH_INSTALL=Y` to enable fresh installation (otherwise, SSL and configuration file will not be refreshed)

### Command lines

```text
$ appc
Commands:
  logon       Log on to App Mesh for a specific time period.
  logoff      End a App Mesh user session
  view        List application[s]
  resource    Display host resource usage
  label       Manage host labels
  enable      Enable a application
  disable     Disable a application
  restart     Restart a application
  reg         Add a new application
  unreg       Remove an application
  run         Run application and get output
  get         Download remote file to local
  put         Upload file to server
  config      Manage basic configurations
  passwd      Change user password
  lock        Lock unlock a user
  log         Set log level

Run 'appc COMMAND --help' for more information on a command.
Use '-b $hostname','--port $port' to run remote command.

Usage:  appc [COMMAND] [ARG...] [flags]
```
---
## 1. App Management

- List application[s]

```text
$ appc view
id name        user  status   health pid    memory  return last_start_time     command
1  ipmail      root  enabled  0       -      -       -     2020-01-17 14:58:50 sh /opt/qqmail/launch.sh
2  test        root  enabled  0       -      -       -     2020-01-17 15:01:00 /usr/bin/env

```
- View application output
```text
$ appc reg -n ping -c 'ping www.baidu.com' -o 10
{
        "cache_lines" : 10,
        "command" : "ping www.baidu.com",
        "name" : "ping",
        "status" : 1,
        "user" : "root"
}

$ appc view
id name        user  status   return pid    memory  start_time          command_line
1  ping        root  enabled  0      14001  2 M     2019-09-19 20:17:50 ping www.baidu.com
$ appc view -n ping -o
PING www.a.shifen.com (14.215.177.38) 56(84) bytes of data.
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=1 ttl=54 time=35.5 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=2 ttl=54 time=35.5 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=3 ttl=54 time=37.4 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=4 ttl=54 time=35.7 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=5 ttl=54 time=36.5 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=6 ttl=54 time=42.6 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=7 ttl=54 time=40.6 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=8 ttl=54 time=39.7 ms
64 bytes from 14.215.177.38 (14.215.177.38): icmp_seq=9 ttl=54 time=36.8 ms
```

- Register a new application

```text
$ appc reg
Register a new application:
  -b [ --host ] arg (=localhost) host name or ip address
  -B [ --port ] arg              port number
  -u [ --user ] arg              Specifies the name of the user to connect to 
                                 App Mesh for this command.
  -x [ --password ] arg          Specifies the user password to connect to 
                                 App Mesh for this command.
  -n [ --name ] arg              application name
  -g [ --metadata ] arg          application metadata string
  -a [ --appuser ] arg           application process running OS user name
  -c [ --cmd ] arg               full command line with arguments
  -I [ --init ] arg              initial command line with arguments
  -F [ --fini ] arg              fini command line with arguments
  -l [ --health_check ] arg      health check script command (e.g., sh -x 'curl
                                 host:port/health', return 0 is health)
  -d [ --docker_image ] arg      docker image which used to run command line 
                                 (this will enable docker)
  -w [ --workdir ] arg           working directory (default /tmp)
  -S [ --stdout ] arg            stdout file
  -s [ --status ] arg (=1)       application status status (start is true, stop
                                 is false)
  -t [ --start_time ] arg        start date time for app (e.g., '2018-01-01 
                                 09:00:00')
  -E [ --end_time ] arg          end date time for app (e.g., '2018-01-01 
                                 09:00:00')
  -j [ --daily_start ] arg       daily start time (e.g., '09:00:00')
  -y [ --daily_end ] arg         daily end time (e.g., '20:00:00')
  -m [ --memory ] arg            memory limit in MByte
  -p [ --pid ] arg               process id used to attach
  -v [ --virtual_memory ] arg    virtual memory limit in MByte
  -r [ --cpu_shares ] arg        CPU shares (relative weight)
  -e [ --env ] arg               environment variables (e.g., -e env1=value1 -e
                                 env2=value2, APP_DOCKER_OPTS is used to input 
                                 docker parameters)
  -i [ --interval ] arg          start interval seconds for short running app
  -q [ --extra_time ] arg        extra timeout for short running app,the value 
                                 must less than interval  (default 0)
  -z [ --timezone ] arg          posix timezone for the application, reflect 
                                 [start_time|daily_start|daily_end] (e.g., 
                                 'WST+08:00' is Australia Standard Time)
  -k [ --keep_running ] arg (=0) monitor and keep running for short running app
                                 in start interval
  -o [ --cache_lines ] arg (=0)  number of output lines will be cached in 
                                 server side (used for none-container app)
  -f [ --force ]                 force without confirm
  -h [ --help ]                  Prints command usage to stdout and exits

# register a app with a native command
$ appc reg -n ping -u kfc -c 'ping www.google.com' -w /opt
Application already exist, are you sure you want to update the application (y/n)?
y
{
   "status" : 1,
   "command" : "ping www.google.com",
   "name" : "ping",
   "pid" : -1,
   "return" : 0,
   "user" : "kfc",
   "working_dir" : "/opt"
}

# register a docker container app
$ appc reg -n mydocker -c 'sleep 30' -d ubuntu
{
        "command" : "sleep 30",
        "docker_image" : "ubuntu",
        "name" : "mydocker",
        "status" : 1,
        "user" : "root"
}

$ appc view
id name        user  status   return pid    memory  start_time          command_line
1  sleep       root  enabled  0      4206   356 K   2019-09-20 09:36:08 /bin/sleep 60
2  mydocker    root  enabled  0      4346   388 K   2019-09-20 09:36:33 sleep 30

$ docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
965fcec657b9        ubuntu              "sleep 30"          5 seconds ago       Up 3 seconds                            app-mgr-2-ubuntu
```

- Remove an application
```text
appc unreg -n ping
Are you sure you want to remove the application (y/n)?
y
Success
```

- Enable/Disable an application
```text
$ appc enable -n ping
$ appc disable -n ping
$ appc restart -n ping
```

---
## 2. Resource Management

- Display host resource usage

<details>
<summary>appc resource</summary>

```text
$ appc resource
{
        "cpu_cores" : 2,
        "cpu_processors" : 2,
        "cpu_sockets" : 1,
        "fs" : 
        [
                {
                        "device" : "/dev/mapper/centos-root",
                        "mount_point" : "/",
                        "size" : 10504634368,
                        "usage" : 0.62867853488720304,
                        "used" : 6604038144
                },
                {
                        "device" : "/dev/sda1",
                        "mount_point" : "/boot",
                        "size" : 1063256064,
                        "usage" : 0.13290110330374755,
                        "used" : 141307904
                },
                {
                        "device" : "/dev/mapper/centos-root",
                        "mount_point" : "/var/lib/docker/containers",
                        "size" : 10504634368,
                        "usage" : 0.62867853488720304,
                        "used" : 6604038144
                },
                {
                        "device" : "/dev/mapper/centos-root",
                        "mount_point" : "/var/lib/docker/overlay2",
                        "size" : 10504634368,
                        "usage" : 0.62867853488720304,
                        "used" : 6604038144
                }
        ],
        "host_name" : "centos1",
        "load" : 
        {
                "15min" : 0.059999999999999998,
                "1min" : 0.070000000000000007,
                "5min" : 0.070000000000000007
        },
        "mem_applications" : 9850880,
        "mem_freeSwap_bytes" : 1287647232,
        "mem_free_bytes" : 3260231680,
        "mem_totalSwap_bytes" : 1287647232,
        "mem_total_bytes" : 4142419968,
        "net" : 
        [
                {
                        "address" : "192.168.2.7",
                        "ipv4" : true,
                        "name" : "enp0s3"
                },
                {
                        "address" : "10.0.3.15",
                        "ipv4" : true,
                        "name" : "enp0s8"
                },
                {
                        "address" : "172.17.0.1",
                        "ipv4" : true,
                        "name" : "docker0"
                },
                {
                        "address" : "fe80::982a:da64:68ec:a6e0",
                        "ipv4" : false,
                        "name" : "enp0s3"
                },
                {
                        "address" : "fe80::a817:69be:f5e9:e667",
                        "ipv4" : false,
                        "name" : "enp0s8"
                }
        ],
        "systime" : "2019-09-12 11:41:38"
}

```
</details>


- View application resource (application process tree memory usage)

```text
$ appc view -n ping
{
        "command" : "/bin/sleep 60",
        "last_start_time" : 1568893521,
        "memory" : 626688,
        "name" : "ping",
        "pid" : 8426,
        "return" : 0,
        "status" : 1,
        "user" : "root"
}
```

---
## 3. Remote command and application output (with session login)

- Run remote application and get stdout
```text
$ appc run -n ping -t 5
PING www.a.shifen.com (220.181.112.244) 56(84) bytes of data.
64 bytes from 220.181.112.244: icmp_seq=1 ttl=55 time=20.0 ms
64 bytes from 220.181.112.244: icmp_seq=2 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=3 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=4 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=5 ttl=55 time=20.1 ms
```

- Run a shell command and get stdout
```text
$ appc run -c 'su -l -c "appc view"'
id name        user  status   health pid    memory  return last_start_time     command
1  appweb      root  enabled  0      3195   3 Mi    -      -                   
2  myapp       root  enabled  0      20163  356 Ki  0      2020-03-26 19:46:30 sleep 30
3  78d92c24-6* root  N/A      0      20181  3.4 Mi  -      2020-03-26 19:46:46 su -l -c "appc view"
```


---
## 4. File Management

- Download a file from server
```text
$ # appc get -r /opt/appmesh/log/appsvc.log -l ./1.log
file <./1.log> size <10.4 M>
```

- Upload a local file to server
```text
$ # appc put -r /opt/appmesh/log/appsvc.log -l ./1.log
Success
```

---
## 5. Label Management
- Manage labels
```text
# list label
$ appc label
arch=x86_64
os_version=centos7.6

# remove label
$ appc label -r -t arch
os_version=centos7.6

# add label
$ appc label --add --label mytag=abc
mytag=abc
os_version=centos7.6
```

---
### Usage scenarios
1. Integrate rpm installation script and register rpm startup command to app mesh automaticlly
2. Remote async shell execute (can build-up web ssh)
3. Host/app resource monitor
4. Can be a standalone JWT server
5. File server
6. Microservice management

---

### Development

- Application state machine
<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/master/doc/state_machine.jpg" width=400 height=400 align=center /></div>

- REST APIs

Method | URI | Body/Headers | Desc
---|---|---|---
POST| /appmgr/login | username=base64(uname) <br> password=base64(passwd) <br> Optional: <br> expire_seconds=600 | JWT authenticate login
POST| /appmgr/auth | curl -X POST -k -H "Authorization:Bearer ZWrrpKI" https://127.0.0.1:6060/appmgr/auth <br> Optional: <br> auth_permission=permission_id | JWT token authenticate
GET | /appmgr/app/$app-name | | Get an application infomation
GET | /appmgr/app/$app-name/health | | Get application health status, no authentication required, 0 is health and 1 is unhealth
GET | /appmgr/app/$app-name/output?keep_history=1 | | Get app output (app should define cache_lines)
POST| /appmgr/app/run?timeout=5?retention=8 | {"command": "/bin/sleep 60", "user": "root", "working_dir": "/tmp", "env": {} } | Remote run the defined application, return process_uuid and application name in body.
GET | /appmgr/app/$app-name/run/output?process_uuid=uuidabc | | Get the stdout and stderr for the remote run
POST| /appmgr/app/syncrun?timeout=5 | {"command": "/bin/sleep 60", "user": "root", "working_dir": "/tmp", "env": {} } | Remote run application and wait in REST server side, return output in body.
GET | /appmgr/applications | | Get all application infomation
GET | /appmgr/resources | | Get host resource usage
PUT | /appmgr/app/$app-name | {"command": "/bin/sleep 60", "name": "ping", "user": "root", "working_dir": "/tmp" } | Register a new application
POST| /appmgr/app/$app-name/enable | | Enable an application
POST| /appmgr/app/$app-name/disable | | Disable an application
DELETE| /appmgr/app/$app-name | | Unregister an application
GET | /appmgr/file/download | Header: <br> file_path=/opt/remote/filename | Download a file from REST server and grant permission
POST| /appmgr/file/upload | Header: <br> file_path=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission
GET | /appmgr/labels | { "os": "linux","arch": "x86_64" } | Get labels
POST| /appmgr/labels | { "os": "linux","arch": "x86_64" } | Update labels
PUT | /appmgr/label/abc?value=123 |  | Set a label
DELETE| /appmgr/label/abc |  | Delete a label
POST| /appmgr/loglevel?level=DEBUG | level=DEBUG/INFO/NOTICE/WARN/ERROR | Set log level
GET | /appmgr/config |  | Get basic configurations
POST| /appmgr/config |  | Set basic configurations
POST| /appmgr/user/admin/passwd | new_password=base64(passwd) | Change user password
POST| /appmgr/user/user/lock | | admin user to lock a user
POST| /appmgr/user/user/unlock | | admin user to unlock a user
PUT | /appmgr/user/usera | | Add usera to Users
DEL | /appmgr/user/usera | | Delete usera
GET | /appmgr/users | | Get user list
GET | /appmgr/roles | | Get role list
POST| /appmgr/role/roleA | | Update roleA with defined permissions
DELETE| /appmgr/role/roleA | | Delete roleA
GET | /appmgr/user/permissions |  | Get user self permissions, user token is required in header
GET | /appmgr/permissions |  | Get all permissions
GET | /appmgr/metrics | | Get Prometheus exporter metrics (this is not scrap url for prometheus server)

---
### 3rd party deependencies
- [C++11](http://www.cplusplus.com/articles/cpp11)
- [ACE](https://github.com/DOCGroup/ACE_TAO)
- [Microsoft/cpprestsdk](https://github.com/Microsoft/cpprestsdk)
- [boost](https://github.com/boostorg/boost)
- [log4cpp](http://log4cpp.sourceforge.net)
- [Thalhammer/jwt-cpp](https://thalhammer.it/projects/jwt_cpp)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)

---
- Setup build environment on CentOS/Ubuntu/Debian
```text
git clone https://github.com/laoshanxi/app-mesh.git
sudo sh app-mesh/autogen.sh
```
- Build App Mesh
```text
cd app-mesh
make
```
- Thread model
<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/master/doc/threadmodel.jpg" width=400 height=282 align=center /></div>



[language.url]:   https://isocpp.org/
[language.badge]: https://img.shields.io/badge/language-C++-blue.svg

[standard.url]:   https://en.wikipedia.org/wiki/C%2B%2B#Standardization
[standard.badge]: https://img.shields.io/badge/C%2B%2B-11%2F14%2F17-blue.svg

[release.url]:    https://github.com/laoshanxi/app-mesh/releases
[release.badge]:  https://img.shields.io/github/v/release/laoshanxi/app-mesh.svg
