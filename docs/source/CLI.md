## Command lines
App Mesh command lines provide the same functionality with Web GUI for *stand-alone* mode, *Consul-cluster* mode related feature require Web GUI.

```text
$ appc
Commands:
  logon       Log on to App Mesh for a specific time period.
  logoff      Clear current login user infomation
  loginfo     Print current logon user

  view        List application[s]
  reg         Add a new application
  unreg       Remove an application
  enable      Enable a application
  disable     Disable a application
  restart     Restart a application

  run         Run command and get output
  exec        Run command by appmesh and impersonate context

  resource    Display host resources
  label       Manage host labels
  config      Manage basic configurations
  log         Set log level

  get         Download remote file to local
  put         Upload local file to App Mesh server

  passwd      Change user password
  lock        Lock unlock a user

Run 'appc COMMAND --help' for more information on a command.
Use '-b $hostname','-B $port' to run remote command.

Usage:  appc [COMMAND] [ARG...] [flags]
```
---
## 1. App Management

- List application[s]

```text
$ appc view
ID NAME        OWNER STATUS   HEALTH PID     MEMORY  CPU  RETURN LAST_START_TIME         COMMAND
1  qqmail      admin enabled  0      -       -       -    0      2020-12-26 19:55:38+08  sh /opt/qqmail/launch.sh
2  ssd         admin enabled  1      -       -       -    -      -                       /usr/sbin/fstrim -a -v
3  loki        admin enabled  0      1058    3 Mi    0%   -      -                       ping www.sina.com
4  ping        admin enabled  0      1059    2.9 Mi  0%   -      -                       ping www.baidu.com
5  docker            enabled  0      1853    2.5 Mi  0%   -      -                       ping www.sina.com
6  sec         admin enabled  0      30306   516 Ki  0%   -      2020-12-26 19:54:37+08  sleep 200

```
- View application output
```text
$ appc reg -n ping -c 'ping www.baidu.com'
{
	"command": "ping www.baidu.com",
	"name": "ping",
	"owner": "admin",
	"register_time": "2020-10-24 07:31:40+08",
	"status": 1
}

$ appc view -n ping
{
	"command": "ping www.baidu.com",
	"health": 0,
	"last_start_time": "2020-10-24 07:31:40+08",
	"memory": 3088384,
	"name": "ping",
	"owner": "admin",
	"pid": 4668,
	"register_time": "2020-10-24 07:31:40+08",
	"status": 1
}

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
  -u [ --user ] arg              Specifies the name of the user to connect to App Mesh for this 
                                 command.
  -x [ --password ] arg          Specifies the user password to connect to App Mesh for this 
                                 command.
  -n [ --name ] arg              application name
  -g [ --metadata ] arg          metadata string (input for application, pass to process stdin), 
                                 '@' allowed to read from file
  --perm arg                     application user permission, value is 2 bit integer: [group & 
                                 other], each bit can be deny:1, read:2, write: 3.
  -c [ --cmd ] arg               full command line with arguments
  -S [ --shell_mode ]            use shell mode, cmd can be more commands
  -I [ --init ] arg              initial command line with arguments
  -F [ --fini ] arg              fini command line with arguments
  -l [ --health_check ] arg      health check script command (e.g., sh -x 'curl host:port/health', 
                                 return 0 is health)
  -d [ --docker_image ] arg      docker image which used to run command line (for docker container 
                                 application)
  -w [ --workdir ] arg           working directory
  -s [ --status ] arg (=1)       initial application status (true is enable, false is disabled)
  -t [ --start_time ] arg        start date time for app (ISO8601 time format, e.g., 
                                 '2020-10-11T09:22:05')
  -E [ --end_time ] arg          end date time for app (ISO8601 time format, e.g., 
                                 '2020-10-11T10:22:05')
  -j [ --daily_start ] arg       daily start time (e.g., '09:00:00')
  -y [ --daily_end ] arg         daily end time (e.g., '20:00:00')
  -m [ --memory ] arg            memory limit in MByte
  -p [ --pid ] arg               process id used to attach
  -O [ --stdout_cache_num ] arg  stdout file cache number
  -v [ --virtual_memory ] arg    virtual memory limit in MByte
  -r [ --cpu_shares ] arg        CPU shares (relative weight)
  -e [ --env ] arg               environment variables (e.g., -e env1=value1 -e env2=value2, 
                                 APP_DOCKER_OPTS is used to input docker parameters)
  --sec_env arg                  security environment variables, encrypt in server side with 
                                 application owner's cipher
  -i [ --interval ] arg          start interval seconds for short running app, support ISO 8601 
                                 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W')
  -q [ --extra_time ] arg        extra timeout for short running app,the value must less than 
                                 interval  (default 0), support ISO 8601 durations (e.g., 
                                 'P1Y2M3DT4H5M6S' 'P5W')
  -z [ --timezone ] arg          posix timezone for the application, reflect 
                                 [start_time|daily_start|daily_end] (e.g., 'GMT+08:00' is Beijing 
                                 Time)
  -k [ --keep_running ]          monitor and keep running for short running app in start interval
  -f [ --force ]                 force without confirm
  --stdin                        accept json from stdin
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
   "working_dir" : "/opt"
}

# register a docker container app
$ appc reg -n mydocker -c 'sleep 30' -d ubuntu
{
        "command" : "sleep 30",
        "docker_image" : "ubuntu",
        "name" : "mydocker",
        "status" : 1
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
        "status" : 1
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
