## Command lines

App Mesh command lines provide the same functionality with Web GUI for *stand-alone* mode, *Consul-cluster* mode related feature require Web GUI.

```text
$ appc
Commands:
  logon       Log on to App Mesh for a specific time period.
  logoff      Clear current login user information
  loginfo     Print current logon user

  view        View application[s]
  add         Add a new application
  rm          Remove an application
  enable      Enable a application
  disable     Disable a application
  restart     Restart a application

  join        Join to a Consul cluster
  cloud       List cloud application[s]
  nodes       List cloud nodes

  run         Run commands or an existing application and get output
  exec        Run command by appmesh and impersonate current shell context

  resource    Display host resources
  label       Manage host labels
  config      Manage basic configurations
  log         Set log level

  get         Download remote file to local
  put         Upload local file to App Mesh server

  passwd      Change user password
  lock        Lock/Unlock a user
  user        View user
  mfa         Two-factor authentication

Run 'appc COMMAND --help' for more information on a command.
Use '-b $server_url' to connect remote. e.g https://127.0.0.1:6060

Usage:  appc [COMMAND] [ARG...] [flags]
```

---

### App management

- List application[s]

```text
$ appc view
ID NAME        OWNER STATUS   HEALTH PID     MEMORY   %CPU RETURN LAST_START_TIME         COMMAND
1  qqmail      admin enabled  0      -       -        -    0      2021-03-26 10:54:26+08  sh /opt/qqmail/launch.sh
2  ssd         admin enabled  1      -       -        -    -      -                       /usr/sbin/fstrim -a -v
3  loki        admin enabled  0      4789    3.1 Mi   0    2      2021-03-26 08:03:37+08  ping www.sina.com
4  ping        admin enabled  0      4790    3.1 Mi   0    2      2021-03-26 08:03:37+08  ping github.com
5  docker            enabled  0      2866    2.5 Mi   0    -      2021-03-26 08:03:28+08  ping www.sina.com
```

- View application output

```text
$ appc add -n ping -c 'ping github.com'
{
 "command": "ping github.com",
 "name": "ping",
 "owner": "admin",
 "register_time": "2020-10-24 07:31:40+08",
 "status": 1
}

$ appc view -n ping
{
  "command": "ping github.com",
  "cpu": 0,
  "fd": 5,
  "health": 0,
  "last_start_time": "2021-03-26 08:03:37+08",
  "memory": 3203072,
  "name": "ping",
  "owner": "admin",
  "pid": 4790,
  "register_time": "2020-10-24 07:31:40+08",
  "return_code": 2,
  "status": 1,
  "stdout_cache_num": 2
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
$ appc add
Register a new application:
  -b [ --url ] arg (=https://localhost:6060) server URL
  -u [ --user ] arg                          Specifies the name of the user to connect to App Mesh for this command.
  -x [ --password ] arg                      Specifies the user password to connect to App Mesh for this command.
  -V [ --verbose ]                           enable verbose output
  -n [ --name ] arg                          application name
  -a [ --desc ] arg                          application description
  -g [ --metadata ] arg                      metadata string/JSON (input for application, pass to process stdin), '@' allowed to
                                             read from file
  --perm arg                                 application user permission, value is 2 bit integer: [group & other], each bit can
                                             be deny:1, read:2, write: 3.
  -c [ --cmd ] arg                           full command line with arguments
  -S [ --shell ]                             use shell mode, cmd can be more shell commands with string format
  -l [ --health_check ] arg                  health check script command (e.g., sh -x 'curl host:port/health', return 0 is
                                             health)
  -d [ --docker_image ] arg                  docker image which used to run command line (for docker container application)
  -w [ --workdir ] arg                       working directory
  -s [ --status ] arg (=1)                   initial application status (true is enable, false is disabled)
  -t [ --start_time ] arg                    start date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05')
  -E [ --end_time ] arg                      end date time for app (ISO8601 time format, e.g., '2020-10-11T10:22:05')
  -j [ --daily_start ] arg                   daily start time (e.g., '09:00:00+08')
  -y [ --daily_end ] arg                     daily end time (e.g., '20:00:00+08')
  -m [ --memory ] arg                        memory limit in MByte
  -p [ --pid ] arg                           process id used to attach
  -O [ --stdout_cache_num ] arg (=3)         stdout file cache number
  -v [ --virtual_memory ] arg                virtual memory limit in MByte
  -r [ --cpu_shares ] arg                    CPU shares (relative weight)
  -e [ --env ] arg                           environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used
                                             to input docker run parameters)
  --sec_env arg                              security environment variables, encrypt in server side with application owner's
                                             cipher
  -i [ --interval ] arg                      start interval seconds for short running app, support ISO 8601 durations and cron
                                             expression (e.g., 'P1Y2M3DT4H5M6S' 'P5W' '* */5 * * * *')
  --cron                                     indicate interval parameter use cron expression
  -q [ --retention ] arg                     extra timeout seconds for stopping current process, support ISO 8601 durations
                                             (e.g., 'P1Y2M3DT4H5M6S' 'P5W').
  --exit arg (=standby)                      default exit behavior [restart,standby,keepalive,remove]
  --control arg                              exit code behavior (e.g, --control 0:restart --control 1:standby), higher priority
                                             than default exit behavior
  -f [ --force ]                             force without confirm
  --stdin arg                                accept json from stdin (provide 'std' string) or local json file path
  -h [ --help ]                              Prints command usage to stdout and exits


# register a app with a native command
$ appc add -n ping -u kfc -c 'ping www.google.com' -w /opt
Application already exist, are you sure you want to update the application (y/n)?
y
{
   "status" : 1,
   "command" : "ping www.google.com",
   "name" : "ping",
   "pid" : -1,
   "return_code" : 0,
   "working_dir" : "/opt"
}

# register a docker container app
$ appc add -n mydocker -c 'sleep 30' -d ubuntu
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
appc rm -n ping
Are you sure you want to remove the application (y/n)?
y
Success
```

- Enable/Disable an application

```text
appc enable -n ping
appc disable -n ping
appc restart -n ping
```

---

### Cloud management

- Join to Consul cluster

```text
# appc join
Join App Mesh cluster::
  -b [ --host ] arg (=localhost) host name or ip address
  -B [ --port ] arg              port number
  -u [ --user ] arg              Specifies the name of the user to connect to App Mesh for this command.
  -x [ --password ] arg          Specifies the user password to connect to App Mesh for this command.
  -c [ --consul ] arg            Consul url (e.g., http://localhost:8500)
  -m [ --main ]                  Join as main node
  -w [ --worker ]                Join as worker node
  -r [ --proxy ] arg             appmesh_proxy_url
  -u [ --user ] arg              Basic auth user name for Consul REST
  -p [ --pass ] arg              Basic auth user password for Consul REST
  -l [ --ttl ] arg (=30)         Consul session TTL seconds
  -s [ --security ]              Enable Consul security (security persist will use Consul storage)
  -h [ --help ]                  Prints command usage to stdout and exits

appc join -c http://127.0.0.1:8500 -l 30 -m -w
App Mesh will join cluster with parameter:
{
  "EnableConsulSecurity": false,
  "IsMainNode": true,
  "IsWorkerNode": true,
  "SessionTTL": 30,
  "Url": "http://127.0.0.1:8500"
}

```

- View cloud applications

```text
$ appc cloud
{
  "myapp": {
    "condition": {
      "arch": "x86_64",
      "os_version": "centos7.6"
    },
    "content": {
      "command": "sleep 30",
      "metadata": "cloud-app",
      "name": "myapp",
      "register_time": "2021-02-18 20:24:03+08",
      "shell": true,
      "status": 1
    },
    "port": 6666,
    "priority": 0,
    "replication": 1,
    "status": {
      "ubuntu-lsx": 0
    }
  }
}
```

---

### Resource management

- Display host resource usage

<details>
<summary>appc resource</summary>

```text
$ appc resource
{
  "appmesh_start_time": "2021-02-20 10:26:55+08",
  "cpu_cores": 6,
  "cpu_processors": 6,
  "cpu_sockets": 1,
  "fd": 17,
  "fs": [
    {
      "device": "/dev/sda2",
      "mount_point": "/",
      "size": 244529655808,
      "usage": 0.26739761823956576,
      "used": 65386647552
    },
    {
      "device": "/dev/sda1",
      "mount_point": "/boot/efi",
      "size": 535805952,
      "usage": 0.01525853897195976,
      "used": 8175616
    }
  ],
  "host_description": "ubuntu-OptiPlex-7070",
  "host_name": "ubuntu-lsx",
  "load": {
    "15min": 0.46999999999999997,
    "1min": 0.64000000000000001,
    "5min": 0.66000000000000003
  },
  "mem_applications": 17352934,
  "mem_freeSwap_bytes": 2147479552,
  "mem_free_bytes": 25269743616,
  "mem_totalSwap_bytes": 2147479552,
  "mem_total_bytes": 33477701632,
  "net": [
    {
      "address": "192.168.3.24",
      "ipv4": true,
      "name": "enp1s0"
    },
    {
      "address": "fe80::8b4a:81ce:7bf5:7431",
      "ipv4": false,
      "name": "enp1s0"
    }
  ],
  "pid": 21430,
  "systime": "2021-02-20 10:27:48+08"
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
        "return_code" : 0,
        "status" : 1
}
```

---

### Remote command and application output (with session login)

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

### File management

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

### Label management

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
