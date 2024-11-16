# App Mesh CLI Documentation

The App Mesh Command Line Interface (CLI) provides equivalent functionality to the Web GUI and SDK for managing applications, system resources.

## Basic Usage

```text
$ appc
App Mesh CLI - Command Line Interface
Usage: appc [COMMAND] [ARG...] [flags]

Authentication Commands:
  logon         Log in to App Mesh for a specified duration
  logoff        Clear current user session
  loginfo       Display current logged-in user
  passwd        Change user password
  lock          Lock or unlock a user
  user          View user information
  mfa           Manage two-factor authentication

Application Management:
  view          List all applications
  add           Add a new application
  rm            Remove an application
  enable        Enable an application
  disable       Disable an application
  restart       Restart an application

Execution Commands:
  run           Execute commands or applications and retrieve output
  shell         Execute commands with shell context emulation

System Management:
  resource      Show host resources
  label         Manage host labels
  config        Manage configurations
  log           Set log level

File Operations:
  get           Download a remote file
  put           Upload a local file to server

Additional Information:
  - Run 'appc COMMAND --help' for detailed command usage
  - Remote connection: Use '-b $server_url' (e.g., https://127.0.0.1:6060)
  - All commands support --help flag for detailed options
```

---

## App management

- List applications

```text
$ appc ls
ID  NAME           OWNER STATUS   HEALTH PID     USER  MEMORY   %CPU RETURN AGE    DURATION STARTS COMMAND
1   ping           mesh  enabled  -      -       -     -        -    2      6d     -        1      "ping github.com -w 300"
2   backup         admin disabled -      -       -     -        -    -      6d     -        0      "mkdir -p /opt/appmesh/work/backup\ncd /*"
4   start_app      -     enabled  OK     -       -     -        -    0      2m1s   -        1      "ls"
5   pyrun          mesh  disabled -      -       -     -        -    -      2m1s   -        0      "python3 /opt/appmesh/bin/py_exec.py"
```

- Register a New Application and View Output

```text
$ appc add -n ping -c 'ping github.com'
  behavior:
    exit: standby
  command: ping github.com
  name: ping
  owner: admin
  register_time: 1731748952
  register_time_TEXT: 2024-11-16T17:22:32+08
  status: 1
  stdout_cache_num: 3

$ appc ls -n ping
  behavior:
    control:
      0: standby
    exit: standby
  command: ping github.com -w 300
  description: appmesh ping test
  health: 1
  last_error: |
    2024-11-16T17:19:25+08 exited with return code: 2, msg:
  last_exit_time: 1731748765
  last_exit_time_TEXT: 2024-11-16T17:19:25+08
  last_start_time: 1731748765
  last_start_time_TEXT: 2024-11-16T17:19:25+08
  name: ping
  next_start_time: 1731748765
  next_start_time_TEXT: 2024-11-16T17:19:25+08
  owner: mesh
  permission: 33
  register_time: 1731202597
  register_time_TEXT: 2024-11-10T09:36:37+08
  return_code: 2
  starts: 1
  status: 1
  stdout_cache_size: 1


$ appc ls -n ping -o
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
  -b [ --url ] arg (=https://localhost:6060) Server URL
  -z [ --forward ] arg                       Target host (or with port) for request forwarding
  -u [ --user ] arg                          User name
  -x [ --password ] arg                      User password
  -V [ --verbose ]                           Enable verbose output
  -n [ --name ] arg                          Application name (required)
  -a [ --desc ] arg                          Application description
  -g [ --metadata ] arg                      Metadata string/JSON (stdin input, '@' for file input)
  --perm arg                                 Permission bits [group & other] (1=deny, 2=read, 3=write)
  -c [ --cmd ] arg                           Command line with arguments (required)
  -S [ --shell ]                             Enable shell mode for multiple commands
  --session_login                            Execute with session login context
  -l [ --health_check ] arg                  Health check command (returns 0 for healthy)
  -d [ --docker_image ] arg                  Docker image for containerized execution
  -w [ --workdir ] arg                       Working directory path
  -s [ --status ] arg (=1)                   Initial status (true=enabled, false=disabled)
  -t [ --start_time ] arg                    Start time (ISO8601: '2020-10-11T09:22:05')
  -E [ --end_time ] arg                      End time (ISO8601: '2020-10-11T10:22:05')
  -j [ --daily_start ] arg                   Daily start time ('09:00:00+08')
  -y [ --daily_end ] arg                     Daily end time ('20:00:00+08')
  -m [ --memory ] arg                        Memory limit (MB)
  -v [ --virtual_memory ] arg                Virtual memory limit (MB)
  -r [ --cpu_shares ] arg                    CPU shares (relative weight)
  -p [ --pid ] arg                           Attach to existing process ID
  -O [ --stdout_cache_num ] arg (=3)         Number of stdout cache files
  -e [ --env ] arg                           Environment variables (-e env1=value1 -e env2=value2, APP_DOCKER_OPTS env is used to
                                             input docker run parameters)
  --sec_env arg                              Encrypted environment variables in server side with application owner's cipher
  -i [ --interval ] arg                      Start interval (ISO8601 duration or cron: 'P1Y2M3DT4H5M6S', '* */5 * * * *')
  --cron                                     Use cron expression for interval
  -q [ --retention ] arg                     Process stop timeout (ISO8601 duration: 'P1Y2M3DT4H5M6S')
  --exit arg (=standby)                      Exit behavior [restart|standby|keepalive|remove]
  --control arg                              Exit code behaviors (--control CODE:ACTION, overrides default exit)
  -f [ --force ]                             Skip confirmation prompts
  --stdin arg                                Read YAML from stdin ('std') or file
  -h [ --help ]                              Display command usage and exit


# register a app with a native command
$ appc add -n ping -u kfc -c 'ping www.google.com' -w /opt
  Application already exist, are you sure you want to update the application (y/n)?
  [y/n]:y
  behavior:
    exit: standby
  command: ping www.google.com
  name: ping
  owner: admin
  register_time: 1731749063
  register_time_TEXT: 2024-11-16T17:24:23+08
  status: 1
  stdout_cache_num: 3
  working_dir: /opt

# register a docker container app
$ appc add -n mydocker -c 'sleep 30' -d ubuntu
  behavior:
    exit: standby
  command: sleep 30
  docker_image: ubuntu
  name: mydocker
  owner: admin
  register_time: 1731749126
  register_time_TEXT: 2024-11-16T17:25:26+08
  status: 1

$ appc ls
ID  NAME           OWNER STATUS   HEALTH PID     USER  MEMORY   %CPU RETURN AGE    DURATION STARTS COMMAND
1   mydocker       admin enabled  OK     4593    root  24 Mi    0    -      6s     5s       1      "sleep 30"
2   ping           admin enabled  OK     4296    lv    2.8 Mi   0    -      1m9s   1m8s     1      "ping www.google.com"

$ docker ps
CONTAINER ID   IMAGE     COMMAND      CREATED         STATUS         PORTS     NAMES
b1277a31333f   ubuntu    "sleep 30"   9 seconds ago   Up 7 seconds             mydocker
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

## Cloud management

- Join Consul Cluster

```text
# appc join
Join App Mesh cluster:
  -b [ --url ] arg (=https://localhost:6060) Server URL.
  -z [ --forward ] arg                       Target host name (or with port) for request forwarding.
  -u [ --user ] arg                          User name for App Mesh connection.
  -x [ --password ] arg                      User password for App Mesh connection.
  -V [ --verbose ]                           Enable verbose output.
  -c [ --consul ] arg                        Consul URL (e.g., http://localhost:8500).
  -m [ --main ]                              Join as main node.
  -w [ --worker ]                            Join as worker node.
  -r [ --proxy ] arg                         App Mesh proxy URL.
  -u [ --user ] arg                          Basic auth user name for Consul REST.
  -p [ --pass ] arg                          Basic auth user password for Consul REST.
  -l [ --ttl ] arg (=30)                     Consul session TTL in seconds.
  -s [ --security ]                          Enable Consul security (security persist will use Consul storage).
  -h [ --help ]                              Display command usage and exit.

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

- Cloud Applications

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

## Resource management

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

- View application resource (application process tree memory usage) with json or yaml format

```text
$ appc ls -n ping --json
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

## Remote run command and view output

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
$ appc run -c 'su -l -c "appc ls"'
id name        user  status   health pid    memory  return last_start_time     command
1  appweb      root  enabled  0      3195   3 Mi    -      -
2  myapp       root  enabled  0      20163  356 Ki  0      2020-03-26 19:46:30 sleep 30
3  78d92c24-6* root  N/A      0      20181  3.4 Mi  -      2020-03-26 19:46:46 su -l -c "appc ls"
```

---

## File management

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

## Label management

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
