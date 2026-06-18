# App Mesh CLI Documentation

The App Mesh Command Line Interface (CLI) provides equivalent functionality to the Web GUI and SDK for managing applications, system resources.

## Basic Usage

```text
$ appm --help
App Mesh CLI

Usage: appm [OPTIONS] <COMMAND>

Commands:
  logon      Login to App Mesh
  logoff     Logout from App Mesh
  loginfo    Display current logged-in user
  add        Register a new application
  rm         Remove an application
  view       List applications
  enable     Enable applications
  disable    Disable applications
  restart    Restart applications (disable then enable)
  run        Run a command or application
  exec       Execute a single remote command
  shell      Interactive remote shell
  get        Download a remote file
  put        Upload a local file
  label      Manage host labels
  log        Set log level
  config     View server configuration
  resource   Show host resources
  passwd     Change user password
  lock       Lock or unlock a user
  user       Manage users
  mfa        Two-factor authentication management
  appmgpwd   Encrypt password (local utility)
  appmginit  Initialize admin password (root-only)
  workflow   Manage workflows
  help       Print this message or the help of the given subcommand(s)

Options:
  -H, --host-url <HOST_URL>      Server host URL (default: last used or wss://127.0.0.1:6058)
  -F, --forward-to <FORWARD_TO>  Forward request to target host
  -U, --user <USER>              Login username
  -X, --password <PASSWORD>      Login password
  -v, --verbose                  Enable debug logging
  -h, --help                     Print help
  -V, --version                  Print version

# Run 'appm <COMMAND> --help' for detailed command usage.
# Remote connection: -H <server_url> (e.g., -H https://127.0.0.1:6060).
```

---

## App management

- List applications

```text
$ appm ls
ID  NAME           OWNER STATUS   HEALTH PID     USER  MEMORY   %CPU RETURN AGE    DURATION STARTS COMMAND
1   pyexec         mesh  disabled -      -       -     -        -    -      7m34s  -        0      "python3 ../bin/py_exec.py"
2   ping           mesh  enabled  OK     4894    lv    13.5 Mi  0    9      7m34s  N/A      2      "ping -w 300 -c 300 github.com"
3   backup         admin enabled  -      -       -     -        -    -      7m34s  -        0      "mkdir -p /opt/appmesh/work/backup\ncd /*"
```

- Register a New Application and View Output

```text
$ appm add -a ping -c 'ping github.com'
  behavior:
    exit: standby
  command: ping github.com
  name: ping
  owner: admin
  register_time: 1731748952
  register_time_TEXT: 2024-11-16T17:22:32+08
  status: 1
  stdout_cache_num: 3

$ appm ls -a ping
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


$ appm ls -a ping -o
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
$ appm add --help
Register a new application

Usage: appm add [OPTIONS]

Options:
  -a, --app <APP>                        Application name
  -c, --cmd <CMD>                        Command with arguments
  -d, --description <DESCRIPTION>        Application description
  -w, --working-dir <WORKING_DIR>        Working directory
  -s, --status <STATUS>                  Initial status [possible values: true, false]
  -u, --shell                            Enable shell mode
  -G, --session-login                    Execute with session login context
  -K, --health-check <HEALTH_CHECK>      Health check command
  -I, --docker-image <DOCKER_IMAGE>      Docker image
  -P, --pid <PID>                        Attach to existing process ID
  -b, --begin-time <BEGIN_TIME>          Start time (ISO 8601)
  -x, --end-time <END_TIME>              End time (ISO 8601)
  -S, --daily-begin <DAILY_BEGIN>        Daily start time (e.g., '09:00:00+08')
  -E, --daily-end <DAILY_END>            Daily end time (e.g., '20:00:00+08')
  -i, --interval <INTERVAL>              Start interval (ISO 8601 duration or cron expression)
  -Y, --cron                             Use cron expression for interval
  -M, --memory-limit <MEMORY_LIMIT>      Memory limit in MB
  -V, --virtual-memory <VIRTUAL_MEMORY>  Virtual memory limit in MB
  -C, --cpu-shares <CPU_SHARES>          CPU shares (relative weight)
  -N, --log-cache-size <LOG_CACHE_SIZE>  Number of stdout cache files
  -p, --permission <PERMISSION>          Permission bits
  -m, --metadata <METADATA>              Metadata (string/JSON, '@' prefix for file)
  -e, --env <ENV>                        Environment variables (repeatable: -e K=V)
  -z, --security-env <SECURITY_ENV>      Encrypted environment variables (repeatable: -z K=V)
  -R, --stop-timeout <STOP_TIMEOUT>      Process stop timeout (ISO 8601 duration)
  -Q, --exit <EXIT>                      Exit behavior: restart|standby|keepalive|remove
  -T, --control <CONTROL>                Exit code behavior (repeatable: --control CODE:ACTION)
  -D, --stdin <STDIN>                    Read YAML from stdin ('std') or file
  -H, --host-url <HOST_URL>              Server host URL
  -F, --forward-to <FORWARD_TO>          Forward request to target host
  -U, --user <USER>                      Login username
  -X, --password <PASSWORD>              Login password
  -f, --force                            Skip confirmation
  -v, --verbose                          Enable debug logging
  -h, --help                             Print help


# register a app with a native command
$ appm add -a ping -c 'ping www.google.com' -w /opt
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
$ appm add -a mydocker -c 'sleep 30' -I ubuntu
  behavior:
    exit: standby
  command: sleep 30
  docker_image: ubuntu
  name: mydocker
  owner: admin
  register_time: 1731749126
  register_time_TEXT: 2024-11-16T17:25:26+08
  status: 1

$ appm ls
ID  NAME           OWNER STATUS   HEALTH PID     USER  MEMORY   %CPU RETURN AGE    DURATION STARTS COMMAND
1   mydocker       admin enabled  OK     4593    root  24 Mi    0    -      6s     5s       1      "sleep 30"
2   ping           admin enabled  OK     4296    lv    2.8 Mi   0    -      1m9s   1m8s     1      "ping www.google.com"

$ docker ps
CONTAINER ID   IMAGE     COMMAND      CREATED         STATUS         PORTS     NAMES
b1277a31333f   ubuntu    "sleep 30"   9 seconds ago   Up 7 seconds             mydocker
```

- Remove an application

```text
appm rm -a ping
Are you sure you want to remove the application (y/n)?
y
Success
```

- Enable/Disable an application

```text
appm enable -a ping
appm disable -a ping
appm restart -a ping
```

---

## Resource management

- Display host resource usage

<details>
<summary>appm resource</summary>

```text
$ appm resource
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
$ appm ls -a ping -j
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
$ appm run -a ping -t 5
PING www.a.shifen.com (220.181.112.244) 56(84) bytes of data.
64 bytes from 220.181.112.244: icmp_seq=1 ttl=55 time=20.0 ms
64 bytes from 220.181.112.244: icmp_seq=2 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=3 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=4 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=5 ttl=55 time=20.1 ms
```

- Run a shell command and get stdout

```text
$ appm run -c 'su -l -c "appm ls"'
id name        user  status   health pid    memory  return last_start_time     command
1  appweb      root  enabled  0      3195   3 Mi    -      -
2  myapp       root  enabled  0      20163  356 Ki  0      2020-03-26 19:46:30 sleep 30
3  78d92c24-6* root  N/A      0      20181  3.4 Mi  -      2020-03-26 19:46:46 su -l -c "appm ls"
```

---

## File management

- Download a file from server

```text
$ # appm get -r /opt/appmesh/work/server.log -l ./1.log
file <./1.log> size <10.4 M>
```

- Upload a local file to server

```text
$ # appm put -r /opt/appmesh/work/server.log -l ./1.log
Success
```

---

## Label management

- Manage labels

```text
# list labels
$ appm label --view
arch=x86_64
os_version=centos7.6

# remove a label
$ appm label -d -l arch
os_version=centos7.6

# add a label
$ appm label -a -l mytag=abc
mytag=abc
os_version=centos7.6
```
