# Application Manager
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
![coverage](https://img.shields.io/badge/coverage-90%25-yellowgreen.svg?maxAge=2592000)
![version](https://img.shields.io/badge/version-1.1.0-blue.svg?maxAge=2592000)

## Introduction
Application Manager is a daemon application to manage different types of sub-applications(process), each application can be a specific jobs, the app-manager will make sure all defined applications running on-time with defined behavior. provide REST APIs for integrate with outside app, provide command-line to start/stop and register new app easily. Also can be a JWT server.

The internal timer is multi-threaded with high-precision that can be used to replace Linux cron-tab and supervisor.

<div align=center><img src="https://github.com/laoshanxi/app-manager/raw/master/doc/diagram.png" width=654 height=385 align=center /></div>


Supported applications  | Behavior
---|---
Long running application | Monitor app running all time and restart when exited immediately
Short runing application | Periodic startup app
Periodic long running application |Long running applicatin but will be restart periodic
Extra Features | Application can define avialable time range in a day <br> Application can define envionment variables <br> Application can define resource (memory & CPU) limitation (cgroup on Linux) <br> SSL support <br> Collect host/app resource usage <br> Remote run shell commands <br> JWT authentication


## Setup build environment on CentOS/Ubuntu/Debian
```
git clone https://github.com/laoshanxi/app-manager.git
sudo sh app-manager/autogen.sh
```
## Build
```
cd app-manager
make
```

## REST APIs

Method | URI | Desc
---|---|---
GET | /app/$app-name | Get an application infomation
GET | /app/$app-name/testrun?timeout=5 | Test run an application
GET | /app/$app-name/testrun/output?process_uuid=uuidabc | Get the stdout and stderr for the test run
GET | /app-manager/applications | Get all application infomation
GET | /app-manager/resources | Get host resource usage
GET | /app-manager/config | Get all the configuration
PUT | /app/$app-name | Register a new application
POST| /app/$app-name?action=start | Start an application
POST| /app/$app-name?action=stop | Stop an application
POST| /authenticate | JWT authenticate
DELETE| /app/$app-name | Unregister an application

## How to install
**CentOS**:
```
wget https://github.com/laoshanxi/app-manager/releases/download/v1.0/appmanager-1.0-1.x86_64.rpm
sudo yum install ./appmanager-1.0-1.x86_64.rpm -y
```
If you directly run command line from installation console, there will have issue on dependency libraries, you need source /opt/appmanager/script/app.bashrc to get the environment. for the new console will be OK, the source operation was automaticlly add to /etc/bashrc
```
$ appc view
appc: error while loading shared libraries: libcpprest.so.2.10: cannot open shared object file: No such file or directory

$ source /opt/appmanager/script/app.bashrc 

$ appc view
id name        user  status   pid    return memory  command_line
1  period      root  enabled  585    0      672 K   /bin/sleep 20
2  ping        root  enabled  586    0      956 K   ping www.baidu.com
```
**Ubuntu**:
```
$ apt install ./appmanager_1.1_amd64.deb -y
```

## Show all sub command

```
$ appc
Commands:
  view        List application[s]
  config      Display configurations
  resource    Display host resource usage
  start       Start a application
  stop        Stop a application
  restart     Restart a application
  reg         Add a new application
  unreg       Remove an application
  test        Test run an application and get output
  sh          Use shell run a command and get output

Run 'appc COMMAND --help' for more information on a command.
Use '-b hostname' to run remote command.

Usage:  appc [COMMAND] [ARG...] [flags]
```


## List application[s]

```
$ appc view
id name        user  status   pid    return memory  command_line
1  period      root  enabled  766    0      20 K    /bin/sleep 20
2  ping        root  enabled  586    0      956 K   ping www.baidu.com
$ appc view -n ping
id name        user  status   pid    return memory  command_line
1  ping        root  enabled  586    0      956 K   ping www.baidu.com
```

## Display host resource usage

```
$ appc resource
{
        "cpu_cores" : 4,
        "cpu_processors" : 4,
        "cpu_sockets" : 1,
        "host_name" : "DESKTOP-JMLV.localdomain",
        "mem_applications" : 10776576,
        "mem_freeSwap_bytes" : 18446743661357039616,
        "mem_free_bytes" : 21730828288,
        "mem_totalSwap_bytes" : 3307175280640,
        "mem_total_bytes" : 25665413120,
        "net" :
        [
                {
                        "address" : "192.168.2.99",
                        "ipv4" : true,
                        "name" : "eth0"
                },
                {
                        "address" : "fe80::60a8:40fb:4169:98f6",
                        "ipv4" : false,
                        "name" : "eth0"
                },
                {
                        "address" : "169.254.106.196",
                        "ipv4" : true,
                        "name" : "eth1"
                },
                {
                        "address" : "fe80::8179:f2dc:d972:6ac4",
                        "ipv4" : false,
                        "name" : "eth1"
                }
        ]
}
```

## Display configurations

```
$ appc config
{
        "Applications" :
        [
                {
                        "command_line" : "/bin/sleep 20",
                        "daily_limitation" :
                        {
                                "daily_end" : "23:00:00",
                                "daily_start" : "09:00:00"
                        },
                        "env" :
                        {
                                "TEST_ENV1" : "value",
                                "TEST_ENV2" : "value"
                        },
                        "keep_running" : true,
                        "memory" : 24576,
                        "name" : "period",
                        "pid" : 911,
                        "posix_timezone" : "CST+8:00:00",
                        "resource_limit" :
                        {
                                "cpu_shares" : 100,
                                "memory_mb" : 200,
                                "memory_virt_mb" : 300
                        },
                        "return" : 0,
                        "run_as" : "root",
                        "run_once" : false,
                        "start_interval_seconds" : 30,
                        "start_interval_timeout" : 0,
                        "start_time" : "2018-01-02 01:05:16",
                        "status" : 1,
                        "working_dir" : "/opt"
                },
                {
                        "command_line" : "ping www.baidu.com",
                        "memory" : 978944,
                        "name" : "ping",
                        "pid" : 586,
                        "return" : 0,
                        "run_as" : "root",
                        "run_once" : false,
                        "status" : 1,
                        "working_dir" : "/tmp"
                }
        ],
        "Description" : "myhost",
        "JWTEnabled" : true,
        "LogLevel" : "DEBUG",
        "RestListenPort" : 6060,
        "SSLCertificateFile" : "server.crt",
        "SSLCertificateKeyFile" : "server.key",
        "SSLEnabled" : true,
        "ScheduleIntervalSeconds" : 2
}
```

## Register a new application

```
$ appc reg
Register a new application:
  -b [ --host ] arg (=localhost) host name or ip address
  -n [ --name ] arg              application name
  -u [ --user ] arg (=root)      application process running user name
  -c [ --cmd ] arg               full command line with arguments
  -w [ --workdir ] arg (=/tmp)   working directory
  -a [ --status ] arg (=1)       application status status (start is true, stop
                                 is false)
  -t [ --start_time ] arg        start date time for short running app (e.g.,
                                 '2018-01-01 09:00:00')
  -s [ --daily_start ] arg       daily start time (e.g., '09:00:00')
  -d [ --daily_end ] arg         daily end time (e.g., '20:00:00')
  -m [ --memory ] arg            memory limit in MByte
  -v [ --virtual_memory ] arg    virtual memory limit in MByte
  -p [ --cpu_shares ] arg        CPU shares (relative weight)
  -e [ --env ] arg               environment variables (e.g., -e env1=value1 -e
                                 env2=value2)
  -i [ --interval ] arg          start interval seconds for short running app
  -x [ --extra_time ] arg        extra timeout for short running app,the value
                                 must less than interval  (default 0)
  -z [ --timezone ] arg          posix timezone for the application, reflect
                                 [start_time|daily_start|daily_end] (e.g.,
                                 'WST+08:00' is Australia Standard Time)
  -k [ --keep_running ] arg (=0) monitor and keep running for short running app
                                 in start interval
  -f [ --force ]                 force without confirm
  -g [ --debug ]                 print debug information
  -h [ --help ]                  help message

  
$ appc reg -n ping -u kfc -c 'ping www.google.com' -w /opt
Application already exist, are you sure you want to update the application (y/n)?
y
{
   "status" : 1,
   "command_line" : "ping www.google.com",
   "name" : "ping",
   "pid" : -1,
   "return" : 0,
   "run_as" : "kfc",
   "working_dir" : "/opt"
}
```




## Remove an application
```
appc unreg -n ping
Are you sure you want to remove the application (y/n)?
y
Success
```

## Start an application
```
$ appc start -n ping
```

## Stop an application
```
$ appc stop -n ping
```

## Test run an application and get stdout
``` sh
$ appc test -n ping -t 5
PING www.a.shifen.com (220.181.112.244) 56(84) bytes of data.
64 bytes from 220.181.112.244: icmp_seq=1 ttl=55 time=20.0 ms
64 bytes from 220.181.112.244: icmp_seq=2 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=3 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=4 ttl=55 time=20.1 ms
64 bytes from 220.181.112.244: icmp_seq=5 ttl=55 time=20.1 ms
```

## Run a shell command and get stdout
``` sh
$ appc sh -e LD_LIBRARY_PATH=/opt/appmanager/lib64 -c "appc view" 
id name        user  status   pid    return memory  command_line
1  period      root  enabled  1044   0      668 K   /bin/sleep 20
2  ping        root  enabled  586    0      956 K   ping www.baidu.com
3  869d8991-0* root  stopped  0      0      0       /bin/sh -c 'export LD_LIBRARY_PATH=/opt/appmanager/lib64;appc view'
```

![example](https://github.com/laoshanxi/app-manager/blob/master/doc/example.gif?raw=true) 

## Remote run a shell command
![appc_sh](https://github.com/laoshanxi/app-manager/blob/master/doc/appc_sh.gif?raw=true) 

## Usage scenarios
1. Integrate with package installation script and register startup command to app manager automaticlly
2. Install on remote host to execute command remotly and get output (can build-up web ssh)
3. Get resource usage (cpu/memory) for each application and host resource status

## 3rd party deependencies
- [C++11](http://www.cplusplus.com/articles/cpp11)
- [ACE](https://github.com/DOCGroup/ACE_TAO)
- [Microsoft cpprestsdk](https://github.com/Microsoft/cpprestsdk)
- [boost](https://github.com/boostorg/boost)
- [jsoncpp](https://github.com/open-source-parsers/jsoncpp)
- [log4cpp](http://log4cpp.sourceforge.net)
- [jwt_cpp](https://thalhammer.it/projects/jwt_cpp)

## Design
### Thread model
<div align=center><img src="https://github.com/laoshanxi/app-manager/blob/master/doc/threadmodel.jpg?raw=true" align=center /></div>