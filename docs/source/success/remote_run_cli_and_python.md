# Remote run
App Mesh support remote run a command, a script, and even a section of Python script

## Run commands
```
# appc run -c whoami
root
```

Run a command with normal exit:
```
# appc run -c 'ping www.baidu.com -w 2' -t 5; echo $?
PING www.a.shifen.com (14.215.177.39) 56(84) bytes of data.
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=1 ttl=55 time=31.8 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=2 ttl=55 time=31.9 ms

--- www.a.shifen.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 31.844/31.850/31.857/0.006 ms
0
```

Run a command and exit due to timeout:
```
# appc run -c 'ping www.baidu.com -w 2' -t 5
PING www.a.shifen.com (14.215.177.39) 56(84) bytes of data.
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=1 ttl=55 time=31.9 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=2 ttl=55 time=31.7 ms

--- www.a.shifen.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 31.722/31.827/31.933/0.105 ms
(base) root@appmesh:~# appc run -c 'ping www.baidu.com -w 20' -t 5; echo $?
PING www.a.shifen.com (14.215.177.39) 56(84) bytes of data.
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=1 ttl=55 time=31.8 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=2 ttl=55 time=31.8 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=3 ttl=55 time=31.8 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=4 ttl=55 time=31.8 ms
64 bytes from 14.215.177.39 (14.215.177.39): icmp_seq=5 ttl=55 time=31.7 ms
9
```

## Run Python script
Use metadata to input python script which would be executed on remote side:
```
# appc run -n  pyrun -g "print(99); print(2+9)" -t -1
99
11
```
