# Docker REST Proxy

Implement a proxy to access /var/run/docker.sock


## Solution1: Nginx

### Start Nginx reverse proxy

```
make
```

### Test reverse proxy

```
make test
```
## Solution2: Golang reverse proxy

dockeragent.go implement a proxy to pass 127.0.0.1:6058 to unix:///var/run/docker.sock
```
$ ./dockeragent -h
Usage of ./dockeragent:
  -socket string
        Docker unix domain socket file (default "/var/run/docker.sock")
  -url string
        The host URL used to listen (default "127.0.0.1:6058")
```
