
## Golang REST agent

### Docker proxy

`dockeragent.go` implement a proxy to pass 127.0.0.1:6058 to unix:///var/run/docker.sock
`docker_nginx` implement a docker proxy demo with Nginx

### AppMesh REST entrypoint

`restagent.go` impelment REST server pass request to backend C++ TCP server tcp:127.0.0.1:6059

```
$ /opt/appmesh/bin/agent -h
Usage of /opt/appmesh/bin/agent:
  -docker_agent_url string
        The host URL used to listen docker proxy (default "https://127.0.0.1:6058")
  -docker_socket_file string
        Docker unix domain socket file path used to forward docker proxy (default "/var/run/docker.sock")
```
