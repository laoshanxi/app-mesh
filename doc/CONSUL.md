# Consul Integration

------

Application Manager can work as *stand-alone* mode and *Consul-cluster* mode.
- Stand-alone mode: The hosted applications are static and applications can only be managed by CLI or REST APIs.
- Consul-cluster mode: The hosted applications are dynamic, The cluster will vote one leader node to do the Consul application schedule, and application will register to Consul for service discovery.

### What is supported:

> * App Manager will keep connection(support SSL) to Consul Service as a consul session
> * App Manager only talks to Consul service by one way communication
> * Each App Manager node report status to Consul KV data
> * App Manager can be a cluster leader node or worker node
> * App Manager Leader node schedule Consul applications and write result to Consul KV data
> * App Manager worker node retrieve Consul applications from Consul dynamically
> * Consul App is defined in Consul and support node selector (the selector can be hostname or any AppManager Labels, regex is not supported)
> * Consul App support register as Consul Service for service discovery (each peer app will get others by env) with service health check point to app health API
> * Consul session support HA recovery
> * App Manager request Consul session with TTL and expire delete behavior

### What is **not** supported:
> * Consul connection ACL
> * Consul watch
> * Schedule consider resource usage

### Consul configuration

```json
  "Consul": {
    "is_master": true,
    "is_node": true,
    "url": "http://localhost:8500",
    "datacenter": "dc1",
    "session_TTL": 30,
    "enable_consul_security": false,
    "consul_docker_img": "consul:latest"
  }
```

------


- Status report
 Each node will report to Consul KV path `appmgr/nodes/$host_name`

 ```shell
curl -s http://localhost:8500/v1/kv/appmgr/nodes/host2?raw | python -m json.tool         
{
    "label": {
        "HOST_NAME": "host2",
        "arch": "x86_64",
        "fdef": "fefe",
        "os_version": "centos7.6"
    },
    "resource": {
        "cpu_cores": 1,
        "mem_free_bytes": 93171712,
        "mem_total_bytes": 1039081472
    }
}
 ```

- Consul application
 Consul application is cluster level application that defined in Consul with replication and node selector.
 App Manager leader node will get defined Consul application and current working nodes. schedule applications to working nodes and write schedule result to Consul.
 Each working node will watch and get its Consul application.
 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/task?recurse | python -m json.tool 
 `
 [
    {
        "CreateIndex": 22168,
        "Flags": 0,
        "Key": "appmgr/task/",
        "LockIndex": 0,
        "ModifyIndex": 22168,
        "Value": null
    },
    {
        "CreateIndex": 113084,
        "Flags": 0,
        "Key": "appmgr/task/myapp",
        "LockIndex": 0,
        "ModifyIndex": 237498,
        "Value": "ewoJCQkJInJlcGxpY2F0aW9uIjogMSwKICAgICAgICAicG9ydCI6NjY2NiwKCQkJCSJjb250ZW50IjogewoJCQkJCSJuYW1lIjogIm15YXBwIiwKCQkJCQkiY29tbWFuZCI6ICJzbGVlcCAzMCIKCQkJCX0sCiAgICAgICJjb25kaXRpb24iOiB7CiAgICAgICAgICAiYXJjaCI6ICJ4ODZfNjQiLAogICAgICAgICAgIm9zX3ZlcnNpb24iOiAiY2VudG9zNy42IgogICAgICB9Cn0="
    },
    {
        "CreateIndex": 25051,
        "Flags": 0,
        "Key": "appmgr/task/myapp2",
        "LockIndex": 0,
        "ModifyIndex": 241391,
        "Value": "ewoJCQkJInJlcGxpY2F0aW9uIjogMCwKICAgICAgICAicG9ydCI6NjY2NywKCQkJCSJjb250ZW50IjogewoJCQkJCSJuYW1lIjogIm15YXBwMiIsCgkJCQkJImNvbW1hbmQiOiAic2xlZXAgNjAiCgkJCQl9LAogICAgICAgICAiY29uZGl0aW9uIjogewoJICAgIAkJImFyY2giOiAieDg2XzY0IgoJICAgIAl9Cn0="
    }
]
 `
 curl -s http://localhost:8500/v1/kv/appmgr/task/myapp?raw | python -m json.tool        
`
{
	"replication": 1,
	"port": 6666,
    "condition": {
        "arch": "x86_64",
        "os_version": "centos7.6"
    },
    "content": {
        "command": "sleep 30",
        "name": "myapp"
    }
}
`
 ```

- Consul topology
 Topology is Consul task schedule result, App Manager leader node will write this part.
   For host dimension, each host is a key
   For task dimension, the result assemble to one key

 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/topology?recurse | python -m json.tool | grep Key
        "Key": "appmgr/topology/",
        "Key": "appmgr/topology/cents",
 curl -s http://localhost:8500/v1/kv/appmgr/topology/myhost?raw | python -m json.tool  
[
    {
        "app": "myapp",
        "peer_hosts": [
            "myhost"
        ]
    },
    {
        "app": "myapp2",
        "peer_hosts": [
            "myhost"
        ]
    }
]
 ```

 ### Consul Key/Value organization
```json
{
	"appmgr": {
		"nodes": {
            "label": {
                "HOST_NAME": "host2",
                "arch": "x86_64",
                "fdef": "fefe",
                "os_version": "centos7.6"
            },
            "resource": {
                "cpu_cores": 1,
                "mem_free_bytes": 93171712,
                "mem_total_bytes": 1039081472
            },
			"host2": { }
		},
		"task": {
			"myapp": {
				"replication": 2,
				"port":8085,
				"content": {
					"name": "myapp",
					"command": "sleep 30"
				}
			},
			"myapp2": {
				"replication": 2,
				"port":0,
				"content": {
					"name": "myapp2",
					"command": "sleep 100"
				}
			}
		},
		"topology": {
			"myhost": [ 
			    {"app": "myapp", "peer_hosts": ["host2"] },
				{"app": "myapp2","peer_hosts": [] }],
			"host2": [ 
			    {"app": "myapp", "peer_hosts": ["myhost"] }
			]
		}
	}
}
```
 
- Use bellow command to start single Consul instance
```shell
$ docker rm consul -f ; docker run --restart=always --net=host -p 8500:8500 -v /etc/hosts:/etc/hosts -e CONSUL_BIND_INTERFACE=eth0 --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config --client=0.0.0.0 -bind=192.168.3.24 -bootstrap-expect=1 -ui
```
- Use bellow command to start 3 nodes Consul cluster
```shell
# server-1
docker run --restart=always --net=host --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config -bind=192.168.1.1 -bootstrap-expect=3 -ui
# server-2
docker run --restart=always --net=host --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config -bind=192.168.1.2 -bootstrap-expect=3 -ui -join 192.168.1.1
# server-3
docker run --restart=always --net=host --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config -bind=192.168.1.3 -bootstrap-expect=3 -ui -join 192.168.1.1
```
Note: consul container health-check will call outside URL, so need DNS to access other hostname or URL