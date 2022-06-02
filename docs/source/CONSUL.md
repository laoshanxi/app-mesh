# Consul Integration

App Mesh can work as *stand-alone* mode and *Consul-cluster* mode.
- Stand-alone mode: The hosted applications can only be managed by CLI or Web UI locally.
- Consul-cluster mode: The hosted applications can be defined in Consul, all the App Mesh nodes will vote one leader node to do the Consul application schedule, the worker App Mesh nodes will got the schedule result and launch corresponding applications.
- Each application with listen port will register as Consul service for service discovery

<div align=center><img src="docs/source/consul_arch.png" width=600 height=300 align=center /></div>

### What is supported:

> * Each App Mesh instance in the cluster will keep a connection(support SSL) to Consul Service as a consul session
> * App Mesh only talks to Consul service by one way communication
> * Each App Mesh node report status to Consul KV data with session lock
> * App Mesh node can be a cluster leader node or worker node
> * Cluster level application is submitted and defined in Consul KV data and support node selector (the selector can be hostname or any App Mesh Labels, wildcards is supported when build gcc version upper than 5.3)
> * App Mesh Leader node schedule cluster applications and write schedule result to Consul KV data
> * App Mesh worker node retrieve cluster applications (schedule result) and launch on worker node
> * Cluster App support register as Consul Service for service discovery (each peer app will get others by env) with service health check point to app health API
> * Consul session support HA recovery
> * App Mesh request Consul session with TTL and expire delete behavior
> * Consul watch is supported for monitor consul schedule changes and security sync-up
> * Schedule consider resource usage and guarantee cluster applications running with corresponding replication

### What is **not** supported:
> * Consul access ACL

### Consul configuration

```json
  "Consul": {
    "IsMainNode": true,
    "IsWorkerNode": true,
    "Url": "http://localhost:8500",
    "SessionTTL": 30,
    "EnableConsulSecurity": false,
    "AppmeshProxyUrl": null
  }
```

------


- Status report
 Each node will report node info to Consul KV path `appmesh/cluster/nodes/$host_name`

 ```shell
curl -s http://localhost:8500/v1/kv/appmesh/cluster/nodes/centos8?raw | python3 -m json.tool
`
{
    "appmesh": "https://centos8:6060",
    "label": {
        "HOST_NAME": "centos8",
        "arch": "x86_64",
        "os_version": "centos7.6"
    },
    "leader": true,
    "resource": {
        "cpu_cores": 64,
        "mem_total_bytes": 270453616640
    }
}
`
 ```

- Consul application
 Consul application is cluster level application that defined in Consul with replication and node selector.
 App Mesh leader node will get defined Consul application and current working nodes. schedule applications to working nodes and write schedule result to Consul.
 Each working node will watch and get its Consul application.
 ```shell
 curl -s http://localhost:8500/v1/kv/appmesh/cluster/tasks?recurse | python3 -m json.tool
 `
 [
    {
        "CreateIndex": 22168,
        "Flags": 0,
        "Key": "appmesh/cluster/tasks/",
        "LockIndex": 0,
        "ModifyIndex": 22168,
        "Value": null
    },
    {
        "CreateIndex": 113084,
        "Flags": 0,
        "Key": "appmesh/cluster/tasks/myapp",
        "LockIndex": 0,
        "ModifyIndex": 237498,
        "Value": "ewoJCQkJInJlcGxpY2F0aW9uIjogMSwKICAgICAgICAicG9ydCI6NjY2NiwKCQkJCSJjb250ZW50IjogewoJCQkJCSJuYW1lIjogIm15YXBwIiwKCQkJCQkiY29tbWFuZCI6ICJzbGVlcCAzMCIKCQkJCX0sCiAgICAgICJjb25kaXRpb24iOiB7CiAgICAgICAgICAiYXJjaCI6ICJ4ODZfNjQiLAogICAgICAgICAgIm9zX3ZlcnNpb24iOiAiY2VudG9zNy42IgogICAgICB9Cn0="
    },
    {
        "CreateIndex": 25051,
        "Flags": 0,
        "Key": "appmesh/cluster/tasks/myapp2",
        "LockIndex": 0,
        "ModifyIndex": 241391,
        "Value": "ewoJCQkJInJlcGxpY2F0aW9uIjogMCwKICAgICAgICAicG9ydCI6NjY2NywKCQkJCSJjb250ZW50IjogewoJCQkJCSJuYW1lIjogIm15YXBwMiIsCgkJCQkJImNvbW1hbmQiOiAic2xlZXAgNjAiCgkJCQl9LAogICAgICAgICAiY29uZGl0aW9uIjogewoJICAgIAkJImFyY2giOiAieDg2XzY0IgoJICAgIAl9Cn0="
    }
]
 `
curl -s http://localhost:8500/v1/kv/appmesh/cluster/tasks/myapp?raw | python3 -m json.tool
`
{
    "replication": 3,
    "port": 6666,
    "memoryMB": 1024,
    "content": {
        "name": "myapp",
        "shell": true,
        "command": "sleep 30"
    },
    "condition": {
        "arch": "x86_64",
        "os_version": "centos7.6"
    }
}

`
 ```

- Consul topology
 Topology is Consul task schedule result, App Mesh leader node will write this dir.
   For host dimension, each host is a key
   For task dimension, the result assemble to one key

 ```shell
curl -s http://localhost:8500/v1/kv/appmesh/topology?recurse | python -m json.tool | grep Key
        "Key": "appmesh/cluster/topology/",
        "Key": "appmesh/cluster/topology/myhost",
curl -s http://localhost:8500/v1/kv/appmesh/topology/myhost?raw | python -m json.tool  
[
    {
        "app": "myapp",
        "schedule_time": "2021-03-25 17:23:58+08"
    }
]

 ```

 ### Consul Key/Value organization
```json
{
	"appmesh": {
        "cluster": {
            "nodes": {
                "host1": {
                    "label": {
                        "HOST_NAME": "centos8",
                        "arch": "x86_64",
                        "os_version": "centos7.6"
                    }
                },
                "host2": {
                    "label": {
                        "HOST_NAME": "centos7",
                        "arch": "x86_64",
                        "os_version": "centos7.6"
                    }
                }
            },
            "tasks": {
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
            }
        },
		"topology": {
			"myhost": [ 
			    {"app": "myapp", "schedule_time": "2021-03-25 17:23:58+08" },
				{"app": "myapp2", "schedule_time": "2021-03-25 17:23:58+08" }],
			"host2": [ 
			    {"app": "myapp", "schedule_time": "2021-03-25 17:23:58+08" }
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
