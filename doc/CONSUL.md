# Consul Integration

------

Application Manager can work as *stand-alone* mode and *cluster* mode when enabled Consul.
- Stand-alone mode: The hosted applications is static and can only on-board applications by CLI or REST APIs.
- Cluster mode: The hosted apps is dynamic, The cluster will vote one leader to do the Consul application schedule, and application will register to Consul for service discovery.

### What is supported:

> * Implement a Consul connection(support SSL) to access Consul REST APIs
> * Two types of Applications : Consul task and local task
> * App Manager on each node organize to a cluster and have one eletion leader
> * Each App Manager node report status to Consul with a requested Consul session id
> * App Manager Leader node schedule Consul tasks and put result in Consul
> * App Manager work node retrieve Consul tasks from Consul dynamiclly
> * Consul App support node selector (the selector can be hostname or any AppManager Labels, regex is not supported)
> * Consul App support register as Consul Service for service discovery (each peer app will get others by env)
> * Consul session id support HA recovery
> * Consul session requested with TTL and expire delete behavior

### What is **not** supported:
> * Consul connection ACL are not supported
> * Consul watch
> * Schedule consider resource usage

### Consul configuration

```json
  "Consul": {
    "is_master": true,
    "is_node": true,
    "url": "http://localhost:8500",
    "session_node": null,
    "datacenter": "dc1",
    "session_TTL": 30,
    "report_interval": 10,
    "topology_interval": 5
  }
```

------


- Status report
 Each node will report 2 keys:
 1. appmgr/status/label/$host_name
 2. appmgr/status/resource/$host_name

 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/status/resource/cents?raw | python -m json.tool
 curl -s http://localhost:8500/v1/kv/appmgr/status/label/cents?raw | python -m json.tool
 {
    "HOST_NAME": "cents",
    "arch": "x86_64",
    "os_version": "centos7.6"
}
 ```

- Consul task
 Consul task define cluster level applications, the defined application will be dispatch to tasks in Consul.
 App Manager leader node will get defined task and current working node. The Consul task can define replication number and 
 application json content which is the same as App Manager app json.
 Each task is a Consul key.
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
   For task demension, the result assemble to one key

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
		"status": {
			"label": {
				"myhost": {"HOST_NAME":"myhost","arch":"x86_64","os_version":"centos7.6"}
			}£¬
			"resource": {}
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
			"host2": ["app": "myhost","peer_hosts": ["myhost"] }]
		}
	}
}
```
 
- Use bellow command to start single Consul instance
```shell
$ docker rm consul -f ; docker run --restart=always --net=host -p 8500:8500 -e CONSUL_BIND_INTERFACE=p8p1 --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config --client=0.0.0.0 -bind=192.168.3.24 -bootstrap-expect=1 -ui
```
Note: consul container healthcheck will call outside URL, so need DNS to access other hostname or URL