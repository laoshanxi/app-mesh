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
 
 ```

- Consul task
 Consul task define cluster level applications, the defined application will be dispatch to tasks in Consul.
 App Manager leader node will get defined task and current working node. The Consul task can define replication number and 
 application json content which is the same as App Manager app json.
 Each task is a Consul key.
 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/task?recurse | python -m json.tool 
 curl -s http://localhost:8500/v1/kv/appmgr/task/myapp?raw | python -m json.tool        
{
    "content": {
        "command": "sleep 30",
        "name": "myapp",
		"condition": {
			"arch": "x86_64",
			"os_version": "centos7.6"
		}
    },
    "replication": 1
}
 ```

- Consul topology
 Topology is Consul task schedule result, App Manager leader node will write this part.
   For host dimension, each host is a key
   For task demension, the result assemble to one key

 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/topology/myhost?raw | python -m json.tool  
[
    "myapp",
    "myapp2"
]
 ```

 ### Consul Key/Value organization
```json
{
	"appmgr": {
		"status": {
			"myhost": {
				"resource": {
					"appmgr_start_time": "2020-02-04 15:37:21",
					"cpu_cores": 6,
					"cpu_processors": 6,
					"cpu_sockets": 1,
					"pid": 16567,
					"fs": [],
					"net": [],
					"systime": "2020-02-04 16:01:58"
				},
				"applications": {
					"ipmail": {
						"cache_lines": 20,
						"command": "sh /opt/qqmail/launch.sh",
						"health": 0,
						"id": "2d93b31e-4721-11ea-8000-6c2b59df0017",
						"last_start_time": "2020-02-04 15:58:50",
						"name": "ipmail",
						"next_start_time": "2020-02-04 16:03:50",
						"start_interval_seconds": 300,
						"start_time": "2020-01-14 21:38:50",
						"status": 1,
						"user": "root",
						"working_dir": "/opt/qqmail"
					}
				}
			}
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
				"replication": 1,
				"port":0,
				"content": {
					"name": "myapp2",
					"command": "sleep 100"
				}
			}
		},
		"topology": {
			"myhost": [ 
			    {"app": "myapp", "peer_hosts": ["hosts"] },
				{"app": "myapp2" }],
			"host2": ["myapp", "myapp2"]
		}
	}
}
```
 
- Use bellow command to start single Consul instance
```shell
$ docker rm consul -f ; docker run --restart=always --net=host -p 8500:8500 -e CONSUL_BIND_INTERFACE=p8p1 --name consul -d docker.io/consul consul agent -server=true -data-dir /consul/data -config-dir /consul/config --client=0.0.0.0 -bind=192.168.3.24 -bootstrap-expect=1 -ui
```