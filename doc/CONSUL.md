# Consul Integration

------

### What is supported:

> * Each App Manager node report status to Consul with a requested Consul session id
> * App Manager cluster can have one eletion leader
> * Two types of Applications : Consul task and normal task
> * App Manager Leader node schedule consul tasks and put result in Consul
> * App Manager node retrieve consul tasks from Consul dynamiclly
> * Consul session id support HA
> * Consul session requested with TTL and delete behavior when expired

### What is **not** supported:
> * Consul connection ACL and SSL are not supported
> * Consul watch
> * Task dispatch policy have not implemented
> * Schedule consider resource usage

### Consul configuration

```
 "Consul": {
    "url": "http://localhost:8500",
    "session_node": null,
    "session_TTL": 30,
    "report_interval": 10,
    "topology_interval": 5
  }
```




#### status report
 Two report key for each node:
 1. appmgr/status/$host_name/resource
 2. appmgr/status/$host_name/applications

 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/status/cents/resource?raw | python -m json.tool
 curl -s http://localhost:8500/v1/kv/appmgr/status/cents/applications?raw | python -m json.tool
 
 ```

 #### Consul task
 Consul task define cluster level applications, the defined application will be dispatch to tasks in consul.
 App Manager leader node will get defined task and current working node. The consul task can define replication number and 
 application json content which is the same as App Manager app json.
 Each task is a consul key.
 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/task?recurse | python -m json.tool 
 curl -s http://localhost:8500/v1/kv/appmgr/task/myapp?raw | python -m json.tool        
{
    "content": {
        "command": "sleep 30",
        "name": "myapp"
    },
    "replication": 1
}
 ```

 #### Consul topology
 Topology is Consul task schedule result, each host is a key, Only  App Manager leader node will write this part.

 ```shell
 curl -s http://localhost:8500/v1/kv/appmgr/topology/cents?raw | python -m json.tool  
[
    "myapp",
    "myapp2"
]
 ```

 ### Consul orgnization
```
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
					"fs": []
					"net": []
					"systime": "2020-02-04 16:01:58"
}				},
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
		},
		"task": {
			"myapp": {
				"replication": 2,
				"content": {
					"name": "myapp",
					"command": "sleep 30"
				}
			},
			"myapp2": {
				"replication": 1,
				"content": {
					"name": "myapp2",
					"command": "sleep 100"
				}
			}
		}
		"topology": {
			"myhost": ["myapp", "myapp2"]
		}
	}
}
```
 