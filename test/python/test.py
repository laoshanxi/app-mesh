#!/usr/bin/python3
import json
import sys
import os
import inspect

# For installation env:
# sys.path.append("/opt/appmesh/sdk/")

# For source code env:
current_file_path = inspect.getfile(inspect.currentframe())
current_dir_name = os.path.abspath(os.path.dirname(current_file_path))
root_dir = os.path.dirname(os.path.dirname(current_dir_name))
sys.path.append(os.path.join(root_dir, "src/sdk/python"))

import appmesh_client

client = appmesh_client.AppMeshClient()
client.login("admin", "Admin123")
client.login_with_token(client.jwt_token)
print(json.dumps(client.get_resource(), indent=2))
print(json.dumps(client.get_app("ping"), indent=2))
print(json.dumps(client.get_apps(), indent=2))
print(json.dumps(client.add_app({"command": "ping www.baidu.com -w 5", "name": "SDK"}), indent=2))
client.run({"command": "ping www.baidu.com -w 5", "shell_mode": True}, False)
print(client.remove_app("SDK"))
print(client.disable_app("ping"))
print(client.enable_app("ping"))
print(client.add_tag("MyTag", "TagValue"))
print(client.get_tags())
print(client.get_app_output("loki"))
print(client.get_app_health("ping"))
print(client.get_metrics())
print(client.download("/opt/appmesh/log/appsvc.log", "1.log"))
print(client.upload(local_file="/opt/appmesh/log/appsvc.log", file_path="/tmp/2.log"))
print(json.dumps(client.get_cloud_apps(), indent=2))
print(
    client.add_cloud_app(
        {
            "condition": {"arch": "x86_64", "os_version": "centos7.6"},
            "content": {
                "command": "sleep 30",
                "metadata": "cloud-sdk-app",
                "name": "cloud",
                "shell_mode": True,
            },
            "port": 6667,
            "priority": 0,
            "replication": 1,
            "memoryMB": 1024,
        }
    )
)
print(json.dumps(client.remove_cloud_app("cloud"), indent=2))
print(json.dumps(client.get_cloud_nodes(), indent=2))
