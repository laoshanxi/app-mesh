#!/usr/bin/python3
import json
import appmesh_client

client = appmesh_client.AppMeshClient()
client.login("admin", "Admin123")
print(json.dumps(client.get_resource(), indent=2))
print(json.dumps(client.get_app("ping"), indent=2))
print(json.dumps(client.get_apps(), indent=2))
client.run({"command": "ping www.baidu.com -w 5", "shell_mode": True}, False)
print(client.disable_app("ping"))
# time.sleep(1)
print(client.enable_app("ping"))
print(client.get_tags())
