#!/usr/bin/env python
import sys
import socket
import os
import uuid

sys.path.append("/opt/appmesh/sdk/")
import appmesh_client

# get host OS ip
# https://stackoverflow.com/questions/31324981/how-to-access-host-port-from-docker-container
host_ip = os.popen(r"route -n | awk '/UG[ \t]/{print $2}'").readline().strip()  # depend on [net-tools]

shadow_app_name = socket.gethostname()  # used as shadow native app name
monitor_app_name = str(uuid.uuid1())  # used as monitor app name
client = appmesh_client.AppMeshClient(server_host=host_ip)
# authentication
client.login("admin", "Admin123")

# prepare command line for native application
args = sys.argv
del args[0]
command = " ".join(args)

# run monitor app without block mode (dependency: pip3 install docker six)
client.run(
    app_json={"command": "python3 /opt/appmesh/bin/container_monitor.py {0} {1}".format(shadow_app_name, monitor_app_name), "name": monitor_app_name},
    synchronized=False,
    max_exec_time=65535,
    block_async_run=False,
)

# run native app with block mode
# TODO: pass container mem/cpu limitation to App Mesh
# TODO: pass container specific Environments to App Mesh
rt = client.run(
    app_json={"name": shadow_app_name, "command": command, "shell_mode": True},
    synchronized=False,
    max_exec_time=65535,
    block_async_run=True,
)
sys.exit(rt)
