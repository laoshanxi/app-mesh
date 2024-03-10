#!/usr/bin/env python
import sys
import socket
import uuid

# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client

APP_NAME_SHADOW = socket.gethostname()  # used as shadow native app name
APP_NAME_MONITOR = str(uuid.uuid1())  # used as monitor app name

client = appmesh_client.AppMeshClient()
# authentication
client.login("admin", "admin123")

# prepare command line for native application
args = sys.argv
del args[0]
COMMANDS = " ".join(args)

# run monitor app without block mode (dependency: pip3 install docker six)
client.run_async(
    app=appmesh_client.App(
        {
            "command": f"python3 /opt/appmesh/bin/container_monitor.py {APP_NAME_SHADOW} {APP_NAME_MONITOR}",
            "name": APP_NAME_MONITOR,
        }
    )
)

# run native app with block mode
# TODO: pass container mem/cpu limitation to App Mesh
# TODO: pass container specific Environments to App Mesh
run = client.run_async(
    app=appmesh_client.App(
        {"name": APP_NAME_SHADOW, "command": COMMANDS, "shell": True}
    ),
)
rt = client.run_async_wait(run)
sys.exit(rt)
