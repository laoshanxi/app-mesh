#!/usr/bin/env python
import os
import socket
import sys
import uuid

import warnings
from urllib3.exceptions import InsecureRequestWarning

# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

APP_NAME_MONITOR = str(uuid.uuid1())  # used as monitor app name
APP_NAME_SHADOW = socket.gethostname()  # used as shadow native app name
# for host mode networking, use cidfile solution to pass container id here
# docker run --cidfile=/tmp/container.id -v /tmp/container.id:/tmp/container.id ${IMAGE}
# https://stackoverflow.com/questions/26979038/how-to-get-container-name-from-inside-docker-io
if os.path.exists("/tmp/container.id"):
    with open("/tmp/container.id", "r", encoding="utf-8") as f:
        APP_NAME_SHADOW = f.readline().strip()


# prepare command line for native application
args = sys.argv
del args[0]
COMMANDS = " ".join(args)

client = appmesh_client.AppMeshClient()
client.login("admin", "admin123")
# run monitor app without block mode (dependency: pip3 install docker six)
client.run_async(
    app=appmesh_client.App(
        {
            "command": f"python3 /opt/appmesh/bin/container_monitor.py {APP_NAME_SHADOW} {APP_NAME_MONITOR}",
            "name": APP_NAME_MONITOR,
            "behavior": {
                "exit": "remove",
            },
        }
    )
)

# run native app with block mode
# TODO: pass container mem/cpu limitation to App Mesh
# TODO: pass container specific Environments to App Mesh
run = client.run_async(
    app=appmesh_client.App({"name": APP_NAME_SHADOW, "command": COMMANDS, "shell": True}),
)
rt = client.run_async_wait(run)
sys.exit(rt)
