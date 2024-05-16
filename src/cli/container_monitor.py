#!/usr/bin/env python
import sys

# python3 -m pip install --upgrade appmesh
from appmesh import appmesh_client
import docker

# input
#  - arg[1] as container name and shadow application name
#  - arg[2] as self monitor application name
args = sys.argv
del args[0]
container_name = args[0]

# login appmesh
appmesh = appmesh_client.AppMeshClient()
appmesh.login("admin", "admin123")

# wait docker finish and ignore container not exist error
# https://docker-py.readthedocs.io/en/stable/containers.html#docker.models.containers.Container.wait
client = docker.APIClient(base_url="unix://var/run/docker.sock")
try:
    print(client.wait(container_name))
except Exception as e:
    print(e)
else:
    pass

# remove related applications
for app_name in args:
    try:
        print(appmesh.app_delete(app_name))
    except Exception as e:
        print(e)

print("Finished")
