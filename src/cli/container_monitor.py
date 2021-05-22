#!/usr/bin/env python

import docker
import sys

sys.path.append("/opt/appmesh/sdk/")
import appmesh_client

# input
#  - arg[1] as container name and shadow application name
#  - arg[2] as self monitor application name
args = sys.argv
del args[0]
container_name = args[0]

# login appmesh
appmesh = appmesh_client.AppMeshClient()
print(appmesh.login("admin", "Admin123"))

# wait docker finish and ignore container not exist error
# https://docker-py.readthedocs.io/en/stable/containers.html#docker.models.containers.Container.wait
client = docker.DockerClient(base_url="unix://var/run/docker.sock")
try:
    print(client.containers.get(container_name).wait())
except Exception as e:
    print(e)
else:
    pass

# remove related applications
for app_name in args:
    print(appmesh.remove_app(app_name))

print("Finished")
