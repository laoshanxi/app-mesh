# Manage cluster level microservice applications

Multiple App Mesh instances can connect as a cluster with [Consul](https://app-mesh.readthedocs.io/en/latest/CONSUL.html) and schedule cluster level microservice applications. Cluster level application can get the benefit of cluster level HA, and the application will be schedule among the cluster with resource requirement consideration.

## Configuration

In cluster environment, an App Mesh instance can be a `main` (leader candidates) node or `worker` node, All main nodes and worker nodes should connect to the same Consul URL to perform a cluster, we can configure from App Mesh UI:

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/07.png" />

### Add cloud application

We can register cloud application in Cloud menu.
<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/08.png" />

Cloud application can have bellow content:

1. application definition JSON body
2. application replication number (App Mesh will schedule and start according instance)
3. application service port (this will be registered to Consul service for service discovering)
4. application schedule preference (node select with labels, support wildcards)

### App Schedule

App Mesh leader node will schedule cloud application to perfected nodes, and cloud app will have cloud icon from UI:

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/09.png" />
