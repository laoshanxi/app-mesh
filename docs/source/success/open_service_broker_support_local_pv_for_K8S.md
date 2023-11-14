# Open service broker support local PV for Kubernetes

Currently, we are moving more and move applications to Kubernetes, but for Data Base applications which depend on IO performance, will get bad experience using shared storage like GlusterFS, Ceph. even Kubernetes support local PV storage class, but still does not support dynamic provision for persistent volume.

## Solution

With the ability of remote execute commands by App Mesh, we can design a real local PV for docker container, this will improve container IO performance and gain the local storage performance.

We usually manage applications on Kubernetes follow [Open Service Broker API](https://github.com/openservicebrokerapi/servicebroker), and implement `Service Broker` for each kind of applications, the application launch process will be handled in `Service Broker`.
<div align=center><img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/localpv.png" /></div>

1. Service Broker accept a instance create request with requested resource
2. Service Broker schedule a dummy YAML with request requirement (plus local PV node label)
3. When Kubernetes finished schedule dummy YAML, create corresponding Local PV remotely
4. Service Broker create real multiple Application YAML with `Daemon Set` to make sure new container schedule to local PV node
5. Delete dummy YAML
6. When broker instance destroying, clean remote PV accordingly
