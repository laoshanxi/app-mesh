# Kubernetes Integration

This document specifies the two Kubernetes integrations of App Mesh: running host-OS native commands from Kubernetes Jobs, and provisioning local persistent volumes through a Service Broker.

## 1. Run host-OS commands from Kubernetes Jobs

Kubernetes manages container applications only. The `laoshanxi/appmesh:container_agent` image (built from [`Dockerfile.container_agent`](https://github.com/laoshanxi/app-mesh/tree/main/docker/Dockerfile.container_agent)) closes that gap: the container forwards its start command to the App Mesh daemon on the host, App Mesh runs it as a native host process, and the container's lifecycle follows the native application.

Each Job container registers two App Mesh applications through the REST API: one starts the container command on the host, the other cleans the App Mesh applications up when the container exits. App Mesh must run on the host OS first ([Installation](../deploy/Install.md#linux-installation)); a [demo video](https://asciinema.org/a/685tfnMjbnxjTB1sKbqs5Qv99) shows the full loop.

A quick test without Kubernetes:

```shell
sudo python3 -m pip install appmesh docker --break-system-packages
export APPMESH_BEARER_TOKEN="<access token>"
docker run --net=host --cidfile=/tmp/container.id -v /tmp/container.id:/tmp/container.id \
  -e APPMESH_BEARER_TOKEN laoshanxi/appmesh:container_agent docker ps
```

### 1.1 Authentication

Each host runs its own App Mesh with its own built-in authentication, so a Job submitter cannot know every node's password — and does not need to. Two options:

| Option | How | Lifetime |
| --- | --- | --- |
| Static bearer | `APPMESH_BEARER_TOKEN` environment variable | 15 minutes — short jobs only |
| Node-local credentials (recommended) | A `hostPath`-mounted password file; the agent container exchanges it for a token at startup and re-authenticates on expiry; the host-side cleanup monitor re-authenticates the same way | Unattended, any container lifetime |

One-time setup on each node — create a least-privilege role, then a dedicated user bound to it. The agent runs applications through `POST /appmesh/app/run`, which needs `app-run-async` — not `app-reg`. Without the second argument, `add-user` binds the read-only `appmesh-viewer` role and every run fails with 403:

```shell
# Requires an administrator token; see Authentication, "Password grant".
export APPMESH_BEARER_TOKEN=$(echo 'admin-password' | sudo /opt/appmesh/script/appmesh-auth.sh user-token)
curl -k -X POST https://127.0.0.1:6060/appmesh/role/appmesh-agent \
  -H "Authorization: Bearer $APPMESH_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '["app-run-async", "app-output-view", "app-delete", "app-view"]'
unset APPMESH_BEARER_TOKEN

openssl rand -hex 24 | sudo tee /etc/appmesh/agent-password | \
  sudo /opt/appmesh/script/appmesh-auth.sh add-user agent@appmesh.local appmesh-agent
sudo chmod 600 /etc/appmesh/agent-password
```

The built-in `appmesh-maintenance` role cannot run applications and fails with 403 here. See [Authentication](../security/Authentication.md) for the role and permission model.

The agent container reads these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `APPMESH_BEARER_TOKEN` | — | Static token; disables the password grant |
| `APPMESH_AGENT_USERNAME` | `admin@appmesh.local` | User for the password grant |
| `APPMESH_AGENT_PASSWORD_FILE` | `/run/appmesh/agent-password` | Password file path inside the container |
| `APPMESH_AGENT_TOKEN_URL` | `https://127.0.0.1:6060/auth/token` | Token endpoint of the node-local agent |
| `APPMESH_AGENT_HOST_PASSWORD_FILE` | `/etc/appmesh/agent-password` | Password file path on the host, used by the cleanup monitor |

Security notes:

- The password never appears in the Job manifest, in a Kubernetes Secret, or in an environment variable, so it cannot leak through `kubectl describe pod`, `docker inspect`, or CI logs.
- Restrict with RBAC and PodSecurity who can create pods with this `hostPath` + `hostNetwork` combination: such a pod can run commands on the node — that is the purpose of this image.

### 1.2 Job example

Run `docker ps` on the host OS through a Job (the command runs on the host, so the image needs no docker installed):

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: myjob
spec:
  template:
    spec:
      containers:
      - name: native-cmd-test
        image: laoshanxi/appmesh:container_agent
        args: ["docker ps"]
        env:
        - name: APPMESH_AGENT_USERNAME
          value: agent@appmesh.local
        volumeMounts:
        - name: agent-cred
          mountPath: /run/appmesh/agent-password
          subPath: agent-password
          readOnly: true
      volumes:
      - name: agent-cred
        hostPath:
          path: /etc/appmesh/agent-password
          type: File
      restartPolicy: Never
      hostNetwork: true
```

```shell
$ kubectl apply -f myjob.yml && kubectl get pods
NAME          READY   STATUS      RESTARTS   AGE
myjob-vtc8h   0/1     Completed   0          8s
$ kubectl logs myjob-vtc8h     # the host's `docker ps` output
```

## 2. Local persistent volumes through a Service Broker

Database applications that depend on I/O performance get poor results on shared storage such as GlusterFS or Ceph. Kubernetes local PV storage classes exist, but Kubernetes does not dynamically provision persistent volumes for them. With App Mesh remote command execution, a Service Broker can create real local PVs for containers:

<div align=center><img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/localpv.png" /></div>

1. The Service Broker accepts an instance-create request with the requested resources.
2. The broker schedules a dummy YAML with the request requirements (plus a local-PV node label).
3. When Kubernetes finishes scheduling the dummy YAML, the broker creates the corresponding local PV remotely through App Mesh.
4. The broker creates the real application YAMLs with a `DaemonSet`, so the new container is scheduled to the local-PV node.
5. The broker deletes the dummy YAML.
6. When the broker instance is destroyed, it cleans the remote PV accordingly.

Applications on Kubernetes follow the [Open Service Broker API](https://github.com/openservicebrokerapi/servicebroker) in this design; each application kind implements its own broker, and the launch process is handled inside the broker.

## 3. Related

- [REST API](../interfaces/RESTAPI.md) — the application and run endpoints the agent container drives
- [Authentication](../security/Authentication.md) — roles, permissions, and the password grant
- [Deploy](../deploy/Install.md) — host installation
