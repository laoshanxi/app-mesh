# Kubernetes run non-container applications

[Demo video](https://asciinema.org/a/685tfnMjbnxjTB1sKbqs5Qv99)

## Background

Kubernetes only support manage container applications, It's impossible to run none-container application by Kubernetes.
This solution provides a simple way to forward container start cmd to AppMesh and running on native host, AppMesh will guarantee the native application have same lifecycle with container.

## Install AppMesh on host OS

AppMesh is a native app manager, provide REST API which can used to manage application remotely. AppMesh is running on host OS, and container can register process to AppMesh by API, each container will register 2 AppMesh applications, one is used to start container command, the other is used to clean AppMesh application when container exits.
[Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html#linux-installation)

## Build Kubernetes Docker image for native command

This Docker image `laoshanxi/appmesh:container_agent` is used to forward container start command to AppMesh, The image was already built and pushed to `docker.io` and built by [Dockerfile](https://github.com/laoshanxi/app-mesh/tree/main/docker/Dockerfile.container_agent).

## Test run native command in docker container

```shell
sudo python3 -m pip install appmesh docker --break-system-packages
# Dex-only authentication: pass a bearer with app-run-async and app-delete
# permissions, for example an administrator token. The token expires after
# 15 minutes; for unattended runs use node-local authentication (below).
export APPMESH_BEARER_TOKEN="<access token>"
docker run --net=host --cidfile=/tmp/container.id -v /tmp/container.id:/tmp/container.id -e APPMESH_BEARER_TOKEN laoshanxi/appmesh:container_agent docker ps
```

## Unattended authentication (node-local credentials)

Each host runs its own App Mesh with its own built-in authentication, so a
Job submitter cannot know every node's password — and does not need to. The
credential stays on the node: the agent container reads it through a
`hostPath` mount and exchanges it for an access token at startup, and the
host-side cleanup monitor re-authenticates the same way when the container
exits. The flow re-authenticates on token expiry, so containers of any
lifetime keep working.

One-time setup on each node — create a dedicated user and store its password
in a root-only file. `add-user` requires the role to exist in the
authorization policy, so create a least-privilege role first (the agent runs
applications through `POST /appmesh/app/run`, which needs `app-run-async`,
not `app-reg`), then create the user bound to it — without the second
argument `add-user` binds the read-only `appmesh-viewer` role and every run
fails with 403:

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

See
[Authentication](https://app-mesh.readthedocs.io/en/latest/Authentication.html#roles)
for the role and permission model. The built-in `appmesh-maintenance` role
cannot run applications and fails with 403 here.

The agent container reads these environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `APPMESH_BEARER_TOKEN` | — | Static token; disables the password grant. Expires in 15 minutes — short jobs only |
| `APPMESH_AGENT_USERNAME` | `admin@appmesh.local` | User for the password grant |
| `APPMESH_AGENT_PASSWORD_FILE` | `/run/appmesh/agent-password` | Password file path inside the container |
| `APPMESH_AGENT_TOKEN_URL` | `https://127.0.0.1:6060/auth/token` | Token endpoint of the node-local agent |
| `APPMESH_AGENT_HOST_PASSWORD_FILE` | `/etc/appmesh/agent-password` | Password file path on the host, used by the cleanup monitor |

Security notes:

- The password never appears in the Job manifest, in a Kubernetes Secret, or
  in an environment variable, so it cannot leak through
  `kubectl describe pod`, `docker inspect`, or CI logs.
- Restrict with RBAC and PodSecurity who can create pods with this
  `hostPath` + `hostNetwork` combination: such a pod can run commands on the
  node — that is the purpose of this image.

## Kubernetes job example to run cmd on host OS

This is an example run `docker ps` command on host OS and I did not install docker to this image, the command will forward to AppMesh and return result to container.

```shell
$ tee myjob.yml <<-'EOF'
apiVersion: batch/v1
kind: Job
metadata:
  name: myjob
spec:
  template:
    metadata:
      name: myjob
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
EOF

$ kubectl apply -f myjob.yml
job.batch/myjob created

$ kubectl get pods
NAME          READY   STATUS      RESTARTS   AGE
myjob-vtc8h   0/1     Completed   0          8s

$ kubectl logs myjob-vtc8h
CONTAINER ID        IMAGE                                                 COMMAND                  CREATED                  STATUS                  PORTS                                                                                                       NAMES
805dc03c3433        laoshanxi/appmesh_agent                               "python3 /opt/appmes…"   Less than a second ago   Up Less than a second
                     k8s_native-cmd-test_myjob-rp6gp_default_473ca690-c685-4d97-b135-499b40c7ad24_0
3e482b6cf175        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 8 seconds ago            Up 8 seconds                                                                                                                        k8s_POD_myjob-rp6gp_default_473ca690-c685-4d97-b135-499b40c7ad24_0
69cd63beddf3        kubernetesui/dashboard                                "/dashboard --insecu…"   3 hours ago              Up 3 hours                                                                                                                          k8s_kubernetes-dashboard_kubernetes-dashboard-1621683118-6dfd7fb446-hbhbj_kube-system_0adaa5dd-e5aa-46d1-9855-ac9fde6afe27_0
5dac52459e05        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 3 hours ago              Up 3 hours                                                                                                                          k8s_POD_kubernetes-dashboard-1621683118-6dfd7fb446-hbhbj_kube-system_0adaa5dd-e5aa-46d1-9855-ac9fde6afe27_0
54739eda7c37        3885a5b7f138                                          "/coredns -conf /etc…"   7 hours ago              Up 7 hours                                                                                                                          k8s_coredns_coredns-545d6fc579-fxzm7_kube-system_6b9073e8-1d25-4362-a78f-09fd964647ab_0
7c79f918b323        3885a5b7f138                                          "/coredns -conf /etc…"   7 hours ago              Up 7 hours                                                                                                                          k8s_coredns_coredns-545d6fc579-8lxbm_kube-system_4083590b-588f-436e-8ab9-367e659aca44_0
d565259460ab        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 7 hours ago              Up 7 hours                                                                                                                          k8s_POD_coredns-545d6fc579-8lxbm_kube-system_4083590b-588f-436e-8ab9-367e659aca44_0
5164ed1d0f5a        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 7 hours ago              Up 7 hours                                                                                                                          k8s_POD_coredns-545d6fc579-fxzm7_kube-system_6b9073e8-1d25-4362-a78f-09fd964647ab_0
4e875b475432        ff281650a721                                          "/opt/bin/flanneld -…"   7 hours ago              Up 7 hours                                                                                                                          k8s_kube-flannel_kube-flannel-ds-amd64-s7xlv_kube-system_721629f8-37c9-4ba6-a5a8-6da2338821df_0
67dfd0f306f0        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 7 hours ago              Up 7 hours                                                                                                                          k8s_POD_kube-flannel-ds-amd64-s7xlv_kube-system_721629f8-37c9-4ba6-a5a8-6da2338821df_0
499ee792a968        4359e752b596                                          "/usr/local/bin/kube…"   7 hours ago              Up 7 hours                                                                                                                          k8s_kube-proxy_kube-proxy-dd8tg_kube-system_22aa23ea-31bb-43db-b291-d45eb299da61_0
a96e5c736f9e        registry.aliyuncs.com/google_containers/pause:3.4.1   "/pause"                 7 hours ago              Up 7 hours                                                                                                                          k8s_POD_kube-proxy-dd8tg_kube-system_22aa23ea-31bb-43db-b291-d45eb299da61_0
ebac7a8ecc0f        0369cf4303ff                                          "etcd --advertise-cl…"   7 hours ago              Up 7 hours                                                                                                                          k8s_etcd_etcd-appmesh_kube-system_5d160e57e8635cd0c69135b7b768045b_0
23a5c9d28c68        771ffcf9ca63                                          "kube-apiserver --ad…"   7 hours ago              Up 7 hours                                                                                                                          k8s_kube-apiserver_kube-apiserver-appmesh_kube-system_3c1f54f06e9a4e45f00deb20f8bacdc6_0
294e4e18d348        e16544fd47b0                                          "kube-controller-man…"   7 hours ago              Up 7 hours                                                                                                                          k8s_kube-controller-manager_kube-controller-manager-appmesh_kube-system_d1b968d45ab2d7c9ed9d656c91ce03e4_0
.
.
.
.
.
.
```
