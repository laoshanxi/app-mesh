# Docker Applications

App Mesh runs a Docker container exactly like a supervised process: register
it with an image instead of a command line and you get scheduling, restart
behavior, health reporting, log tailing, graceful stop and exit codes — on a
single node or across a cluster through the same REST/SDK surface. This guide
covers what a user can do and how, from fields to lifecycle semantics.

Everything below works through the standard application APIs (REST, CLI,
five SDKs) and over cluster forwarding (`-F <node>` / `X-Target-Host`): a
Docker application registered on a remote node runs on that node's Docker.

## Quick start

Run a web server as a supervised container (REST):

```json
PUT /appmesh/app/myweb
{
  "name": "myweb",
  "docker_image": "nginx:1.27",
  "command": "nginx -g 'daemon off;'",
  "docker_ports": ["8080:80"],
  "session_login": false,
  "shell": false
}
```

The same application with the CLI:

```shell
appm add -a myweb -I nginx:1.27 -c "nginx -g 'daemon off;'" --docker-port 8080:80
appm view -a myweb        # container_id, health, exit code, restarts
appm view -a myweb -o     # tail the container output; add -f to follow
```

Python SDK:

```python
from appmesh.app import App
app = App()
app.name = "myweb"
app.docker_image = "nginx:1.27"
app.command = "nginx -g 'daemon off;'"
app.docker_ports = ["8080:80"]
client.add_app(app)
```

Rust SDK:

```rust
let app = AppMeshClient::builder("myweb")
    .docker_image("nginx:1.27")
    .command("nginx -g 'daemon off;'")
    .docker_ports(vec!["8080:80".into()])
    .build();
client.add_app(app).await?;
```

## Container wiring fields

| Field | Meaning | Docker equivalent |
|---|---|---|
| `docker_image` | Image reference (`repo:tag` or `repo@sha256:...`) | the image argument |
| `command` | Container command; split into argv, becomes the container `Cmd` | command after the image |
| `docker_ports` | Array of `[hostIp:]hostPort:containerPort[/protocol]` | `-p` |
| `docker_volumes` | Array of bind strings (`/host:/container:rw`) | `-v` |
| `docker_network` | `host`, `bridge`, `none`, or a network name | `--network` |
| `resource_limit.cpu` | Fractional CPU cores (e.g. `0.5`), mapped to `NanoCPUs` | `--cpus` |
| `metadata` | A full Docker create-request body merged into the container definition | anything Docker supports |

`metadata` is the power channel: any field of the Docker Engine
`POST /containers/create` body (for example `User`, `Entrypoint`, `Labels`,
or any `HostConfig` key such as `PortBindings`, `Binds`, `Memory`, devices or
ulimits) can be set directly. Merge order:

1. App Mesh forces `AutoRemove=false`, `RestartPolicy=no` and the ownership
   labels (its restart and cleanup semantics own the container);
2. application fields (`Cmd`, `Image`, `Env`, `WorkingDir`, resource limits,
   `docker_ports` / `docker_volumes` / `docker_network`) override `metadata`;
3. `metadata` provides everything else.

The container user follows the principal-bound `execution_user` (mapped to
the Docker `User` field) unless `metadata.User` overrides it — use
`metadata.User` for `uid:gid` spellings.

## How App Mesh talks to Docker

The built-in agent owns the Docker conversation: it embeds the official
Docker Go client and drives the Docker Engine API directly (create, start,
stop, logs, exec, image pull, events). The daemon keeps the run-state
machine and calls the agent over a PSK-signed loopback channel; no `docker`
CLI is involved and no shell parses Docker output. The agent uses
`DOCKER_HOST` when set and the local socket otherwise, so a podman
compatibility socket (`podman system service`) or a remote engine needs no
extra configuration.

Docker is off where it cannot run: the container service, the events push,
and image pulls only activate when `Docker.Enable` is true (the default) and
an endpoint exists. Set `Docker.Enable: false` to also exclude a node that
has a socket; the daemon then refuses container applications with a clear
error, and the `APPMESH_DOCKER_Enable` environment variable overrides the
setting for both processes. The container service itself answers only the
local daemon: the agent verifies the peer address (loopback or its own
listen address) before the PSK proof, mirroring the daemon's internal-route
transport gate.

Container exits are delivered by an agent subscription to Docker events: a
dying container reports its exit immediately instead of waiting for the next
scheduler poll. Polling stays armed as a fallback; it takes over if the
event markers stop arriving (for example during an agent restart), and a
low-frequency backstop inspect keeps flowing even while markers are fresh so
a die event lost in a reconnect gap cannot stall a run.

## Images and registries

- A missing image is pulled automatically through the Docker Engine API
  before the container starts (`APP_DOCKER_IMG_PULL_TIMEOUT`, default 300 s,
  bounds it). Pull progress belongs to the intermediate pull run: with
  `stdout_backup_count >= 1` it is preserved as the previous run's output
  (read it back with `stdout_index=1`), otherwise the container run's output
  replaces it, matching how a fresh start replaces previous output.
- Private registries: provide credentials as secured environment values —
  `APP_DOCKER_REGISTRY_SERVER`, `APP_DOCKER_REGISTRY_USER`,
  `APP_DOCKER_REGISTRY_PASSWORD` in `secret_env`. They are used for the
  image pull only: they never appear in the container environment, in
  application views, or in logs.
- On-demand runs (below) require the image to be present locally — they
  never pull. Register the application (or pre-pull) first.

## Health

Health semantics come straight from the container; the host is never probed:

- **Image HEALTHCHECK wins.** If the image defines a `HEALTHCHECK`, App Mesh
  reads the verdict Docker already maintains (`healthy` / `unhealthy`;
  `starting` counts as healthy during the start period). Docker executes the
  probe; App Mesh never re-executes it. An explicit `health_check_cmd` is
  bypassed in that case (logged), so the probe is never duplicated.
- **No image HEALTHCHECK**: `health_check_cmd` is executed *inside* the
  container (via the exec API), exit code 0 = healthy.
- Neither defined: no health semantics; the application keeps its current
  health state.
- A container that cannot be reached is marked unhealthy (fail-closed).

In application views `health` is `0` = healthy, `1` = unhealthy. Health
drives `depends_on` gating and appears in events (`HEALTH_CHANGE`).

## Lifecycle

- **Restart = fresh container.** Every start removes any previous container
  of this application and creates a new one; nothing carries over. Restart
  policy is owned by App Mesh's application `behavior`, not by Docker.
- **Graceful stop.** Disabling, deleting or timing out an application sends
  SIGTERM with a grace period (`stop_grace_period`, default 10 s, like
  `docker stop`) and SIGKILL only after the grace; the container is then
  removed deterministically.
- **Exit codes** are the container's real exit code, readable in the
  application view and in restart/exit policies.
- **Crash leftovers self-heal**: containers are named `appmesh-<application>`
  and labeled `appmesh.managed` / `appmesh.app`; a restart cleans up its own
  leftovers by label and can never delete a foreign container that happens to
  share the name (start refuses with a clear error instead). On daemon
  startup, labeled containers whose application no longer exists are reported
  as orphans; set `APPMESH_DOCKER_ORPHAN_SWEEP=delete` in the daemon
  environment to also remove them.

## Logs and output

`GET /appmesh/app/{name}/output` (or `appm view -a <name> -o`) tails the
container's combined stdout/stderr. The `X-Output-Position` cursor is a nanosecond
timestamp: pass it back as `stdout_position` to read increments without
duplicates. Output stays readable after the container exits, until the next
start removes it.

## Run tasks

The on-demand run APIs (`POST /appmesh/app/run`, `syncrun`, the SDK `run_*`
methods) accept Docker applications:

```shell
appm run --docker-image alpine:latest -c "sh -c 'echo hi; exit 3'"   # returns output + exit code 3
```

The run creates a temporary application, starts the container, streams its
output and reports the container's exit code. The image must exist locally
(on-demand runs do not pull). Workflow steps use the same mechanism — a step
with `docker_image` runs its command in a container of that image.

## Limits

- Docker applications are not supported on Windows daemon hosts.
- The agent needs a reachable Docker endpoint: the local socket or
  `DOCKER_HOST`.
- `stdout_backup_count` is ignored for Docker applications (output is read
  from the container, not rotated files).
- `resource_limit` maps to `Memory` / `MemorySwap` / `CpuShares`; for other
  knobs use `metadata.HostConfig`.
