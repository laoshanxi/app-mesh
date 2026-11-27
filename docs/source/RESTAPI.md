# REST API

## Source of truth

The normative API description is `src/daemon/rest/openapi.yaml`
([browse interactively](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/rest/openapi.yaml)).
App Mesh is an OAuth protected resource: except for discovery/readiness
endpoints, requests use an OAuth access token in the
`Authorization: Bearer` header.

## Discovery and authentication

| Method | URI | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| GET | `/appmesh/auth/config` | Public issuer, audience, client, and flow hints; advertises `"refresh_token": false` when refresh tokens are disabled |
| GET | `/oauth/callback` | Static OAuth callback relay page |
| POST | `/appmesh/auth/enroll-first-admin` | Enroll the first built-in App Mesh administrator |
| GET | `/appmesh/logo.svg` | Branding logo for the authentication-service login page |
| GET | `/appmesh/favicon.png` | Branding favicon for the authentication-service login page |

## Principals, roles, and permissions

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/principal/self` | Current verified principal and App Mesh authorization |
| GET | `/appmesh/principal/self/permissions` | Current principal effective permissions |
| GET | `/appmesh/principals` | List App Mesh authorization principals |
| POST | `/appmesh/principal/{principal_id}` | Update an App Mesh principal policy; on a tombstoned principal an explicit `"status": "active"` revives it (an update without `status` is rejected) |
| DELETE | `/appmesh/principal/{principal_id}` | Delete an App Mesh authorization principal |
| GET | `/appmesh/roles` | List App Mesh roles |
| POST | `/appmesh/role/{role}` | Create or replace a role |
| DELETE | `/appmesh/role/{role}` | Delete an unused role |
| GET | `/appmesh/permissions` | List available permission identifiers |
| POST | `/appmesh/security/apikeys` | Issue a request-signing API key for the caller; an administrator may pass `{"principal": "<id>"}` in the body to issue for another principal. The response contains the secret exactly once |
| GET | `/appmesh/security/apikeys` | List the caller's request-signing API keys; `?all=1` lists all keys and needs the `principal-list` permission. Secrets are never returned |
| DELETE | `/appmesh/security/apikey/{key_id}` | Revoke a request-signing API key. The key owner or the `principal-set` permission may revoke |

`X-Target-Host` forwarding (cluster requests, `-F <node>` in the CLI) requires the `host-forward` permission on the authenticated principal; both the Engine and the Go agent reject a forward without it with 403. The packaged `appmesh-admin` role carries it, viewer/guest roles do not.

A principal policy accepts `sandbox: {"mode": "off" | "write" | "strict"}`: the
file system sandbox of the applications that Principal owns. An empty mode removes
the override. See [Application sandbox](Sandbox.md).

## Applications

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/applications` | List visible applications |
| GET | `/appmesh/app/{name}` | Get an application |
| PUT | `/appmesh/app/{name}` | Register or update a non-system application |
| DELETE | `/appmesh/app/{name}` | Delete a non-system application |
| POST | `/appmesh/app/{name}/enable` | Enable a non-system application |
| POST | `/appmesh/app/{name}/disable` | Disable a non-system application |
| GET | `/appmesh/app/{name}/output` | Read application output |
| GET | `/appmesh/app/{name}/output/stream` | Stream application output over server-sent events |
| GET | `/appmesh/app/{name}/health` | Get application health |

### Application field notes

- `permission` — share bits `<other><group>` (1 deny, 2 read, 3 write; `0` = everyone full access). When the field is omitted the application is registered **owner-only** (`11`); pass `0` explicitly to open it to every principal.
- `stdout_backup_count` — output files kept per application across restarts (default `0`: each start replaces the previous run's output). Ignored (with a warning) for Docker applications: their output is fetched from the container, not rotated files.
- `daily_limitation.daily_start` / `daily_end` — seconds since UTC midnight (integers).
- `sandbox_mode` / `sandbox_workdir` — read-only runtime fields of native applications: the file system sandbox of the current or next run (`off`, `write`, `strict`) and its private workspace. A definition that sets `working_dir` is rejected with `400` while the sandbox mode of its owner is not `off`.
- An application whose `end_time` is in the past, or whose `interval` is not a positive duration, is rejected with `400`.

Applications use `owner_principal_id`; REST input cannot create
`system: true` applications or choose an arbitrary process user.

`PUT /appmesh/app/{name}` takes the application name from the request body.
The name in the URI must match it; a mismatch or a missing body name is
rejected with 400. Time fields such as `start_time` and `end_time` are
epoch seconds; other formats are rejected.

### Docker applications

Set `docker_image` to run the application as a container instead of a host
process. The container Cmd comes from `command`; the container name is
`appmesh-<application name>` (the application name must therefore start with
a letter or digit, per Docker container name rules) and every container is
labeled `appmesh.managed=true` and `appmesh.app=<application name>`: cleanup
only ever deletes containers carrying those labels, never a foreign container
that merely shares a name.

Common wiring is a first-class field, using the `docker run` spelling:

| Field | Meaning |
|---|---|
| `docker_ports` | Array of `[hostIp:]hostPort:containerPort[/protocol]`, compiled into `HostConfig.PortBindings` |
| `docker_volumes` | Array of bind strings (`/host:/container:rw`), compiled into `HostConfig.Binds` |
| `docker_network` | `host`, `bridge`, `none` or a network name, compiled into `HostConfig.NetworkMode` |

The agent's container service is the only Docker backend: the built-in agent
embeds the official Docker Go client, and the daemon drives it over a
PSK-signed loopback channel (no docker CLI involved). Common flags belong in
the first-class fields above, everything else in `metadata`.

`metadata` remains the full-power channel: it is merged into the Docker
create request body, so any Docker field (including `User`, `Entrypoint`,
`Labels`, `HostConfig`) can be set directly. Merge order: daemon-forced keys
(`AutoRemove=false`, `RestartPolicy=no`, the ownership labels) > application
fields (`Cmd`, `Image`, `Env`, `WorkingDir`, resource limits, the first-class
wiring above) > `metadata`. The container `User` follows the principal-bound
`execution_user` unless `metadata.User` overrides it.

Lifecycle semantics:

- A missing image is pulled by the agent through the Docker Engine API — the daemon needs no docker CLI and no docker socket of its own. Container exits arrive through the agent's Docker-events subscription (polling stays armed as a fallback). Registry credentials for private registries come from `secret_env` as `APP_DOCKER_REGISTRY_SERVER`, `APP_DOCKER_REGISTRY_USER` and `APP_DOCKER_REGISTRY_PASSWORD`; they never reach the container environment or the logs. `APP_DOCKER_IMG_PULL_TIMEOUT` (default 300 s) bounds the pull.
- Stopping sends SIGTERM first (`stop_grace_period`, default 10 s like `docker stop`) and SIGKILL only after the grace; the container is then removed deterministically.
- `health_check_cmd` runs **inside the container** (via the exec API); a channel failure marks the application unhealthy rather than probing the host. When the image defines a HEALTHCHECK, App Mesh reads the verdict Docker already maintains instead and bypasses `health_check_cmd` — the probe is never executed twice.
- Output is fetched from the container log; the `X-Output-Position` cursor is a nanosecond timestamp of the newest delivered line, so incremental reads never duplicate lines.
- Restart means a fresh container: the previous container is removed and re-created (no state carry-over).
- `Docker.Enable` (daemon config, hot-reloaded, default true; `APPMESH_DOCKER_Enable` overrides): false keeps the container service, the events push and image pulls off the node, and the daemon refuses container applications with a clear error.
- `Docker.HostSecurityPolicy` (daemon config, hot-reloaded): `off` (default) / `audit` (log) / `enforce` (reject) for high-risk container settings (privileged, pid=host, binds of `/` or the Docker socket, CapAdd SYS_ADMIN/SYS_PTRACE).
- `resource_limit.cpu` (fractional cores) maps to container `NanoCPUs` alongside `memory_mb`/`memory_virt_mb`/`cpu_shares`.
- On-demand runs (`/appmesh/app/run`, `syncrun`) support Docker applications: the run starts the container, streams its output and reports the container exit code. The image must exist locally — an on-demand run never pulls (register the application to pull first). Windows hosts reject Docker applications.
- On daemon start, labeled containers whose application no longer exists are logged as orphans; set `APPMESH_DOCKER_ORPHAN_SWEEP=delete` in the daemon environment to remove them.
- `Sandbox.Enable` and `Sandbox.Mode` (daemon config, hot-reloaded): the file system sandbox of native applications and its node default mode (`off` / `write` / `strict`). `APPMESH_Sandbox_Enable` and `APPMESH_Sandbox_Mode` override them.

## Run and tasks

| Method | URI | Purpose |
|---|---|---|
| POST | `/appmesh/app/run` | Start an asynchronous command |
| POST | `/appmesh/app/syncrun` | Run a command synchronously |
| POST | `/appmesh/app/{name}/task` | Send a task request to a managed application |
| GET | `/appmesh/app/{name}/task` | Fetch the next task payload for a managed application process |
| PUT | `/appmesh/app/{name}/task` | Return the task result from a managed application process |
| DELETE | `/appmesh/app/{name}/task` | Cancel the pending task request for a managed application |
| POST | `/appmesh/app/{name}/task/stream` | Send a task request and stream partial results (SSE) |
| POST | `/appmesh/app/{name}/task/partial` | Push an incremental task result (worker RPC) |
| POST | `/appmesh/app/{name}/input` | Inject bytes into the stdin of a pipe-stdin application |

The streaming routes answer `text/event-stream` frames (partials, final
result, terminal status). The engine serves them natively (default
wss/https 6063), and the agent REST listener (6060) relays them for local
requests; they do not traverse node forwarding. See
[Streaming.md](Streaming.md)
for the event contract, the stdin pipe mode, and the SDK generator APIs.

The built-in LLM agent is driven through these task routes: `POST .../task` with
a `session_send` / `session_close` JSON payload, `POST .../task/stream` for its
live partials. The payload and the reply envelope are documented in the
[llm-agent README](https://github.com/laoshanxi/app-mesh/blob/main/src/apps/llm-agent/README.md#wire-protocol-run_task-payload).

### Client disconnect during `syncrun`

`syncrun` replies when the command finishes. The engine stops the on-demand run
if the waiting client disconnects. This cleanup needs a direct connection to the
REST listener. The agent port and the CLI/WebSocket transports multiplex
requests over one connection. The engine cannot observe the client disconnect
there. The run then continues until it finishes or reaches its timeout.

## Event subscription

| Method | URI | Purpose |
|---|---|---|
| POST | `/appmesh/app/{name}/subscribe` | Subscribe to events from one application |
| DELETE | `/appmesh/app/{name}/subscribe` | Remove an event subscription |
| POST | `/appmesh/subscribe` | Subscribe to events from all applications |
| DELETE | `/appmesh/subscribe` | Remove an event subscription |

## Files, labels, and configuration

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/file/download` | Download a file |
| POST | `/appmesh/file/upload` | Upload a file |
| DELETE | `/appmesh/file/delete` | Delete a file (guarded by the dedicated file-delete permission) |
| GET | `/appmesh/labels` | List host labels |
| PUT | `/appmesh/label/{label}` | Set a host label |
| DELETE | `/appmesh/label/{label}` | Delete a host label |
| GET | `/appmesh/config` | Get runtime configuration |
| POST | `/appmesh/config` | Update runtime configuration |

### File transfer notes

- `X-File-Path` must be absolute; `X-File-Mode` is the **decimal** file mode (for example `493` for `0755`), matching the `st_mode` convention used by the SDKs. A value outside `0..511` (for example the octal digits `"755"`) is ignored on every transport — the file keeps its default mode; it is never masked.
- Uploads never overwrite by default: an existing destination returns `409`. Send `X-File-Overwrite: true` to replace it (the new content is published atomically).
- `DELETE /appmesh/file/delete` removes one regular file named by `X-File-Path` under its own `file-delete` permission (independent of `file-upload`); a missing file returns `404`, a directory or anything else is refused.
- The daemon's own installation tree (the directory that holds `bin/`, `ssl/`, `config/`, `script/` and `work/`, for example `/opt/appmesh`) is refused on both directions regardless of `REST.FileAllowedBaseDir`; symbolic links into it are resolved before the check. The `work/share` and `work/workspaces` subtrees inside it are the only exchangeable exception.
- An unset `REST.FileAllowedBaseDir` (the packaged default) jails transfers to the daemon's work directory tree (`BaseConfig.WorkingDirectory`, `/opt/appmesh/work` by default). Combined with the installation-tree exclusion above, the exchangeable default is the `work/share` and `work/workspaces` area. Set the option to an absolute path to allow transfers in another tree; every absolute path outside the jail is refused for download, upload, and delete.
- Pseudo filesystems (`/proc`, `/sys`, `/dev`) are refused on every transfer: their files stat as regular size-0 files and would otherwise download as empty `200` bodies.
- The work directory layout behind these rules is specified in [WorkDir.md](WorkDir.md).

## Resources and metrics

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/resources` | Get host resources |
| GET | `/appmesh/metrics` | Get Prometheus metrics |
| GET | `/metrics` | Get Prometheus metrics |

The host resource document carries a `sandbox` object: `enabled` (`Sandbox.Enable`), `mode` (the node default), `supported` (the kernel provides Landlock) and `abi` (the Landlock ABI version, `0` when unsupported).

## Response headers

- CORS is opt-in: the Engine sends `Access-Control-Allow-Origin` only by echoing a request `Origin` listed in `REST.CorsAllowOrigins`. With the default empty list no CORS headers are sent at all (the UI is a same-origin proxy and needs none).
- Every REST response carries `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. The API serves JSON/files, never active content, so the policy has no functional side effects.

## Out of scope

There are no Engine endpoints for username/password login, token renewal,
logout/blacklist, TOTP, directory users, password changes, groups, or upstream
identity-provider administration. Those operations belong to the
authentication service or its operator-managed upstream identity provider.

## Related

- [Authentication](Authentication.md) — OAuth flows and a worked Python SDK example
- [Event subscription](EventSubscription.md)
- [Build App Mesh](Build.md) — build guidance and integrations
