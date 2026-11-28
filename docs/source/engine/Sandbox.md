# Application Sandbox

This document is the single specification of the App Mesh application sandbox. The daemon, the REST API, the SDKs and the other documentation must agree with it.

The sandbox limits the file access of a native application process with Linux Landlock. The sandbox is disabled by default. A container application (`docker_image`) is isolated by Docker and does not use the sandbox.

## 1. Modes

| Mode | Writes | Reads |
|---|---|---|
| `off` | unrestricted | unrestricted |
| `write` | the application workspace and `work/share` | unrestricted |
| `strict` | the application workspace and `work/share` | the read baseline (section 5) |

In every mode the application can execute programs, use the network, and call `stat`, `chdir`, `chmod`, `chown`, `utime`, and `setxattr`.

## 2. Policy

An application definition has no sandbox field. The policy comes from the node and from the Principal. An application cannot switch the sandbox on, off, or to a weaker mode.

Node level in `config.yaml`:

```yaml
Sandbox:
  Enable: false
  Mode: "off"
```

| Key | Default | Meaning |
|---|---|---|
| `Sandbox.Enable` | `false` | Master switch. The value must be a boolean. `false` sets every application to mode `off`. |
| `Sandbox.Mode` | `off` | Node default mode for applications whose owner sets no mode: `off`, `write`, or `strict`. An unknown value keeps the previous mode and logs a warning. |

Principal level in `authorization.yaml` or through `POST /appmesh/principal/{principal_id}`:

```yaml
sandbox:
  mode: "write"
```

`sandbox.mode` of a Principal replaces the node default for the applications of that Principal. An empty mode removes the override. `off` is a valid choice for a trusted Principal.

The effective mode of an application is:

| Application | Effective mode |
|---|---|
| Container application (`docker_image`) | `off` |
| System application | `off` |
| Native application | `sandbox.mode` of its owner, else the node `Mode` |
| On-demand run of an existing application | the stricter of the caller mode and the base application owner mode |

Both settings hot-reload. A change applies to the next start of each application.

Environment variables `APPMESH_Sandbox_Enable` and `APPMESH_Sandbox_Mode` override the two keys. The active `config.yaml` must contain the `Sandbox` section for them.

## 3. Workspace

Each sandboxed application gets one private workspace. [WorkDir.md](WorkDir.md) specifies the layout.

| Path | Mode | Owner | Content |
|---|---|---|---|
| `work/workspaces/` | 0711 | daemon | Root of all workspaces |
| `work/workspaces/<principal>/` | 0711 | daemon | Workspaces of one Principal |
| `work/workspaces/<principal>/<application>/` | 0700 | execution user | Working directory of the application, with `tmp/` inside |

`<principal>` is the first 16 hexadecimal characters of the SHA-256 digest of the Principal ID.

Which workspace a run uses:

- A registered application uses `workspaces/<owner>/<application>`.
- An on-demand run of an existing application uses `workspaces/<caller>/<base application>`. Runs of one base application by one Principal share that workspace.
- An anonymous run uses a temporary workspace `workspaces/<caller>/<generated name>`.

The Engine sets `TMPDIR=<workspace>/tmp` and `HOME=<workspace>`. An `env` entry of the application overrides both variables.

The workspace is the only private area an application can write. An application that must exchange files with other applications uses `work/share`. `work/share` is a node-wide exchange area: every sandboxed application can read and write it. Do not store secrets in it.

### Ownership

The Engine gives the workspace to the execution user. When the execution user of an application changes, the Engine changes the owner of the workspace and of every file in it. The parent directories stay owned by the daemon and are traverse-only.

### Lifecycle

| Event | Result |
|---|---|
| An anonymous run ends and its application is removed | Its temporary workspace is deleted. |
| A run instance is removed | The workspace is kept. It is shared with the base application. |
| An application is deleted | Every workspace named after the application is deleted: its own, and the workspaces of its on-demand runs under every caller. |
| An application is replaced or re-registered with the same name | The workspace is kept. |
| A Principal is deleted | `workspaces/<principal>/` is deleted. |
| A Principal directory is left empty | It is deleted. |

The workspace is deleted after the application stopped and outside the application mutation lock.

## 4. Requirements

A sandboxed application starts only when all these conditions are true. A rejected start sets `last_error` of the application. An on-demand run answers `400` with the reason.

1. The kernel supports Landlock. See section 6.
2. The application process runs as a non-root user. A root daemon requires a non-root `execution_user` or `BaseConfig.DefaultExecUser`.
3. `working_dir` is empty. Registration rejects a definition that sets `working_dir`. A recovered definition with `working_dir` stays registered and refuses to start.
4. Mode `strict` is not combined with a `session_login` user switch. `sudo` cannot read its configuration under the read baseline.
5. An unprivileged daemon does not combine any mode with a `session_login` user switch. See `no_new_privs` below.
6. `Sandbox.Enable` is `true`. Otherwise the mode is `off` and none of these conditions applies.

`no_new_privs`: the sandbox always sets `no_new_privs` on the application process. Setuid binaries and file capabilities gain no privilege inside the sandbox. A root daemon starts `sudo` for `session_login` as root and still switches users. An unprivileged daemon cannot: `sudo` cannot elevate under `no_new_privs`.

### Health check

`health_check_cmd` of a sandboxed application runs as the execution user inside the same sandbox. A probe that the policy refuses marks the application unhealthy.

## 5. Read baseline of strict mode

`strict` permits reads of the application workspace, of `work/share`, and of these paths. An absent path is skipped.

- `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`
- `/etc/ld.so.cache`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d`
- `/etc/ssl/certs`, `/etc/ssl/openssl.cnf`
- `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`, `/etc/passwd`, `/etc/group`, `/etc/localtime`
- `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`
- `/proc`
- The shell script of the application

Every mode permits writes to `/dev/null`.

## 6. Kernel support

| Kernel | Landlock ABI | Behavior |
|---|---|---|
| 5.13 and later | 1 | Writes are confined. A rename or link between the workspace and `work/share` fails. |
| 5.19 and later | 2 | A rename or link between the workspace and `work/share` is permitted. |
| 6.2 and later | 3 | `truncate` is confined also. |

On Landlock ABI 1 and 2, `truncate` is controlled by file permissions only. On a kernel without Landlock, and on macOS and Windows, an application with a mode other than `off` does not start.

## 7. Visibility

`GET /appmesh/resources` returns the capability of the host:

```json
"sandbox": {"enabled": false, "mode": "off", "supported": true, "abi": 3}
```

- `enabled` is `Sandbox.Enable`; `mode` is the node default.
- `supported` and `abi` describe the kernel. `abi` is `0` when Landlock is not available.

The application view returns two read-only fields for native applications:

- `sandbox_mode`: `off`, `write`, or `strict`. A running application reports the mode of its current process. An idle application reports the mode of its next start.
- `sandbox_workdir`: present when `sandbox_mode` is not `off`.

## 8. Limits

- A container application is not confined by the sandbox mode of its Principal. Set `Docker.HostSecurityPolicy` to `enforce` to reject host-facing container settings.
- The file API runs in the daemon and is not sandboxed. A Principal with file permissions can read, overwrite, and delete files in any workspace.
- `strict` permits reads of `/proc`. Process metadata of the host stays visible.
- `strict` does not permit reads of application files outside the read baseline, for example files under `/opt` or the home directory of the execution user. Copy them into the workspace or into `work/share`.
- `/tmp` and `/dev/shm` are not writable. Applications use `TMPDIR`.
- Landlock ABI 1 does not permit a rename or link between the workspace and `work/share`. Copy the file instead.
- A daemon restart keeps the sandbox of a running process. The application reports the mode of the policy at restart time, not the mode of its start.

## 9. Clients that send working_dir

A sandboxed application cannot set `working_dir`. A client that sends `working_dir` receives `400` while the sandbox mode of its Principal is not `off`. This applies to `appm run`, to the remote sandbox, and to the web shell. Keep `sandbox.mode` at `off` for the Principals that use them, or drop `working_dir` from the request and upload files into `sandbox_workdir`.
