# Work Directory Specification

This document is the single specification for the App Mesh work directory layout and for the life time of every file below it. The daemon, the file API, the Go agent, installers and the other documentation must agree with it.

## 1. Layout rules

- The work directory is `BaseConfig.WorkingDirectory`; the default is `/opt/appmesh/work`.
- Directories are split by responsibility: daemon-private state and a shared exchange area.
- `runtime/` holds daemon-private state only. Applications reach their stdout, stdin and shell scripts through file descriptors, never by path.
- `share/` is the only cross-application data area and the default application working directory.
- Execution users must be able to traverse the work directory and `runtime/`. The daemon re-applies the traverse bits at startup.

## 2. Directories

| Path | Mode | Purpose | File API |
|---|---|---|---|
| `config/` | 0700 | Configuration overrides, keys | Refused |
| `apps/` | — | Application YAML definitions | Refused |
| `auth/` | — | Authentication and authorization state | Refused |
| `runtime/` | 0711 | Daemon-private state root; daemon working directory | Refused |
| `runtime/stdout/` | 0700 | Application output files | Refused |
| `runtime/stdin/` | 0700 | Transient stdin files | Refused |
| `runtime/shell/` | 0711 | Generated shell scripts | Refused |
| `runtime/uploads/` | 0700 | HTTP upload cache | Refused |
| `runtime/.snapshot` | 0600 | High-availability snapshot | Refused |
| `share/` | 1777 sticky | Shared exchange area; default application working directory | Allowed |

Every directory is owned by the daemon user, except the application workspace, which is owned by its execution user. Modes are POSIX; Windows installs keep the default access rules.

## 3. Where an application runs

- An application without `working_dir` runs in `share/`.
- An application with `working_dir` runs in that directory.
- An application inherits the environment of the daemon process, plus its `env` entries.
- An on-demand run of an existing application uses the workspace named after the base application. An anonymous on-demand run gets a temporary workspace.
- The daemon process runs with `runtime/` as its working directory. `runtime/` sits two levels below the install root, so `../../script/...` paths in managed application commands keep resolving.
- The Go agent stages file transfers under `share/` and also runs there.

## 4. Life time

### 4.1 Files of an application

| Artifact | Path | Created | Removed |
|---|---|---|---|
| Definition | `apps/<application>.yaml` | Registration or update of a persistent application | When the application is deleted |
| Output | `runtime/stdout/appmesh.<application>.out`, with `.1` … `.N` and `.bak` | Every start | When the application is deleted |
| Shell script | `runtime/shell/appmesh.<application>.<id>.sh` | Start of a `shell` or `session_login` application | When the application stops using the script, or at daemon start |
| Launch stdin | `runtime/stdin/appmesh.<run>.stdin` | Start of an application with `metadata` | When the run ends, or at daemon start |

- On-demand run applications are not persistent. Their files follow the same rules and are removed when the run application is removed.
- Output files survive a daemon restart. `stdout_backup_count` sets how many earlier outputs are kept.
- Re-registering an application with the same name replaces the definition and keeps the output files and the workspace.
- A container application writes its output to the same output files.
- The daemon never removes a file in `share/`. An application that writes into `share/` leaves its files there after it is deleted.

### 4.2 Directories without application data

| Path | Life time |
|---|---|
| `config/` | Managed by the operator. The daemon adds its runtime policy files and removes nothing. |
| `auth/` | Managed by the authentication bootstrap. The daemon removes nothing. |
| `runtime/.snapshot` | Rewritten by the daemon on every scheduler pass. |
| `share/` | Holds user data. The daemon removes nothing. |
| `workflow/` | Run history of the workflow engine. Removed when the workflow is deleted through the workflow API. |
| `server.log` | The daemon log. |

Delete a workflow through the workflow API. Deleting its definition application `workflow-<name>` through the application API keeps the run history under `workflow/`.

## 5. File transfer exchange

- With the packaged defaults, only `work/share` is exchangeable; every other path under the work directory is refused.
- An external `REST.FileAllowedBaseDir` jail keeps its behavior: the whole external tree is exchangeable, the work directory is not.
- `share/` is world-writable with the sticky bit: every execution user can create files, and each user can delete only their own files. Do not store secrets in it.
