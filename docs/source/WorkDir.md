# Work Directory Specification

This document is the single specification for the App Mesh work directory layout. The daemon, the file API, the Go agent, installers and the documentation must agree with it.

## 1. Layout rules

- The work directory is `BaseConfig.WorkingDirectory`; the default is `/opt/appmesh/work`.
- Directories are split by responsibility: daemon-private state, shared exchange, per-principal workspaces.
- `runtime/` holds daemon-private state only. Applications reach their stdout, stdin and shell scripts through file descriptors, never by path.
- `share/` is the only cross-application data area and the default application working directory.
- `workspaces/` is reserved for the planned Landlock sandbox. It is created, but currently unused.

## 2. Directories

| Path | Mode | Purpose | File API |
|---|---|---|---|
| `config/` | 0700 | Configuration overrides, keys | Refused |
| `apps/` | — | Application YAML definitions | Refused |
| `auth/` | — | Authentication and authorization state | Refused |
| `runtime/` | 0711 | Daemon-private state root; daemon working directory | Refused |
| `runtime/stdout/` | 0700 | Application stdout files | Refused |
| `runtime/stdin/` | 0700 | Transient stdin files | Refused |
| `runtime/shell/` | 0711 | Generated shell scripts | Refused |
| `runtime/uploads/` | 0700 | HTTP upload cache | Refused |
| `runtime/.snapshot` | 0600 | High-availability snapshot | Refused |
| `workspaces/` | 0711 | Per-principal sandbox workspaces (reserved) | Allowed |
| `share/` | 1777 sticky | Shared exchange area; default application working directory | Allowed |

Every directory is owned by the daemon user. Modes are POSIX; Windows installs keep the default access rules.

## 3. Defaults

- An application without `working_dir` runs in `share/`.
- The daemon process runs with `runtime/` as its working directory. `runtime/` sits at the same depth as the former `work/tmp`, so `../../script/...` paths in managed app commands keep resolving.
- The Go agent stages file transfers under `share/` and also runs there.

## 4. Migration from `work/tmp`

The upgrade is automatic on the first start after the update. Each moved entry is logged; a failed move aborts the startup instead of dropping data.

| Before | After |
|---|---|
| `work/tmp` (application data, default working directory) | `work/share` |
| `work/tmp/uploads` | `work/runtime/uploads` |
| `work/tmp/.snapshot` | `work/runtime/.snapshot` |
| `work/stdout` | `work/runtime/stdout` |
| `work/stdin`, `work/shell` | Removed (transient files, rebuilt every start) |

The file transfer exchange area changes with the layout; scripts that reference `work/tmp` by absolute path must move to `work/share`.

## 5. File transfer exchange

- With the packaged defaults, only `work/share` and `work/workspaces` are exchangeable; every other path under the work directory is refused.
- An external `REST.FileAllowedBaseDir` jail keeps its behavior: the whole external tree is exchangeable, the work directory is not.
- `share/` is world-writable with the sticky bit: every execution user may create files, and each user can delete only their own files. Do not store secrets in it.
