# OS User Design

## Overview

App Mesh has two types of users:

- **API Users** control *what you can do* — login identity with password, roles, and permissions (e.g., `admin`, `mesh`, `test`). Configured in `security.yaml` or via OAuth2/Consul.
- **OS Users** control *who runs your applications* — the Linux/macOS user identity (UID/GID) under which child processes execute. Each API user can be mapped to an OS user via the `exec_user` field.

```
API User "deploy"  ──(exec_user: "www-data")──►  Applications run as OS user "www-data"
API User "admin"   ──(exec_user: "")──────────►  Applications run as DefaultExecUser or daemon user
API User "test"    ──(exec_user: "nobody")────►  Applications run as OS user "nobody"
```

### Which Mode Should I Use?

| My Scenario | Recommended Mode | Why |
|-------------|-----------------|-----|
| Docker container | **Non-root** (default) | Simple and secure, no configuration needed |
| Single server, one team | **Non-root** | All apps share one OS user, minimal attack surface |
| CI runner / automation | **Non-root** | No need for user isolation |
| Multi-tenant, shared host | **Root** | Different teams' apps run as different OS users |
| Strict process isolation required | **Root** | Each API user maps to a separate OS user |

### Non-Root Mode (Recommended)

The daemon runs as a regular OS user (e.g., `appmesh`). All applications run as that same user regardless of `exec_user` settings. This is the simplest and most secure setup.

**Package install:**

```bash
# Create user and install
groupadd -r appmesh && useradd -m -r -g appmesh appmesh
export APPMESH_DAEMON_EXEC_USER=appmesh
export APPMESH_DAEMON_EXEC_USER_GROUP=appmesh
dpkg -i appmesh.deb  # or rpm -ivh appmesh.rpm
```

**Docker:** Works out of the box, no configuration needed.

```bash
docker run -d laoshanxi/appmesh
```

### Root Mode

The daemon runs as root and can switch to different OS users when spawning applications. Configure `DefaultExecUser` for a global default, and optionally set `exec_user` per API user for fine-grained control.

**Package install:**

```bash
# Install without specifying a daemon user (defaults to root)
dpkg -i appmesh.deb
```

Then configure user mapping:

```yaml
# config.yaml
BaseConfig:
  DefaultExecUser: "appmesh"   # Fallback OS user
  DisableExecUser: false       # Enable per-user switching

# security.yaml
Users:
  admin:
    exec_user: ""              # Uses DefaultExecUser → appmesh
  deploy:
    exec_user: "www-data"      # deploy's apps run as www-data
  test:
    exec_user: "nobody"        # test's apps run as nobody
```

Container images default to non-root mode. An explicit `--user 0:0` override runs
the daemon and native managed applications as root. OS-user switching additionally
requires `DisableExecUser=false` and the required container capabilities.

### Execution User Priority

When an application starts, the OS user is determined by:

1. The API user's `exec_user` field (if set and `DisableExecUser=false`)
2. The global `DefaultExecUser` from `config.yaml` (if set and `DisableExecUser=false`)
3. The daemon process's own OS user (final fallback)

Execution-user switching is disabled when `DisableExecUser=true` or the daemon's
current UID is non-zero. This is a platform rule, not a container check, so all
applications in non-root mode run as the daemon's own user.

The Docker image runs as UID/GID `482:482` and sets
`APPMESH_BaseConfig_DisableExecUser=true`. The normal environment override path
keeps that value authoritative during startup, SIGHUP reloads, and REST updates;
there is no container-specific execution-user policy in C++. A `docker_image`
application is separate and follows its image's own `USER` declaration.

---

## Internals

### Installation

**Non-root package install** — on systemd and launchd, the installer writes the service user/group into the native service definition, runs `chown` on the install directory, and saves environment variables to `/opt/appmesh/appmesh.default`. systemd loads it with `EnvironmentFile`, init.d (which remains root-managed) parses and exports its entries before startup, launchd receives the same values through its native `EnvironmentVariables` dictionary, and Docker uses its process environment. Native service managers execute `bin/appmesh` directly.

**Root package install** — systemd service keeps empty `User=`/`Group=` fields (systemd treats empty as root).

**Docker startup chain:**

```
tini (PID 1)
  → docker-entrypoint.sh
    → appmesh  (482:482 by default, or an explicit root override)
```

The Dockerfile selects the pre-created `appmesh` user with fixed UID/GID 482, sets `APPMESH_BaseConfig_DisableExecUser=true`, and makes the complete `/opt/appmesh` tree owned by that identity. The Docker-only entrypoint verifies writable runtime paths, handles initialization and startup-command arguments, then replaces itself with `bin/appmesh`. An explicit `--user` override works when that identity can write the mounted runtime directories. Docker configuration comes from the inherited process environment; it does not load `appmesh.default`. Bind mounts that replace image directories must be writable by the selected identity.

Configuration persistence writes a temporary file in `work/config` and atomically
replaces the destination while preserving its mode. This supports readable files
copied into a UID-482-owned directory; single-file bind mounts are not writable
configuration targets because container runtimes do not permit replacing them.

### Security

- When switching users, any `exec_user` name resolving to UID 0 is rejected; the literal username `"root"` skips user switching entirely, so the process inherits the daemon's own OS user.
- If `DisableExecUser=false` but the daemon is not running as root, a warning is logged and user switching is disabled at runtime.
- With the image-default `DisableExecUser=true`, native managed applications inherit UID/GID 482; uploads keep the daemon owner and owner-read permission, and runtime-copied files must be readable by UID 482.
- In containers, Fixed 482:482 (appmesh) are used as valid execution users even without a corresponding `/etc/passwd` entry.

## Configuration Reference

| Config Key | Location | Default | Description |
|-----------|----------|---------|-------------|
| `APPMESH_DAEMON_EXEC_USER` | Install env var | (empty) | OS user for the daemon process; written to systemd `User=` or launchd `UserName` |
| `APPMESH_DAEMON_EXEC_USER_GROUP` | Install env var | (empty) | OS group for the daemon process; written to systemd `Group=` or launchd `GroupName` |
| `BaseConfig.DefaultExecUser` | `config.yaml` | `""` | Global default OS user for child app execution |
| `BaseConfig.DisableExecUser` | `config.yaml` | `false` | When `true`, skip per-user resolution; non-root daemons also disable it automatically at runtime |
| `exec_user` | `security.yaml` per user | `""` | Per-API-user OS execution identity |

## Mode Comparison

|  | Non-Root Mode | Root Mode |
|--|---------------|-----------|
| **Daemon user** | Specified OS user | root |
| **Child app user** | Same as daemon (no switching) | Per `exec_user` / `DefaultExecUser` |
| **Package install** | Set `APPMESH_DAEMON_EXEC_USER` | Do not set (defaults to root) |
| **Docker** | Default `482:482` (`appmesh`) | Explicit `--user 0:0` |
| **DisableExecUser** | No effect (switching unavailable) | Set `false` to enable per-user switching |
| **Security posture** | Least privilege, no escalation path | Root daemon, higher risk surface |
| **Use case** | Single-tenant, containers, CI | Multi-tenant, user isolation |
