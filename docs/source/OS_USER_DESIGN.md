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

**Docker:**

```bash
docker run -d \
  -e APPMESH_RUN_AS_ROOT=true \
  -e APPMESH_BaseConfig_DisableExecUser=false \
  -e APPMESH_BaseConfig_DefaultExecUser=appmesh \
  laoshanxi/appmesh
```

### Execution User Priority

When an application starts, the OS user is determined by:

1. The API user's `exec_user` field (if set and `DisableExecUser=false`)
2. The global `DefaultExecUser` from `config.yaml` (if set and `DisableExecUser=false`)
3. The daemon process's own OS user (final fallback)

In non-root mode, the daemon lacks permission to call `seteuid()`, so all applications run as the daemon's own user regardless of the above settings.

---

## Internals

### Installation

**Non-root package install** — the installer writes `User=`/`Group=` into the systemd service, runs `chown` on the install directory, and saves environment variables to `/opt/appmesh/appmesh.default` (loaded via systemd `EnvironmentFile`).

**Root package install** — systemd service keeps empty `User=`/`Group=` fields (systemd treats empty as root).

**Docker privilege-drop chain:**

```
tini (PID 1)
  → docker-entrypoint.sh
    → setpriv --reuid=appmesh --regid=appmesh --init-groups --no-new-privs
      → entrypoint.sh
        → exec appmesh  (runs as appmesh:482)
```

The Dockerfile pre-creates the `appmesh` user with fixed UID/GID 482 and sets `DisableExecUser=true`. When `APPMESH_RUN_AS_ROOT=true`, the `setpriv` step is skipped.

### Security

- When switching users, any `exec_user` name resolving to UID 0 is rejected; the literal username `"root"` skips user switching entirely, so the process inherits the daemon's own OS user.
- If `DisableExecUser=false` but the daemon is not running as root, a warning is logged at startup indicating that user switching will not take effect.
- In containers, numeric UID strings (e.g., `"1001"`) are accepted as valid execution users even without a corresponding `/etc/passwd` entry.

## Configuration Reference

| Config Key | Location | Default | Description |
|-----------|----------|---------|-------------|
| `APPMESH_DAEMON_EXEC_USER` | Install env var | (empty) | OS user for the daemon process; written to systemd `User=` |
| `APPMESH_DAEMON_EXEC_USER_GROUP` | Install env var | (empty) | OS group for the daemon process; written to systemd `Group=` |
| `BaseConfig.DefaultExecUser` | `config.yaml` | `""` | Global default OS user for child app execution |
| `BaseConfig.DisableExecUser` | `config.yaml` | `false` | When `true`, skip per-user resolution; all apps use daemon's user |
| `APPMESH_RUN_AS_ROOT` | Docker env var | `false` | Skip privilege drop in Docker entrypoint |
| `exec_user` | `security.yaml` per user | `""` | Per-API-user OS execution identity |

## Mode Comparison

|  | Non-Root Mode | Root Mode |
|--|---------------|-----------|
| **Daemon user** | Specified OS user | root |
| **Child app user** | Same as daemon (no switching) | Per `exec_user` / `DefaultExecUser` |
| **Package install** | Set `APPMESH_DAEMON_EXEC_USER` | Do not set (defaults to root) |
| **Docker** | Default (setpriv to appmesh:482) | `APPMESH_RUN_AS_ROOT=true` |
| **DisableExecUser** | No effect (switching unavailable) | Set `false` to enable per-user switching |
| **Security posture** | Least privilege, no escalation path | Root daemon, higher risk surface |
| **Use case** | Single-tenant, containers, CI | Multi-tenant, user isolation |
