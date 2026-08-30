# OS Execution User Design

## Overview

App Mesh separates authenticated identity from operating-system process identity:

- A **Principal** is the immutable App Mesh identity derived from a Dex token. Roles and
  permissions decide what it may do.
- An **execution user** is the Linux/macOS account under which a native child process runs.
  It does not authenticate the Principal or grant App Mesh permissions.

The optional `execution_user` policy belongs to the Principal overlay in
`authorization.yaml`. It is not stored in Dex, an upstream IdP, or a legacy Engine user record.

```text
Dex token -> (issuer, subject) -> Principal ID -> execution_user -> native child UID/GID
```

When a Principal registers or runs an application through REST, the Engine derives
`owner_principal_id` from the validated bearer, ignores a caller-supplied execution user,
and copies the Principal's configured `execution_user` into the application definition.
This prevents a caller from selecting a more privileged OS account.

Changing a Principal mapping affects newly registered/run applications. Update or
re-register existing persistent applications when their materialized execution user must
change.

## Which Mode Should I Use?

| Scenario | Recommended mode | Reason |
|----------|------------------|--------|
| Docker container | non-root (default) | one fixed UID/GID and the smallest host privilege surface |
| Single server or CI runner | non-root | application-level OS-user switching is unnecessary |
| Shared multi-tenant host | root, only when required | allows approved Principals to map to isolated OS accounts |
| Strict native process isolation | root, with explicit mappings | each approved Principal can receive a distinct non-root OS account |

## Non-Root Mode (Recommended)

The daemon runs as a regular OS user, such as `appmesh`. Native managed applications run
as that same user; per-Principal switching is unavailable when the daemon is not root.

```bash
groupadd -r appmesh && useradd -m -r -g appmesh appmesh
export APPMESH_DAEMON_EXEC_USER=appmesh
export APPMESH_DAEMON_EXEC_USER_GROUP=appmesh
dpkg -i appmesh.deb  # or rpm -ivh appmesh.rpm
```

The Docker image runs as UID/GID `482:482` and sets
`APPMESH_BaseConfig_DisableExecUser=true`. A `docker_image` application follows its
image's own `USER` declaration.

## Root Mode

A root daemon may switch native child processes to approved non-root OS accounts. Enable
switching and set a safe global fallback in `config.yaml`:

```yaml
BaseConfig:
  DefaultExecUser: "appmesh"
  DisableExecUser: false
```

Configure the Principal-to-OS-user policy in `authorization.yaml`. Principal IDs are stable
bindings to Dex issuer and subject; display names are not authorization keys.

```yaml
Authorization:
  principals:
    "<stable-principal-id>":
      kind: user
      issuer: "https://auth.example.com/dex"
      subject: "directory-subject-id"
      status: active
      execution_user: "www-data"
      roles: ["deployer"]
```

Do not put passwords, Dex client secrets, or access tokens in this file.

## Resolution and Enforcement

For REST-created applications, the effective native user is resolved as follows:

1. Validate the Dex bearer and resolve its immutable Principal.
2. Materialize the Principal overlay's `execution_user` on the application, if configured.
3. Otherwise use `BaseConfig.DefaultExecUser`, when switching is enabled.
4. Otherwise inherit the daemon process user.

Packaged System Apps are trusted installation artifacts owned by `system:appmesh`; remote
callers cannot create them. Any explicit execution-user setting in such an artifact is part
of the operator-controlled package policy, not user input.

Execution-user switching is disabled when `DisableExecUser=true` or the daemon is not
running as root. Windows does not perform Unix user switching.

## Installation and Container Behavior

- Non-root systemd and launchd installs write the selected service user/group into the
  native service definition and persist install environment in
  `/opt/appmesh/appmesh.default`.
- A root systemd install leaves `User=` and `Group=` empty.
- The Docker entrypoint verifies writable runtime paths, then replaces itself with the
  daemon. Bind-mounted runtime directories must be writable by the selected container UID.
- Docker configuration comes from process environment; it does not load
  `appmesh.default`.
- An explicit `--user 0:0` runs the container daemon as root, but user switching still
  requires `DisableExecUser=false` and the necessary container capabilities.

## Security Constraints

- A resolved execution user whose UID is 0 is rejected for child-user switching.
- The image-default UID/GID 482 inherits ownership of native managed processes when
  switching is disabled.
- Ownership remains `owner_principal_id`; an OS account name is never a resource owner or
  authorization identity.

## Configuration Reference

| Key | Location | Default | Purpose |
|-----|----------|---------|---------|
| `APPMESH_DAEMON_EXEC_USER` | install environment | empty | OS user for the daemon service |
| `APPMESH_DAEMON_EXEC_USER_GROUP` | install environment | empty | OS group for the daemon service |
| `BaseConfig.DefaultExecUser` | `config.yaml` | `""` | fallback native child user |
| `BaseConfig.DisableExecUser` | `config.yaml` | `false` | disable native child-user switching |
| `execution_user` | Principal in `authorization.yaml` | `""` | native child user materialized for that Principal's applications |
