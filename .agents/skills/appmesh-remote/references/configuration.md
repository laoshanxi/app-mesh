# Configuration

Read this reference when configuring a remote node, authentication, TLS,
synchronization excludes, or installing the skill in another repository.

## Prerequisites

- Install the App Mesh Python SDK with `pip install appmesh`.
- Provide a reachable App Mesh daemon.
- Set `APPMESH_WORKSPACE` to the remote working directory before `sync`,
  `sync-exec`, or `deploy`.

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `APPMESH_HOST` | App Mesh REST endpoint | `https://127.0.0.1:6060` |
| `APPMESH_WORKSPACE` | Remote source directory | Required for sync and deploy |
| `APPMESH_USER` | Login user | `admin` |
| `APPMESH_PASSWORD` | Login password | Development default from the SDK tool |
| `APPMESH_SSL_VERIFY` | `true`, `false`, or a CA path | `false` |
| `APPMESH_SYNC_EXCLUDE` | Extra comma-separated tar exclude patterns | Empty |

Configure real credentials explicitly. Prefer certificate verification outside
isolated development nodes, and never print passwords or private key material.

```bash
export APPMESH_HOST=https://192.168.1.100:6060
export APPMESH_WORKSPACE=/home/dev/myproject
export APPMESH_USER=admin
export APPMESH_PASSWORD='<password>'
export APPMESH_SSL_VERIFY=/path/to/ca.pem
export APPMESH_SYNC_EXCLUDE='*.o,dist/'
```

## Install in another repository

Copy the complete skill directory so its script and references remain together:

```bash
mkdir -p .agents/skills
cp -R /path/to/app-mesh/.agents/skills/appmesh-remote .agents/skills/
```

If the target does not already have a `.claude` directory, expose all shared
agent configuration with:

```bash
ln -s .agents .claude
```

If `.claude` already exists, expose only this skill:

```bash
mkdir -p .claude/skills
ln -s ../../.agents/skills/appmesh-remote .claude/skills/appmesh-remote
```
