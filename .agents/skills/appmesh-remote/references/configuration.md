# Configuration

Read this reference when configuring a remote node, authentication, TLS,
synchronization excludes, or installing the skill in another repository.

## Prerequisites

- Install the App Mesh Python SDK with `pip install appmesh`.
- Provide a reachable App Mesh daemon.
- Set `APPMESH_ACCESS_TOKEN` to a valid access token for the daemon.
- Set `APPMESH_WORKSPACE` to the remote working directory before `sync`,
  `sync-exec`, or `deploy`.

## Environment variables

| Variable | Purpose | Default |
| --- | --- | --- |
| `APPMESH_ENGINE_URL` | App Mesh REST endpoint | `https://127.0.0.1:6060` |
| `APPMESH_ACCESS_TOKEN` | Access token sent to the daemon | Required |
| `APPMESH_WORKSPACE` | Remote source directory | Required for sync and deploy |
| `APPMESH_SSL_VERIFY` | `true`, `false`, or a CA path | `false` |
| `APPMESH_SYNC_EXCLUDE` | Extra comma-separated tar exclude patterns | Empty |

Configure real credentials explicitly. Prefer certificate verification outside
isolated development nodes, and never print access tokens or private key material.

```bash
export APPMESH_ENGINE_URL=https://192.168.1.100:6060
export APPMESH_ACCESS_TOKEN='<access token>'
export APPMESH_WORKSPACE=/home/dev/myproject
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
