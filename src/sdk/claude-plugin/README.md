# App Mesh Claude Code Plugin

Edit code locally with Claude Code, build and run remotely on an [App Mesh](https://github.com/laoshanxi/app-mesh) server.

## Prerequisites

- **Remote server**: [App Mesh](https://github.com/laoshanxi/app-mesh) installed and running ([install guide](https://app-mesh.readthedocs.io/en/latest/Install.html))
- **Local machine**: Python 3.6+

## Quick Start

### 1. Install the Python SDK

```bash
pip install appmesh
```

### 2. Add the skill to your project

Run from your project root:

```bash
curl -sL https://github.com/laoshanxi/app-mesh/archive/refs/heads/main.tar.gz \
  | tar xz --strip-components=4 -C /tmp app-mesh-main/src/sdk/claude-plugin \
  && mkdir -p .claude/skills .claude/rules \
  && cp -r /tmp/claude-plugin/skills/appmesh-remote .claude/skills/ \
  && cp /tmp/claude-plugin/rules/remote-dev-mode.md .claude/rules/ \
  && rm -rf /tmp/claude-plugin
```

### 3. Configure and start

```bash
# Replace with your actual server address and remote working directory
export APPMESH_HOST=https://your-server:6060
export APPMESH_WORKSPACE=/home/dev/myproject

claude
```

Done. Now just talk to Claude naturally.

## Example Workflow

```
You:    "fix the null pointer in config.cpp"
Claude: reads and edits config.cpp locally

You:    "build it"
Claude: syncs files to remote, runs make, streams output back
        [sync] Uploading 1024 KB ...
        [exec] cd build && make -j8
        [100%] Built target myapp
        [exit] 0

You:    "run the tests"
Claude: syncs + runs tests remotely
        [exec] cd build && make test ARGS=-V
        All tests passed.
        [exit] 0

You:    "deploy it as a service called my-api"
Claude: syncs files + registers as a long-running App Mesh application
        [deploy] Registered 'my-api' with keepalive.

You:    "show me the output of my-api"
Claude: [output] tick tick tick ...

You:    "stop and remove my-api"
Claude: [cleanup] Removed my-api

You:    "commit and push"
Claude: commits and pushes locally via git
```

Claude automatically decides what runs locally (edit, search, git) and what runs remotely (build, test, deploy).

## Optional Environment Variables

| Variable | Default | Description |
|---|---|---|
| `APPMESH_USER` | `admin` | Login username |
| `APPMESH_PASSWORD` | `admin123` | Login password |
| `APPMESH_SSL_VERIFY` | `false` | SSL certificate verification |
| `APPMESH_SYNC_EXCLUDE` | _(none)_ | Extra exclude patterns, comma-separated (e.g. `*.o,dist/`) |
