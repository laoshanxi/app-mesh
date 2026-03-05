---
name: appmesh-remote
description: "Sync local changes (tar + upload) and execute build/test/run on remote servers (appmesh Python SDK)."
---

# Remote Execution Skill

Local development + remote execution. All file operations (Read/Edit/Write/Grep/Glob) and Git happen **locally** using Claude's native tools. Only build/test/run goes remote via tar-based sync + appmesh Python SDK.

## Prerequisites

- `pip install appmesh` (Python SDK)
- App Mesh daemon running on remote server

## Environment Variables

```bash
export APPMESH_HOST=https://192.168.1.100:6060   # App Mesh server URL
export APPMESH_WORKSPACE=/home/dev/myproject      # Remote working directory
# Optional:
export APPMESH_PASSWORD=admin123                  # Default: admin123
export APPMESH_SSL_VERIFY=false                   # Default: false
export APPMESH_SYNC_EXCLUDE="*.o,dist/"           # Extra sync excludes
```

## Commands

### Build / Test (sync + execute)

```bash
python3 .claude/skills/appmesh-remote/remote.py sync-exec "<command>" --timeout <seconds>
```

Examples:
```bash
python3 .claude/skills/appmesh-remote/remote.py sync-exec "cd build && make -j\$(nproc)" --timeout 600
python3 .claude/skills/appmesh-remote/remote.py sync-exec "cd build && make test ARGS=-V" --timeout 600
python3 .claude/skills/appmesh-remote/remote.py sync-exec "python3 -m pytest tests/" --timeout 300
```

### Execute Only (no sync, for system commands)

```bash
python3 .claude/skills/appmesh-remote/remote.py exec "<command>" --timeout <seconds>
```

Examples:
```bash
python3 .claude/skills/appmesh-remote/remote.py exec "apt-get install -y libboost-dev" --timeout 300
python3 .claude/skills/appmesh-remote/remote.py exec "uname -a && python3 --version"
python3 .claude/skills/appmesh-remote/remote.py exec "mkdir -p build && cd build && cmake .."
```

### Sync Only

```bash
python3 .claude/skills/appmesh-remote/remote.py sync
```

### Run a Script

```bash
python3 .claude/skills/appmesh-remote/remote.py run-script /tmp/my_script.sh --timeout 300
```

### Deploy as Long-Running Service

```bash
python3 .claude/skills/appmesh-remote/remote.py deploy <name> "<command>"
```

### View App Output

```bash
python3 .claude/skills/appmesh-remote/remote.py output <app_name>
```

### Cleanup Interrupted Task

```bash
python3 .claude/skills/appmesh-remote/remote.py cleanup <app_name>
```

## Rules

- **Read / Edit / Write / Grep / Glob** → always LOCAL (Claude native tools)
- **Git** → always LOCAL
- **Build / Test / Run** → `sync-exec` (tar sync + remote execute)
- **Install packages / diagnostics** → `exec` (remote execute, no sync)
- **Deploy** → `deploy` (tar sync + register service)
