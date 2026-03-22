# Claude Code remote sandbox

A Claude Code skill that provides **remote execution sandboxing** — edit code locally, build/test/run/deploy on a remote App Mesh server in isolation.

## 1. Why

Developers on Mac/Windows often need to compile, test, or deploy on a remote Linux server. Traditional approaches (SSH + rsync, Docker dev containers, VS Code Remote) all require heavyweight setup and don't integrate with AI coding assistants.

**App Mesh Remote Sandbox** solves this with zero local infrastructure — no SSH keys, no Docker, no rsync. Just `pip install appmesh`, set two environment variables, and Claude Code automatically syncs files (tar + SDK upload) and executes commands remotely via the appmesh Python SDK. The developer experience is fully transparent: say "build" or "deploy" in natural language, and the AI routes it to the right place.

## 2. Architecture

```
Local Mac (Claude Code)                     Remote Linux (App Mesh)
┌─────────────────────────┐                ┌─────────────────────────┐
│ Read/Edit/Write/        │                │                         │
│ Grep/Glob/Git           │                │  APPMESH_WORKSPACE/     │
│   ↓ local files         │  tar + upload  │    (code mirror)        │
│                         │ ─────────────→ │                         │
│ remote.py               │  SDK API       │  appsvc daemon          │
│   sync-exec "make"      │ ─────────────→ │    ↓ execute cmd        │
│                         │                │    ↓ stdout             │
│ real-time stdout        │ ←───────────── │    ↓ stream back        │
└─────────────────────────┘                └─────────────────────────┘
```

Two channels:

- **tar + SDK upload**: File sync. `tar czf` locally → `upload_file()` via SDK API → remote `tar xzf`. No SSH required.
- **appmesh Python SDK**: Command execution via `run_app_async()` with real-time stdout streaming, app lifecycle management.

### Why tar-based sync (not rsync)

- **No SSH required** — works with SDK API only, through firewalls/NAT
- **No rsync dependency** — `tar` is universal, available everywhere
- **Simple** — no state files, no incremental tracking needed
- **Trade-off** — always full sync (no incremental), mitigated by compression and exclude patterns

## 3. Environment Variables

| Variable               | Purpose                                  | Example                      |
| ---------------------- | ---------------------------------------- | ---------------------------- |
| `APPMESH_HOST`         | App Mesh server URL                      | `https://192.168.1.100:6060` |
| `APPMESH_USER`         | Login username                           | `admin`                      |
| `APPMESH_PASSWORD`     | Login password                           | `PASSWORD`                   |
| `APPMESH_WORKSPACE`    | Remote working directory                 | `/home/dev/app-mesh`         |
| `APPMESH_SSL_VERIFY`   | SSL certificate verification             | `false`                      |
| `APPMESH_SYNC_EXCLUDE` | Extra exclude patterns (comma-separated) | `*.o,dist/`                  |

**Minimum config** (two variables):

```bash
export APPMESH_HOST=https://192.168.1.100:6060
export APPMESH_WORKSPACE=/home/dev/app-mesh
```

## 4. Prerequisites

1. **Local**: `pip install appmesh` (Python SDK)
2. **Local**: `tar` (macOS/Linux ship with it)
3. **Remote**: App Mesh daemon running
4. No SSH access needed. No rsync needed. No appc CLI needed.

## 5. Implementation: `remote.py`

Single Python CLI tool (~240 lines) with 6 subcommands:

### Commands

```
remote.py <command> [args]

Commands:
  sync                            tar + upload + extract to remote workspace
  exec <cmd> [--timeout N]        execute on remote (no sync)
  sync-exec <cmd> [--timeout N]   sync + execute (main dev loop)
  run-script <file> [--timeout N] upload script + execute + cleanup
  deploy <name> <cmd>             sync + register as long-running service
  cleanup <app_name>              stop and remove remote app
```

### Core Functions

**`do_sync(client)`**:

1. `tar czf` local git repo root (excludes `.git`, `build`, `node_modules`, `__pycache__`, `.claude`, `*.o`, `*.pyc`)
2. SHA-256 hash check — skip upload if unchanged since last sync (override with `--force`)
3. `client.upload_file()` tar to remote `/tmp/`
4. `client.run_app_sync("mkdir -p $WORKSPACE && tar xzf ... -C $WORKSPACE")` extract
5. Separate cleanup call: `client.run_app_sync("rm -f ...")` — always runs even if extract fails

**`do_exec(client, cmd, timeout, working_dir)`**:

1. `client.run_app_async(App({"command": cmd, "shell": True, "working_dir": workspace}))`
2. `run.wait(stdout_print=True, timeout=timeout)` — real-time stdout streaming
3. `KeyboardInterrupt` → disable + delete app, exit 130

### Key Design Decisions

- `run_app_async` (not `run_app_sync`) for all execution — enables real-time stdout streaming
- `run_app_sync` only for quick infrastructure ops (extract tar, chmod, rm)
- `auto_refresh_token=True` for long sessions
- `ssl_verify=False` by default (self-signed certs common in dev)
- Exit code propagation: `sys.exit(rc)` so Claude sees build failures

## 6. Workflow

### 6.1 Setup

```bash
# 1. Install Python SDK
pip install appmesh

# 2. Set environment variables
export APPMESH_HOST=https://192.168.1.100:6060
export APPMESH_WORKSPACE=/home/dev/app-mesh

# 3. Start Claude Code
claude
```

### 6.2 Daily Development Loop

```
User: "fix the segfault in Configuration.cpp"

  Claude: Grep("segfault", path="src/daemon/")            → local search
  Claude: Read("src/daemon/Configuration.cpp")              → local read
  Claude: Edit("src/daemon/Configuration.cpp", old→new)     → local edit

User: "build"

  Claude: Bash('python3 .claude/skills/appmesh-remote/remote.py sync-exec "cd build && make -j$(nproc)"')

  Output:
    [sync] Packing /Users/dev/app-mesh ...
    [sync] Uploading 2048 KB ...
    [sync] Extracting to /home/dev/app-mesh ...
    [sync] Done.
    [exec] cd build && make -j8
    [ 12%] Building CXX object ...
    [100%] Built target appsvc
    [exit] 0

User: "run the tests"

  Claude: Bash('python3 .claude/skills/appmesh-remote/remote.py sync-exec "cd build && make test ARGS=-V"')

User: "commit and push"

  Claude: Bash("git add ... && git commit -m '...'")        → local git
  Claude: Bash("git push origin main")                      → local git
```

### 6.3 Routing Rules: Local vs Remote

**Remote — needs to "run" something on the OS:**

| User Intent                           | Subcommand   | Sync? | Examples                                            |
| ------------------------------------- | ------------ | ----- | --------------------------------------------------- |
| Build / compile                       | `sync-exec`  | Yes   | `make`, `cmake --build`, `cargo build`, `go build`  |
| Run tests                             | `sync-exec`  | Yes   | `make test`, `pytest`, `go test`, `npm test`        |
| Run program                           | `sync-exec`  | Yes   | `python3 app.py`, `./myapp`, `node server.js`       |
| Install packages / system diagnostics | `exec`       | No    | `apt install`, `uname -a`, `df -h`, `which python3` |
| Deploy as long-running service        | `deploy`     | Yes   | `deploy my-api "python3 server.py"`                 |
| Run a standalone script               | `run-script` | No    | `run-script /tmp/setup.sh`                          |
| Stop / remove a remote app            | `cleanup`    | No    | `cleanup my-api`                                    |

**Local — Claude native tools, no remote involvement:**

| User Intent       | Tool        | Examples                                        |
| ----------------- | ----------- | ----------------------------------------------- |
| Read / view files | Read        | `Read("src/main.cpp")`                          |
| Edit / fix code   | Edit        | `Edit("src/main.cpp", old→new)`                 |
| Search code       | Grep / Glob | `Grep("segfault")`, `Glob("**/*.py")`           |
| Create new files  | Write       | `Write("src/new_module.cpp", ...)`              |
| Git operations    | Bash        | `git add`, `git commit`, `git push`, `git diff` |

**Quick decision rule:** Does it need to execute on the OS? → Remote. Just reading/writing files or git? → Local.

## 7. Plugin Structure

```
src/sdk/claude-plugin/
├── plugin.json
├── skills/appmesh-remote/
│   ├── SKILL.md
│   └── remote.py
├── rules/remote-dev-mode.md
└── README.md
```

**Installation:** Copy `skills/appmesh-remote/` and `rules/` into the target project's `.claude/` directory. See [README.md](../sdk/claude-plugin/README.md) for details.

## 8. Validation

| #   | Test         | Command                        | Expected                                       |
| --- | ------------ | ------------------------------ | ---------------------------------------------- |
| 1   | Sync         | `sync`                         | tar + upload + extract, files appear on remote |
| 2   | Edit + build | Edit → `sync-exec "make"`      | Sync changed files, build succeeds             |
| 3   | Execute only | `exec "uname -a"`              | No sync, direct execute                        |
| 4   | Run script   | `run-script /tmp/test.sh`      | Upload + execute + cleanup                     |
| 5   | Deploy       | `deploy svc "python3 svc.py"`  | Sync + register keepalive service              |
| 6   | Cleanup      | `cleanup app_name`             | Disable + delete app                           |
| 7   | Ctrl+C       | Interrupt during exec          | App disabled + deleted                         |
| 8   | Cross-repo   | Install plugin in another repo | Set env → works                                |

All tests 1-6 verified against live Docker container (2026-03-07).

## 9. Known Limitations

1. **Full sync each time** — tar sends entire repo (minus excludes), not incremental like rsync. Mitigated by gzip compression.
2. **Remote build artifacts not auto-retrieved** — use `client.download_file()` or `exec "cat ..."` to retrieve.
3. **Excludes are pattern-based** — no `.gitignore` integration, must configure `APPMESH_SYNC_EXCLUDE` for project-specific patterns.
4. **Single workspace** — one remote directory per session. Multiple workspaces need separate env var sets.
