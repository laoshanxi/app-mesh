# AI coding agent remote sandbox

An agent skill for Codex and Claude Code that provides **remote execution
sandboxing** — edit code locally, then build, test, run, or deploy on a remote
App Mesh server in isolation.

## 1. Why

Developers on Mac/Windows often need to compile, test, or deploy on a remote Linux server. Traditional approaches (SSH + rsync, Docker dev containers, VS Code Remote) all require heavyweight setup and don't integrate with AI coding assistants.

**App Mesh Remote Sandbox** solves this with zero local infrastructure — no SSH keys, no Docker, no rsync. Just `pip install appmesh`, set two environment variables, and the coding agent automatically syncs files (tar + SDK upload) and executes commands remotely via the App Mesh Python SDK. The developer experience is fully transparent: say "build" or "deploy" in natural language, and the agent routes it to the right place.

## 2. Architecture

```
Local machine (Codex or Claude Code)         Remote node (App Mesh)
┌─────────────────────────┐                ┌─────────────────────────┐
│ Read/Edit/Write/        │                │                         │
│ Grep/Glob/Git           │                │  APPMESH_WORKSPACE/     │
│   ↓ local files         │  tar + upload  │    (code mirror)        │
│                         │ ─────────────→ │                         │
│ scripts/remote.py       │  SDK API       │  appmesh daemon          │
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

| Variable                   | Purpose                                  | Example                      |
| -------------------------- | ---------------------------------------- | ---------------------------- |
| `APPMESH_ENGINE_URL`       | Target App Mesh Engine URL               | `https://192.168.1.100:6060` |
| `APPMESH_DEX_ISSUER`       | Stable canonical Dex issuer              | `https://auth.example/dex`   |
| `APPMESH_DEX_ACCESS_URL`   | Client-reachable route to the same Dex   | `https://gateway.example/dex`|
| `APPMESH_BEARER_TOKEN`     | Dex access token used as the bearer      | Set from the OAuth result    |
| `APPMESH_WORKSPACE`        | Remote working directory                 | `/home/dev/app-mesh`         |
| `APPMESH_SSL_VERIFY`       | Engine certificate verification          | `true`                       |
| `APPMESH_SYNC_EXCLUDE`     | Extra exclude patterns (comma-separated) | `*.o,dist/`                  |

The Engine URL and Dex access URL are deliberately independent. This remains
true for a local Engine: it still validates against the canonical issuer and
needs an explicit route to Dex. Obtain `APPMESH_BEARER_TOKEN` from Dex before
starting the remote tool; the tool never receives an identity-provider password.

**Runtime config:**

```bash
export APPMESH_ENGINE_URL=https://192.168.1.100:6060
export APPMESH_WORKSPACE=/home/dev/app-mesh
# Set APPMESH_BEARER_TOKEN from a Dex OAuth result in the calling environment.
```

## 4. Prerequisites

1. **Local**: `pip install appmesh` (Python SDK)
2. **Local**: `tar` (macOS/Linux ship with it)
3. **Remote**: App Mesh daemon running
4. No SSH access needed. No rsync needed. No appm CLI needed.

## 5. Implementation: `scripts/remote.py`

Single Python CLI tool (~340 lines) with 7 subcommands:

### Commands

```
python3 <skill-dir>/scripts/remote.py <command> [args]

Commands:
  sync                            tar + upload + extract to remote workspace
  exec <cmd> [--timeout N]        execute on remote (no sync)
  sync-exec <cmd> [--timeout N]   sync + execute (main dev loop)
  run-script <file> [--timeout N] upload script + execute + cleanup
  deploy <name> <cmd>             sync + register as long-running service
  output <app_name>               view stdout of a running/finished app
  cleanup <app_name>              stop and remove remote app
```

### Core Functions

**`do_sync(client)`**:

1. `tar czf` local git repo root (excludes `.git`, `build`, `node_modules`, `__pycache__`, `.agents`, `.claude`, `.codex`, `*.o`, `*.pyc`)
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
- Dex bearer is supplied through `APPMESH_BEARER_TOKEN`; renewal is performed by the OAuth client
- `ssl_verify=False` by default (self-signed certs common in dev)
- Exit code propagation: `sys.exit(rc)` so the coding agent sees build failures

## 6. Workflow

### 6.1 Setup

```bash
# 1. Install Python SDK
pip install appmesh

# 2. Set environment variables
export APPMESH_ENGINE_URL=https://192.168.1.100:6060
export APPMESH_WORKSPACE=/home/dev/app-mesh
# Set APPMESH_BEARER_TOKEN from a Dex OAuth result in the calling environment.

# 3. Start a supported coding agent
codex   # or: claude
```

### 6.2 Daily Development Loop

```
User: "fix the segfault in Configuration.cpp"

  Agent: search src/daemon/ for "segfault"                 → local search
  Agent: read src/daemon/Configuration.cpp                 → local read
  Agent: edit src/daemon/Configuration.cpp                 → local edit

User: "build"

  Agent: python3 .agents/skills/appmesh-remote/scripts/remote.py sync-exec "cd build && make -j$(nproc)"

  Output:
    [sync] Packing /Users/dev/app-mesh ...
    [sync] Uploading 2048 KB ...
    [sync] Extracting to /home/dev/app-mesh ...
    [sync] Done.
    [exec] cd build && make -j8
    [ 12%] Building CXX object ...
    [100%] Built target appmesh
    [exit] 0

User: "run the tests"

  Agent: python3 .agents/skills/appmesh-remote/scripts/remote.py sync-exec "cd build && make test ARGS=-V"

User: "commit and push"

  Agent: git add ... && git commit -m '...'                 → local git
  Agent: git push origin main                               → local git
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

**Local — coding-agent native tools, no remote involvement:**

| User Intent       | Tool        | Examples                                        |
| ----------------- | ----------- | ----------------------------------------------- |
| Read / view files | Read        | `Read("src/main.cpp")`                          |
| Edit / fix code   | Edit        | `Edit("src/main.cpp", old→new)`                 |
| Search code       | Grep / Glob | `Grep("segfault")`, `Glob("**/*.py")`           |
| Create new files  | Write       | `Write("src/new_module.cpp", ...)`              |
| Git operations    | Bash        | `git add`, `git commit`, `git push`, `git diff` |

**Quick decision rule:** Does it need to execute on the OS? → Remote. Just reading/writing files or git? → Local.

## 7. Skill Structure

```
.agents/skills/appmesh-remote/
├── SKILL.md
├── scripts/
│   └── remote.py
└── references/
    ├── configuration.md
    └── troubleshooting.md

.claude -> .agents
```

The `.agents/` directory is the canonical source used by Codex. The repository's
`.claude` directory is a link to `.agents`, so Claude Code discovers the same
skills and settings without maintaining a second directory.

### Install in another repository

Copy the canonical skill into the target repository:

```bash
mkdir -p .agents/skills
cp -R /path/to/app-mesh/.agents/skills/appmesh-remote .agents/skills/
```

If the target does not already have a `.claude` directory, expose the same
configuration to Claude Code with:

```bash
ln -s .agents .claude
```

If `.claude` already exists, link only the skill instead:

```bash
mkdir -p .claude/skills
ln -s ../../.agents/skills/appmesh-remote .claude/skills/appmesh-remote
```

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
| 8   | Cross-repo   | Install the skill in another repo | Set env → works                              |

All tests 1-6 verified against live Docker container (2026-03-07).

## 9. Known Limitations

1. **Full sync each time** — tar sends entire repo (minus excludes), not incremental like rsync. Mitigated by gzip compression.
2. **Remote build artifacts not auto-retrieved** — use `client.download_file()` or `exec "cat ..."` to retrieve.
3. **Excludes are pattern-based** — no `.gitignore` integration, must configure `APPMESH_SYNC_EXCLUDE` for project-specific patterns.
4. **Single workspace** — one remote directory per session. Multiple workspaces need separate env var sets.
