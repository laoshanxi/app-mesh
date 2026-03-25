# CLAUDE.md

## Project Overview

App Mesh — C++17 cross-platform (Linux/macOS/Windows) application management platform. Systemd-like process lifecycle, remote execution, cron scheduling, RBAC/JWT security, REST/WebSocket/TCP APIs. SDKs: C++, Python, Go, Rust, Java, JavaScript. Plus MCP and MQTT integrations.

## Build & Test

```bash
# Build
mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

# Package (.deb/.rpm)
make pack

# Tests (Catch2/CTest)
make test ARGS="-V"

# Static analysis
make cppcheck

# Docker build (no local deps)
docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_ubuntu22 \
  sh -c "mkdir build && cd build && cmake .. && make && make pack"

# SDK tests
python3 -m unittest --verbose              # from src/sdk/python/test/
go test ./src/sdk/go/ -test.v
go test ./src/sdk/agent/pkg/cloud/ -test.v
```

## Code Conventions

- C++17, `-Wall` enabled
- CamelCase for classes
- Logging: `LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR` (from `StreamLogger.h`)
- Singletons: `RESTHANDLER`, `WORKER`, `TIMER_MANAGER`, `TOKEN_BLACK_LIST`
- Pre-commit hooks: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle, gitleaks
- API spec: `src/daemon/rest/openapi.yaml`
- Config env overrides: `APPMESH_<Section>_<Key>` (e.g. `APPMESH_REST_RestListenPort=6060`)

## Remote Execution Policy

When `APPMESH_WORKSPACE` is set, use `appmesh-remote` skill for build/test/run/deploy. Code reading, editing, searching, and git stay local.

### Remote commands (via `remote.py`)
- `python3 .claude/skills/appmesh-remote/remote.py sync-exec "<cmd>"` — build/test (syncs files first)
- `python3 .claude/skills/appmesh-remote/remote.py exec "<cmd>"` — system commands
- `python3 .claude/skills/appmesh-remote/remote.py deploy <name> "<cmd>"` — deploy service
- `python3 .claude/skills/appmesh-remote/remote.py run-script <file>` — run script
- `python3 .claude/skills/appmesh-remote/remote.py cleanup <app_name>` — cleanup leftover app

### Trigger remote when user says: build, test, run, execute, deploy, "on the server", "remotely"
### Stay local for: code read/edit/search, git, user says "run locally"
### Defaults: host `https://127.0.0.1:6060`, user `admin`, password `admin123`
