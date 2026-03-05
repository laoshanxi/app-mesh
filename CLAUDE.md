# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

App Mesh is a cross-platform (Linux, macOS, Windows) application management platform written in C++17. It provides systemd-like process lifecycle management, remote execution, cron/periodic scheduling, multi-tenant RBAC security with JWT, and REST/WebSocket/TCP APIs. Multi-language SDKs exist for C++, Python, Go, Rust, Java, and JavaScript, plus MCP and MQTT integrations.

## Build Commands

```bash
# Configure and build (from repo root)
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Create distribution package (.deb/.rpm via nfpm)
make pack

# Run C++ tests (Catch2, via CTest)
make test ARGS="-V"

# Disable tests during build
cmake -DAPPMESH_NO_TESTS=1 ..

# Static analysis
make cppcheck

# AddressSanitizer build
cmake .. -DENABLE_ASAN=ON

# Docker-based build (no local deps needed)
docker run --rm -v $(pwd):$(pwd) -w $(pwd) \
  laoshanxi/appmesh:build_ubuntu22 \
  sh -c "mkdir build && cd build && cmake .. && make && make pack"
```

### SDK Tests

```bash
# Python (from src/sdk/python/test/)
python3 -m unittest --verbose

# Go
go test ./src/sdk/go/ -test.v

# Go agent tests
go test ./src/sdk/agent/pkg/cloud/ -test.v
```

## Architecture

### Binaries
- **appsvc** (`src/daemon/main.cpp`): Core daemon. Startup sequence: env → logging → config → ACE reactor → security → directories → signals → recover apps → REST server → HA recovery → main loop.
- **appc** (`src/cli/`): CLI client. `CommandDispatcher` extends the C++ SDK (`ClientHttp`) and maps subcommands to REST calls.

### Daemon Core (ACE Reactor Pattern)
The daemon is built on the ACE framework:
- `ACE_TP_Reactor` — Thread-pool reactor for TCP socket I/O across configurable I/O threads.
- `TimerManager` (`TIMER_MANAGER` singleton) — `ACE_Timer_Heap` adapter for all timers (app scheduling, health checks, token cleanup).
- `ACE_Process_Manager` — Child process exit event handling via `ProcessExitHandler`.
- `Worker` (`WORKER` singleton) — Thread pool dequeuing `HttpRequestContext` from `moodycamel::BlockingConcurrentQueue`, dispatching to `RESTHANDLER`.

### Request Pipeline
```
Client (HTTPS/WSS/TCP) → uWebSockets (or libwebsockets/ACE TCP)
  → Worker thread pool (BlockingConcurrentQueue)
    → RestHandler (JWT verify + RBAC permission check)
      → Domain handler (app/user/file/config/label)
        → Response via ReplyContext (thread-safe, one-shot)
```

### Source Layout

**`src/daemon/`** — Daemon core
- `Configuration.h/.cpp` — YAML config singleton. Nested structs (`BaseConfig`, `JsonRest`, `JsonSsl`, `JsonJwt`). Thread-safe app registry via `ACE_Map_Manager`. Hot-reload via `hotUpdate()`. Env var overrides with `APPMESH_` prefix (e.g., `APPMESH_REST_RestListenPort=6060`).
- `PersistManager.h/.cpp` — HA snapshot (`.snapshot` file). Persists running PIDs and JWT blacklist for crash recovery; daemon re-attaches to still-running children on restart.
- `application/` — App lifecycle:
  - `Application.h` — State machine: DISABLED/ENABLED → RUNNING/STOPPED. `execute()` spawns processes. Prometheus metrics (start count, memory, CPU, PID, file descriptors).
  - `AppBehavior.h` — Exit actions: STANDBY, RESTART, KEEPALIVE, REMOVE.
  - `AppTimer.h` — Three scheduling variants: base (oneshot), `AppTimerPeriod` (interval), `AppTimerCron` (cron expression via croncpp).
  - `AppUtils.h` — STATUS/PERMISSION enums, `ShellAppFileGen` (generates shell scripts), `LogFileQueue` (rotating stdout logs).
- `process/` — Process execution:
  - `AppProcess.h` — Core process (extends `ACE_Process`). Stdin/stdout pipes, delayed kill, cgroup resource limiting.
  - `DockerProcess.h` — Docker/Podman via CLI (`docker run`/`docker logs`).
  - `DockerApiProcess.h` — Docker via REST API.
  - `LinuxCgroup.h` — Abstract base with V1/V2/Null implementations. Factory auto-detects cgroup version.
- `rest/` — REST API server:
  - `RestBase.h` — JWT token verify/generate, XSS sanitization, route-to-handler binding via `std::map`.
  - `PrometheusRest.h` — Inherits RestBase. Prometheus counter/gauge metrics + `/metrics` endpoint.
  - `RestHandler.h` — Inherits PrometheusRest. All API endpoints. Singleton `RESTHANDLER`.
  - `Worker.h` — Request dispatch thread pool. Singleton `WORKER`.
  - `HttpRequest.h` — Request/response wrapper. Specialized: `AutoCleanup`, `WithTimeout` (408), `OutputView` (poll), `TaskRequest` (bidirectional).
  - `Data.h` — msgpack-serialized `Request`/`Response` structs. Response adds CORS/security headers, auth cookies.
  - `SocketStream.h` — Custom binary framing over TLS: 8-byte header (4-byte magic `0x07C707F8` + 4-byte length) + msgpack body.
  - `uwebsockets/` — Current backend (C++17+, compile flag `HAVE_UWEBSOCKETS`):
    - `Service.h` — Template `WSS::Server<bool SSL>`. Multi-threaded (one `uWS::App` + event loop per I/O thread).
    - `Adaptor.hpp` — `WebSocketAdaptor` singleton. Bridges uWS to WORKER thread pool.
    - `ReplyContext.h` — Thread-safe one-shot reply (prevents double-reply).
  - `openapi.yaml` — OpenAPI 3.0 spec (canonical API definition). Served at `/appmesh/swagger`.
- `security/` — Auth subsystem (plugin pattern via `Security::init(plugin)`):
  - `Security.h` — Abstract interface: `verifyUserKey`, user/role CRUD.
  - `SecurityJson.h` — Local `security.yaml` backend. Optional key encryption via Crypto++.
  - `SecurityConsul.h` — Consul KV backend.
  - `SecurityKeycloak.h` — Keycloak/OAuth2. Validates JWT against JWKS endpoint, maps realm roles.
  - `SecurityLDAP.h` — LDAP auth (in `ldapplugin/`). Group-to-role mapping.
  - `User.h` — Password (bcrypt), TOTP MFA (RFC 6238), lock/unlock.
  - `Role.h` — Role with permission set.
  - `HMACVerifier.h` — HMAC-PSK for agent-daemon trust. PSK exchanged via POSIX shared memory.
  - `TokenBlacklist.h` — In-memory JWT blacklist with expiry cleanup, persisted in snapshot.

**`src/common/`** — Shared utilities
- `Utility.h` — Central utility class + global constants (ports: 6060 REST, 6059 TCP, 6058 WSS; buffer sizes; path constants).
- `RestClient.h` — libcurl HTTP client with SSL/session/cookie support.
- `DateTime.h` — ISO8601/RFC3339 parse/format, timezone handling.
- `TimerHandler.h` — ACE timer base class + `TimerManager` singleton.
- `os/` — OS abstraction: process tree, `/proc` parsing, network, cgroup, kill tree, Windows job objects.
- `lwsservice/` — Legacy libwebsockets backend (compiled when C++ < 17).

**`src/cli/`** — CLI client
- `CommandDispatcher.h` — Extends C++ SDK. Maps subcommands (login, app add/delete/run, shell, file up/download, etc.) to REST calls.

**`src/sdk/`** — Client SDKs
- `cpp/ClientHttp.h` — C++ HTTP SDK (also base for CLI).
- `python/appmesh/` — Python SDK with HTTP, TCP, WSS transports.
- `go/` — Go SDK with HTTP, TCP, WSS transports.
- `rust/`, `java/`, `javascript/` — Additional SDKs.
- `agent/` — Go agent sidecar. Handles Consul HA, Docker proxy, Prometheus endpoint.
- `mcp/` — MCP server for LLM tool integration.
- `mqtt/` — MQTT IoT bridge.

**`test/`** — C++ unit tests (Catch2): datetime, utility, security, websockets, queue.

**`cmake/`** — Build modules: `Dependencies.cmake` (finds all libs), `DetectCPU.cmake`, `InstallConfig.cmake`, `InstallRuntime.cmake` (platform-aware RPATH/dylib handling), `WindowsConfig.cmake` (vcpkg).

### Key Dependencies
ACE (async I/O), Boost 1.76+ (filesystem/regex/thread/program_options/date_time), OpenSSL, spdlog, nlohmann/json, yaml-cpp, jwt-cpp, Crypto++ (bcrypt/encryption), msgpack-cxx, libcurl, prometheus-cpp, uriparser, zlib, uWebSockets, libwebsockets (legacy), croncpp, concurrentqueue

### Configuration
- Main config: `src/daemon/config.yaml` → installs to `/opt/appmesh/config/config.yaml`
- Security: `src/daemon/security/security.yaml` (users/roles), `oauth2.yaml`, `consul.yaml`
- Default ports: REST 6060, TCP 6059, WebSocket 6058
- Environment variable overrides: `APPMESH_<Section>_<Key>` (e.g., `APPMESH_REST_RestListenPort=6060`)

### REST Server Dual-Backend
Compile-time selection via `HAVE_UWEBSOCKETS` (auto-set when C++17+ available):
- **uWebSockets** (default): Multi-threaded, one event loop per I/O thread. HTTP + WebSocket on same port.
- **libwebsockets** (legacy fallback): Single I/O thread + shared worker pool. Used with GCC < 8.

## Code Standards

- C++17 (C++20 on Windows, C++11 for GCC < 5)
- `-Wall` enabled globally
- Pre-commit hooks: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle (Java), gitleaks
- CamelCase for classes
- Logging via spdlog macros: `LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR` (defined in `StreamLogger.h`)
- Singletons via ACE macros: `RESTHANDLER`, `WORKER`, `TIMER_MANAGER`, `TOKEN_BLACK_LIST`
- OpenAPI spec: `src/daemon/rest/openapi.yaml`

## Remote Execution Policy

> Also shipped as `src/sdk/claude-plugin/rules/remote-dev-mode.md` for plugin consumers.

When `APPMESH_WORKSPACE` is set, remote execution mode is active. Local development + remote execution: tar-based sync uploads files, appmesh Python SDK executes commands.

### Local operations (Claude native tools, no special handling)
- **Read / Edit / Write / Grep / Glob** → local files
- **Git** → local git

### Remote operations (via `remote.py`)
- **Build / Test** → `python3 .claude/skills/appmesh-remote/remote.py sync-exec "<cmd>"`
- **System commands** → `python3 .claude/skills/appmesh-remote/remote.py exec "<cmd>"`
- **Deploy service** → `python3 .claude/skills/appmesh-remote/remote.py deploy <name> "<cmd>"`
- **Run script** → `python3 .claude/skills/appmesh-remote/remote.py run-script <file>`

### Use `appmesh-remote` skill automatically when:
- User says build, test, run, execute, or deploy and env vars are set
- User says "on the server", "remotely", "on the host"
- User asks to install packages or check remote system status

### Do NOT use remote execution for:
- Reading, editing, searching code → use Claude native tools locally
- Git operations → run locally
- User explicitly says "run locally" or "run here"

### Interrupt handling
- `remote.py` handles Ctrl+C: disables and deletes the remote app automatically
- If a remote app is left behind: `python3 .claude/skills/appmesh-remote/remote.py cleanup <app_name>`

### Defaults
- Default credentials: user `admin`, password `admin123`
- Default host: `https://127.0.0.1:6060`
