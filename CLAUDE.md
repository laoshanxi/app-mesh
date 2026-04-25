# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

App Mesh is a C++17 cross-platform (Linux/macOS/Windows) application management platform. Think systemd + cron + remote execution API with RBAC/JWT security, REST/WebSocket/TCP interfaces, and SDKs in Python, Go, Rust, Java, JavaScript, and C++.

## Build & Test

```bash
# Full build
mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release && make -j$(nproc)

# Build with AddressSanitizer
cmake .. -DENABLE_ASAN=ON && make -j$(nproc)

# Build without tests
cmake .. -DAPPMESH_NO_TESTS=1 && make -j$(nproc)

# Package (.deb/.rpm via nfpm)
make pack

# C++ tests (Catch2/CTest)
make test ARGS="-V"

# Run a single C++ test by name
cd build && ctest -R <test_name> -V

# Static analysis
make cppcheck

# Docker build (no local deps needed)
docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_ubuntu22 \
  sh -c "mkdir build && cd build && cmake .. && make && make pack"

# SDK tests
cd src/sdk/python/test && python3 -m unittest --verbose
go test ./src/sdk/go/ -test.v
cd src/sdk/rust && cargo test
```

CMake targets `python_tests` and `go_tests` also exist (`make python_tests`, `make go_tests`).

## Architecture

### Daemon (`src/daemon/`)

The core service. Initialization flows through `main.cpp`: ACE framework init → config → SSL → security → app recovery → REST server → worker pool → ACE reactor event loop.

**Key subsystems:**

| Directory | What it does |
|-----------|-------------|
| `rest/` | HTTP/WebSocket/TCP server, REST endpoint routing, worker thread pool, event pub/sub |
| `application/` | App lifecycle (spawn, enable/disable, schedule, health), cron support, task messaging |
| `process/` | Process wrappers: native (`AppProcess`), Docker CLI (`DockerProcess`), Docker API (`DockerApiProcess`), cgroup resource limits (`LinuxCgroup`) |
| `security/` | Pluggable auth backends: local JSON, Consul, Keycloak/OAuth2, LDAP. JWT tokens, RBAC, HMAC PSK |

**Singletons** (ACE_Singleton pattern, access via `::instance()`):

| Macro | Class | Header |
|-------|-------|--------|
| `RESTHANDLER` | `RestHandler` | `rest/RestHandler.h` |
| `WORKER` | `Worker` | `rest/Worker.h` |
| `TOKEN_BLACK_LIST` | `TokenBlacklist` | `security/TokenBlacklist.h` |
| `EVENT_DISPATCHER` | `EventDispatcher` | `rest/EventDispatcher.h` |
| `HMACVerifierSingleton` | `HMACVerifier` | `security/HMACVerifier.h` |

Other singletons use `static instance()`: `Configuration`, `Security`, `ResourceCollection`, `PersistManager`, `HealthCheckTask`, `ConsulConnection`.

**Request flow:** Client → `SocketServer` (accept) → `SocketStream` (parse HTTP) → `WORKER` queue (lock-free `moodycamel::BlockingConcurrentQueue`) → `RestHandler` (regex-based route dispatch) → handler method → response.

### Common Library (`src/common/`)

Shared across daemon and CLI. Notable:
- `StreamLogger.h` — logging macros (`LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR`) wrapping spdlog
- `Utility.h` — string ops, file helpers, ID generation
- `DateTime.h` / `DurationParse.h` — time and duration parsing
- `JwtHelper.h` — JWT encode/decode
- `RestClient.h` — HTTP client for inter-service calls
- `lwsservice/` — libwebsockets server/client wrappers

### CLI (`src/cli/`)

`appc` command-line tool. `CommandDispatcher.cpp` handles all subcommands, communicating with the daemon over HTTP.

### SDKs (`src/sdk/`)

Each SDK (Python, Go, Rust, Java, JavaScript) provides HTTP, TCP, and/or WebSocket clients plus a server-side interface for receiving tasks. The Go agent (`src/sdk/agent/`) adds cluster orchestration. MCP integration lives in `src/sdk/mcp/`.

## Code Conventions

- C++17 (C++20 on Windows, C++14 on older GCC). `-Wall` enabled.
- CamelCase for classes, `m_` prefix for member variables.
- Logging: `LOG_DBG << "msg";` — never `std::cout` or `printf`.
- Config env overrides: `APPMESH_<Section>_<Key>` (e.g. `APPMESH_REST_RestListenPort=6060`).
- REST API spec: `src/daemon/rest/openapi.yaml` (OpenAPI 3.1.0) — keep this in sync with handler changes.
- Pre-commit hooks enforce: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle, gitleaks, trailing-whitespace, end-of-file-fixer.

## Key Dependencies

C++: ACE (networking/threading/reactor), Boost, OpenSSL, spdlog, nlohmann/json, yaml-cpp, jwt-cpp, prometheus-cpp, libwebsockets, msgpack, Crypto++, croncpp, moodycamel concurrent queue.
