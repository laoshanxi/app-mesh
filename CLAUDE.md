# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

App Mesh is a cross-platform (Linux, macOS, Windows) application management platform written in C++17. It provides systemd-like process lifecycle management, remote execution, scheduling, multi-tenant RBAC security with JWT, and REST/WebSocket APIs. Multi-language SDKs exist for C++, Python, Go, Rust, Java, and JavaScript.

## Build Commands

```bash
# Configure and build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Create distribution package (.deb/.rpm)
make pack

# Run C++ tests (Catch2)
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
# Python
python3 -m unittest --verbose  # from src/sdk/python/test/

# Go
go test ./src/sdk/go/ -test.v
```

## Architecture

### Binaries
- **appsvc** (`src/daemon/main.cpp`): Core daemon. Uses ACE reactor pattern for async I/O with configurable worker/IO thread pools.
- **appc** (`src/cli/`): CLI client that communicates with appsvc via REST.

### Source Layout
- `src/daemon/` — Daemon core
  - `Configuration.cpp/h` — YAML config parsing with env var overrides (`APPMESH_` prefix) and hot-reload
  - `application/` — Application lifecycle: state machine (ENABLED/DISABLED → RUNNING/STOPPED), cron scheduling, health checks
  - `process/` — Process execution: native processes, Docker containers, Linux cgroup resource limiting
  - `rest/` — REST API server with two backends:
    - `uwebsockets/` — Current HTTP/2 backend (compile flag: `HAVE_UWEBSOCKETS`)
    - Legacy libwebsockets (deprecated)
  - `security/` — Auth subsystem: JWT (HS256/RS256/SS256), RBAC, HMAC-PSK, with pluggable backends (local JSON, Consul, Keycloak/OAuth2, LDAP)
- `src/common/` — Shared utilities: REST client, datetime/duration parsing, logging (spdlog), HTTP helpers
- `src/sdk/` — Client SDKs (cpp, python, go, rust, java, javascript, mcp, mqtt)
- `test/` — C++ unit tests (Catch2): datetime, utility, security, websockets
- `cmake/` — CMake modules: Dependencies.cmake, DetectCPU.cmake, InstallConfig.cmake, InstallRuntime.cmake, WindowsConfig.cmake

### Key Dependencies
ACE (async I/O), Boost (filesystem/regex/thread/program_options/date_time), OpenSSL, spdlog, nlohmann/json, yaml-cpp, jwt-cpp, libwebsockets, Crypto++, msgpack, libcurl, prometheus-cpp, uriparser, zlib

### Configuration
- Main config: YAML format (`config.yaml`)
- Default install path: `/opt/appmesh/`
- Environment variable overrides: prefix `APPMESH_` (e.g., `APPMESH_REST_RestListenPort=6060`)

## Code Standards

- C++17 (C++20 on Windows, C++11 for GCC < 5)
- `-Wall` enabled globally
- Pre-commit hooks: cpplint (C++), pylint, golangci-lint, shellcheck, eslint, Checkstyle (Java), gitleaks
- CamelCase for classes, OpenAPI spec at `src/daemon/rest/openapi.yaml`