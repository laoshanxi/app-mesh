# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Working Rules

These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

### Rule 1 — Think Before Coding
State assumptions explicitly. If uncertain, ask rather than guess.
Present multiple interpretations when ambiguity exists.
Push back when a simpler approach exists.
Stop when confused. Name what's unclear.

### Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

### Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

### Rule 4 — Goal-Driven Execution
Define success criteria. Loop until verified.
Don't follow steps. Define success and iterate.
Strong success criteria let you loop independently.

### Rule 5 — Use the model only for judgment calls
Use me for: classification, drafting, summarization, extraction.
Do NOT use me for: routing, retries, deterministic transforms.
If code can answer, code answers.

### Rule 6 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

### Rule 7 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

### Rule 8 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

### Rule 9 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

### Rule 10 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

### Rule 11 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

## Project Overview

App Mesh is a C++17 cross-platform (Linux/macOS/Windows) application management platform — one secure daemon to run, schedule, and remote-control apps across machines, with Dex/OIDC bearer authentication, Principal-based RBAC, REST/WebSocket/TCP interfaces, and SDKs in Python, Go, Rust, Java, and JavaScript.

## Ports

The `REST` section of `src/daemon/config.yaml` defines three port keys (env override `APPMESH_REST_<Key>`, e.g. `APPMESH_REST_RestListenPort`). The Go agent reads the same config file and env prefix, so an override affects both processes.

| Port | Config key | Bound by | Transport / purpose |
|------|------------|----------|---------------------|
| 6060 | `RestListenPort` | Go agent | Agent HTTPS entry — reverse-proxies REST/WSS to the daemon over TCP 6059; primary client surface, never bound by the daemon |
| 6059 | `TcpApiPort` | daemon | TCP API — msgpack-framed protocol used by SDK clients (`ClientTCP`) and by the agent's proxy/forwarding path |
| 6058 | `WebSocketPort` | daemon | Single listener serving both HTTPS REST and WSS — SDK clients (`ClientWSS`), event subscribe, and daemon-to-daemon forwarding |

All ports authenticate the same Dex bearer. Additional ports: Dex 6062 (issuer) / 6063 (healthz), the `dexuser` admin UI 6064 (loopback, gRPC 5557), and the agent's Prometheus exporter 6061 (`APPMESH_REST_PrometheusExporterListenPort`, default off).

## Binary Inspection Tools

Binary-inspection tooling (`otool`/`nm`/`strings` on macOS, `objdump`/`readelf`/`ldd` on Linux, LSP/clangd) is allowed and encouraged — prefer it over guesswork for symbols, linked libraries, or backtraces.

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

# Test targets. CTest itself has no registered case: add_subdirectory(test) is
# disabled in CMakeLists.txt, so `make test ARGS="-V"` runs nothing.
# python_tests needs a live daemon plus APPMESH_TEST_ACCESS_TOKEN, and fails
# (not skips) without them. go_tests and rust_tests skip their live-daemon
# cases when APPMESH_BEARER_TOKEN is absent.
make python_tests
make go_tests
make workflow_tests   # workflow engine, unit + E2E (-tags=e2e)
make rust_tests

# Static analysis
make cppcheck

# Docker build (no local deps needed)
docker run --rm -v $(pwd):$(pwd) -w $(pwd) laoshanxi/appmesh:build_ubuntu22 \
  sh -c "mkdir build && cd build && cmake .. && make && make pack"

# CLI build (Rust)
cd src/cli && cargo build --release

# CLI unit tests
cd src/cli && cargo test

# CLI integration tests (requires running daemon)
cd src/cli && cargo test --test remote_test -- --ignored --test-threads=1

# SDK tests (the Python suite needs APPMESH_TEST_ACCESS_TOKEN and a live daemon)
cd src/sdk/python/test && APPMESH_TEST_ACCESS_TOKEN=<dex-token> python3 -m unittest --verbose
go test ./src/sdk/go/ -test.v
cd src/sdk/rust && cargo test
```

## Architecture

### Daemon (`src/daemon/`)

The core service. Initialization flows through `main.cpp`: framework init → config → SSL → security → app recovery → REST server → worker pool → main monitoring loop. Child processes run on Boost.Process V2 over `ProcessService` (single-threaded asio loop: exit waits, stdout pumps, exit finalization); `TimerManager` is a separate asio timer thread.

**Key subsystems:**

| Directory | What it does |
|-----------|-------------|
| `rest/` | HTTP/WebSocket/TCP server, REST endpoint routing, worker thread pool, event pub/sub |
| `application/` | App lifecycle (spawn, enable/disable, schedule, health), cron support, task messaging |
| `process/` | Process wrappers: native (`AppProcess`), Docker CLI (`DockerProcess`), Docker API (`DockerApiProcess`), cgroup resource limits (`LinuxCgroup`) |
| `security/` | Dex-only OIDC verification, immutable Principal mapping, authorization roles, secret protection, and process HMAC PSK |

**Singletons** (ACE_Singleton pattern, access via `::instance()`):

| Macro | Class | Header |
|-------|-------|--------|
| `RESTHANDLER` | `RestHandler` | `rest/RestHandler.h` |
| `WORKER` | `Worker` | `rest/Worker.h` |
| `EVENT_DISPATCHER` | `EventDispatcher` | `rest/EventDispatcher.h` |

`HMACVerifier` is not a singleton — each managed system spawn (Agent, Workflow) gets a fresh instance; `Configuration`, `Security`, `ResourceCollection`, `PersistManager`, and `HealthCheckTask` use `static instance()`.

**Request flow:** Client → `DrogonAdaptor` (HTTPS/WSS) or `TcpAdaptor` (TCP 6059) in `rest/drogon/` → `WORKER` queue (lock-free `moodycamel::BlockingConcurrentQueue`) → `RestHandler` (regex-based route dispatch) → handler method → response.

### Common Library (`src/common/`)

Shared C++ library used by the daemon. Notable:
- `StreamLogger.h` — logging macros (`LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR`)
- `Utility.h` — string ops, file helpers, ID generation
- `JwtHelper.h` — unverified token parsing, used only alongside OIDC verification
- `RestClient.h` — HTTP client for inter-service calls

### CLI (`src/cli/`)

`appm` command-line tool in Rust (clap + the Rust SDK over WSS). `src/commands/` holds the subcommand handlers; `tests/integration_test.rs` runs without a daemon, `tests/remote_test.rs` needs one (`--ignored`).

### Agent (`src/agent/`)

REST proxy service for the daemon (`appmesh`), written in Go. Accepts HTTP requests from clients and forwards them to the daemon via TCP, offloading traffic and reducing pressure on the C++ core. Also provides a Docker daemon reverse proxy (`/appmesh/docker/*`), and Prometheus metrics exporter.

### SDKs (`src/sdk/`)

| SDK | Language | Transport |
|-----|----------|-----------|
| `rust/` | Rust | HTTP, TCP, WSS |
| `python/` | Python | HTTP, TCP, WSS |
| `go/` | Go | HTTP, TCP, WSS |
| `java/` | Java | HTTP, TCP, WSS |
| `javascript/` | JavaScript | HTTP, TCP |

Each SDK also provides a server-side interface for receiving tasks.

### Integrations (`src/integrations/`)

Ecosystem connectors bridging App Mesh with external systems:
- `mcp-server/` — standalone MCP OAuth Resource Server (Streamable HTTP); validates Dex tokens and forwards the caller bearer to App Mesh. Runs as an App Mesh App.
- `mcp-bridge/` — stdio MCP server plus `mcp_pipe.py`, a stdio↔WebSocket tunnel to a remote LLM gateway.
- `mqtt/` — MQTT bridge scripts for IoT scenarios (example-grade).

### LLM Agent (`src/apps/llm-agent/`)

Optional LLM agent runtime, run as an App Mesh App (Python package `llm_agent`). A thin wrapper around the Claude Agent SDK: the SDK owns the agent loop, tools, and history; llm-agent only routes `session_send`/`session_close` over the task RPC and keys each session to a stable workdir. The daemon does the authorization (RBAC on `run_task`); the model credential is a secured env var. Not in the base Docker image — use the `llm_agent` target / `laoshanxi/appmesh:llm`. See `src/apps/llm-agent/README.md`.

## Code Conventions

- C++ standard: C++17 (GCC 8+/Clang), C++20 on Windows. `-Wall` enabled.
- CamelCase for classes, `m_` prefix for member variables.
- Logging: `LOG_DBG << "msg";` — never `std::cout` or `printf`.
- Comments: keep them short. One line when one line is enough. No metrics, no restating the code, no history.
- Config env overrides: `APPMESH_<Section>_<Key>` (e.g. `APPMESH_REST_RestListenPort=6060`).
- REST API spec: `src/daemon/rest/openapi.yaml` (OpenAPI 3.1.0) — keep this in sync with handler changes.
- Technical documentation: write in ASD-STE100 Simplified Technical English.
- Pre-commit hooks enforce: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle, gitleaks, trailing-whitespace, end-of-file-fixer.

## Key Dependencies

C++ (daemon): ACE (remaining utilities), Boost (incl. Boost.Process V2 ≥1.86), OpenSSL, spdlog, nlohmann/json, yaml-cpp, jwt-cpp, prometheus-cpp, Drogon + trantor (HTTP/WSS/TCP transport; pulls jsoncpp, c-ares, brotli), uriparser, msgpack, Crypto++, croncpp, moodycamel concurrent queue.

Rust (CLI): clap, tokio, rustls, serde/serde_json/serde_yaml, anyhow. The CLI depends on the Rust SDK crate (`src/sdk/rust`).

Go (agent): gorilla/mux, gorilla/websocket, viper, zap, msgpack.
