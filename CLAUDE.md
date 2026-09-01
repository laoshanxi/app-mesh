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

### Rule 6 — Token budgets are not advisory
Per-task: 4,000 tokens. Per-session: 30,000 tokens.
If approaching budget, summarize and start fresh.
Surface the breach. Do not silently overrun.

### Rule 7 — Surface conflicts, don't average them
If two patterns contradict, pick one (more recent / more tested).
Explain why. Flag the other for cleanup.
Don't blend conflicting patterns.

### Rule 8 — Read before you write
Before adding code, read exports, immediate callers, shared utilities.
"Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.

### Rule 9 — Tests verify intent, not just behavior
Tests must encode WHY behavior matters, not just WHAT it does.
A test that can't fail when business logic changes is wrong.

### Rule 10 — Checkpoint after every significant step
Summarize what was done, what's verified, what's left.
Don't continue from a state you can't describe back.
If you lose track, stop and restate.

### Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

### Rule 12 — Fail loud
"Completed" is wrong if anything was skipped silently.
"Tests pass" is wrong if any were skipped.
Default to surfacing uncertainty, not hiding it.

## Project Overview

App Mesh is a C++17 cross-platform (Linux/macOS/Windows) application management platform — one secure daemon to run, schedule, and remote-control apps across machines, with Dex/OIDC bearer authentication, Principal-based RBAC, REST/WebSocket/TCP interfaces, and SDKs in Python, Go, Rust, Java, JavaScript, and C++.

## Daemon Ports

Three listener ports are defined by `src/daemon/config.yaml` (`REST` section; env override `APPMESH_REST_<Key>`, e.g. `APPMESH_REST_RestListenPort`):

| Port | Config key | Transport / purpose |
|------|------------|---------------------|
| 6060 | `RestListenPort` | HTTPS REST API — the primary management surface (also what the Go agent reverse-proxies) |
| 6059 | `RestTcpPort` | TCP API — msgpack-framed protocol used by SDK clients (`ClientTCP`) |
| 6058 | `WebSocketPort` | WSS API — WebSocket transport used by SDK clients and event subscribe (`ClientWSS`) |

All three authenticate the same Dex bearer. Additional ports: Dex itself listens on 6062 (issuer) and 6063 (telemetry healthz) when the bundled auth stack runs. The Go agent's Prometheus exporter uses the fixed convention **6061** when enabled (`APPMESH_REST_PrometheusExporterListenPort`, default `0` = off; all docker-compose deployments enable 6061).

## Binary Inspection Tools

When analyzing built binaries or debugging native issues, binary-inspection tooling is allowed and encouraged: `otool`/`nm`/`strings`/`dSYMutil` on macOS (Linux: `objdump`/`readelf`/`ldd`), and language servers (LSP/clangd via the IDE) for code navigation. Prefer these over guesswork when verifying symbol presence, linked libraries, stripped symbols, or crash backtraces.

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

# CLI build (Rust)
cd src/cli && cargo build --release

# CLI unit tests
cd src/cli && cargo test

# CLI integration tests (requires running daemon)
cd src/cli && cargo test --test remote_test -- --ignored --test-threads=1

# SDK tests
cd src/sdk/python/test && python3 -m unittest --verbose
go test ./src/sdk/go/ -test.v
cd src/sdk/rust && cargo test
```

CMake targets `python_tests`, `go_tests`, and `rust_tests` also exist.

## Architecture

### Daemon (`src/daemon/`)

The core service. Initialization flows through `main.cpp`: ACE framework init → config → SSL → security → app recovery → REST server → worker pool → ACE reactor event loop.

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
| `HMACVerifierSingleton` | `HMACVerifier` | `security/HMACVerifier.h` |

Other singletons use `static instance()`: `Configuration`, `Security`, `ResourceCollection`, `PersistManager`, and `HealthCheckTask`.

**Request flow:** Client → `SocketServer` (accept) → `SocketStream` (parse HTTP) → `WORKER` queue (lock-free `moodycamel::BlockingConcurrentQueue`) → `RestHandler` (regex-based route dispatch) → handler method → response.

### Common Library (`src/common/`)

Shared C++ library used by the daemon. Notable:
- `StreamLogger.h` — logging macros (`LOG_DBG`, `LOG_INF`, `LOG_WAR`, `LOG_ERR`) wrapping spdlog
- `Utility.h` — string ops, file helpers, ID generation
- `DateTime.h` / `DurationParse.h` — time and duration parsing
- `JwtHelper.h` — bearer normalization and unverified token parsing used only alongside OIDC verification
- `RestClient.h` — HTTP client for inter-service calls
- `lwsservice/` — libwebsockets server/client wrappers

### CLI (`src/cli/`)

`appm` command-line tool, written in Rust. Uses clap for argument parsing and the Rust SDK (`src/sdk/rust`) for WSS communication with the daemon. Key structure:
- `src/main.rs` — entry point, clap command definitions
- `src/commands/` — subcommand handlers (Dex bearer import, app management, config, file, run)
- `tests/integration_test.rs` — CLI argument parsing and subcommand tests (no daemon needed)
- `tests/remote_test.rs` — integration tests against a running daemon (run with `--ignored`)

### Agent (`src/sdk/agent/`)

REST proxy service for the daemon (`appmesh`), written in Go. Accepts HTTP requests from clients and forwards them to the daemon via TCP, offloading traffic and reducing pressure on the C++ core. Also provides a Docker daemon reverse proxy (`/appmesh/docker/*`), and Prometheus metrics exporter.

### SDKs (`src/sdk/`)

| SDK | Language | Transport |
|-----|----------|-----------|
| `rust/` | Rust | HTTP, TCP, WSS |
| `python/` | Python | HTTP, TCP, WSS |
| `go/` | Go | HTTP, TCP, WSS |
| `java/` | Java | HTTP, TCP, WSS |
| `javascript/` | JavaScript | HTTP, TCP |
| `cpp/` | C++ | HTTP |

Each SDK provides client libraries for interacting with the daemon plus a server-side interface for receiving tasks.

### MCP (`src/sdk/mcp_server/`, `src/sdk/mcp_bridge/`)

Model Context Protocol integration, enabling AI agents to manage applications via MCP. Two flavors:
- `mcp_server/` — standalone MCP OAuth Resource Server over **Streamable HTTP**. It validates Dex access tokens against the canonical issuer, may reach Dex through a separately configured access address, and forwards the caller bearer unchanged to App Mesh. It does not mint a second token or expose an upstream IdP. Designed to run as an App Mesh App.
- `mcp_bridge/` — a stdio MCP server plus `mcp_pipe.py`, a stdio↔WebSocket tunnel for relaying a local MCP server out to a remote LLM gateway.

### LLM Agent (`src/sdk/llm-agent/`)

LLM agent runtime that runs **as an App Mesh App** (Python package `llm_agent`). A thin wrapper around the official **Claude Agent SDK** (built on Claude Code — runs Claude by default, but can also target other models: Bedrock/Vertex, or DeepSeek/Qwen/GLM/MiniMax/OpenAI via an Anthropic-compatible endpoint). The SDK drives a Claude Code CLI as a subprocess; the `claude-agent-sdk` wheel bundles that CLI (no Node.js needed). The default Docker image keeps the llm-agent App package and `claude-agent-sdk` out of the base runtime; use the `llm_agent` Docker target / `laoshanxi/appmesh:llm` image when this optional App is needed. The agent loop, tools (Claude Code's built-in Read/Write/Edit/Bash/…), and conversation history are all the SDK's; llm-agent only routes `session_send`/`session_close` over the task RPC and gives each session a stable workdir (`<workspace>/<session_id>`) that keys the SDK's on-disk history (continuing a session = same `session_id`). Two roles: a shared App for batch/DAG (Scenario A) and an admin-provisioned per-session worker App for interactive streaming (Scenario B). No auth/quota/tenant in the agent itself — the daemon authorizes `run_task` (RBAC + the worker App's `permission`); the model credential is a secured env var (`ANTHROPIC_API_KEY` for the Anthropic API; the backend's equivalent otherwise). See `src/sdk/llm-agent/README.md`.

## Code Conventions

- C++ standard tiers: C++11 (GCC < 5), C++14 (GCC 5–7), C++17 (GCC 8+), C++20 (Windows). `-Wall` enabled. Code must compile under C++11 for CentOS 7 (GCC 4.8.5); polyfills for `std::make_unique` and `std::exchange` are in `src/common/Utility.h`.
- CamelCase for classes, `m_` prefix for member variables.
- Logging: `LOG_DBG << "msg";` — never `std::cout` or `printf`.
- Config env overrides: `APPMESH_<Section>_<Key>` (e.g. `APPMESH_REST_RestListenPort=6060`).
- REST API spec: `src/daemon/rest/openapi.yaml` (OpenAPI 3.1.0) — keep this in sync with handler changes.
- Technical documentation: write in ASD-STE100 Simplified Technical English.
- Pre-commit hooks enforce: cpplint, pylint, golangci-lint, shellcheck, eslint, Checkstyle, gitleaks, trailing-whitespace, end-of-file-fixer.

## Key Dependencies

C++ (daemon): ACE (networking/threading/reactor), Boost, OpenSSL, spdlog, nlohmann/json, yaml-cpp, jwt-cpp, prometheus-cpp, uWebSockets (C++17+, libwebsockets as fallback for older GCC), libcurl, uriparser, msgpack, Crypto++, croncpp, moodycamel concurrent queue.

Rust (CLI): clap, tokio, rustls, serde/serde_json/serde_yaml, anyhow. The CLI depends on the Rust SDK crate (`src/sdk/rust`).

Go (agent): gorilla/mux, gorilla/websocket, viper, zap, msgpack.
