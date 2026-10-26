[![language.badge]][language.url] [![standard.badge]][standard.url] [![unittest.badge]][unittest.url] [![Coverity](https://img.shields.io/coverity/scan/21528.svg)](https://scan.coverity.com/projects/laoshanxi-app-mesh) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh/badge)](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh) [![OpenSSF Baseline](https://www.bestpractices.dev/projects/12481/baseline)](https://www.bestpractices.dev/projects/12481) [![Documentation Status](https://readthedocs.org/projects/app-mesh/badge/?version=latest)](https://app-mesh.readthedocs.io/en/latest/?badge=latest)

[![release.badge]][release.url] [![docker.badge]][docker.url] [![pypi.badge]][pypi.url] [![npm.badge]][npm.url] [![cargo.badge]][cargo.url] [![cockpit.badge]][cockpit.url] [![Join the chat at https://gitter.im/app-mesh/community](https://badges.gitter.im/app-mesh/community.svg)](https://gitter.im/app-mesh/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

# App Mesh

**One secure, lightweight daemon to run, schedule, and remote-control apps across machines.**

## 🧭 Concepts

App Mesh gives you two capabilities: **Hosting** and **Computing**.

### 🎛 Hosting

Declare an app once. The daemon keeps it running.

- **Lifecycle** — start, stop, and recover the app after a crash or a daemon restart
- **Scheduling** — cron, fixed intervals, start and end dates, daily time windows
- **Protection** — health checks, CPU and memory limits, OS user, tenant isolation
- **Any app** — a native process or a Docker app

Think systemd on every machine. Or Kubernetes desired state, for any app.

### 🧮 Computing

Submit work to any node. Get the result back.

- **Command or script** — starts a new process, runs once
- **Task message** — reuses a warm app that is already running, no startup cost
- **Parallel and control** — fan out work across nodes; run sync or async, stream output, set timeouts
- **Workflow** — chain many work items into a DAG pipeline and run it natively
- **AI** — send task messages to a hosted LLM agent, or give coding agents a sandbox node to build and run

Think serverless, on your own machines.

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/diagram.svg" alt="App Mesh architecture" align=center /></div>

<details>
<summary>Internal component view</summary>

![block-diagram](https://github.com/laoshanxi/app-mesh/raw/main/docs/source/block_diagram.svg)

</details>

## ⚡ Quick Start

Start the daemon in Docker:

```shell
docker run -d --restart=always --name=appmesh --net=host -v appmesh-work:/opt/appmesh/work -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh:latest
```

The `appmesh-work` volume persists authentication state and application
definitions; without it, a recreated container loses the administrator
password and every registered app. The container runs as UID 482 — grant that
identity access to the Docker socket to manage Docker apps.

Host your first app with the `appm` CLI — open a shell in the daemon container:

```shell
$ docker exec -ti appmesh bash

# Sign in once (non-interactive)
$ /opt/appmesh/script/appmesh-auth.sh print-initial-password | appm logon -u admin@appmesh.local --password-stdin

# List registered applications
$ appm ls
ID  NAME      OWNER   ENABLED  HEALTH  PID  USER     MEMORY  %CPU  RETURN
0   py-task   system  Yes      OK      574  appmesh  32.5Mi  0     -
1   py-exec   system  -        -       -    -        -       -     -
2   identity  system  Yes      OK      344  appmesh  40.5Mi  0     -
3   dexuser   system  Yes      OK      573  appmesh  17.5Mi  0     -
4   workflow  system  Yes      OK      575  appmesh  13.7Mi  0     -

# Register a new application
$ appm add -a myapp -c "python3 -u -c 'import time; [print(i, time.ctime()) or time.sleep(1) for i in range(10)]'"

# View its live output
$ appm ls -a myapp -o
0 Wed Sep 16 10:56:12 2026
1 Wed Sep 16 10:56:13 2026
2 Wed Sep 16 10:56:14 2026

# appm -h for more usage
```

Send a task message to a running app through the SDK. Mint an admin token first (see the [authentication guide](https://app-mesh.readthedocs.io/en/latest/Authentication.html)):

```shell
$ export APPMESH_BEARER_TOKEN=$(/opt/appmesh/script/appmesh-auth.sh print-initial-password \
    | /opt/appmesh/script/appmesh-auth.sh user-token)
```

```python
import os
from appmesh import AppMeshClient
client = AppMeshClient(bearer_token=os.environ["APPMESH_BEARER_TOKEN"])

result_from_server = "0"
for i in range(10):
    task_data = f"print({result_from_server} + {i}, end='')"
    result_from_server = client.run_task(app_name="py-task", data=task_data)
    print(result_from_server)
```

For native packages (`.deb`/`.rpm`), systemd setup, and cluster initialization, see the [Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html) and the [Dockerfile](Dockerfile).

## 🚀 Core Capabilities

| Pillar    | Capability             | What you get                                                                                                                                                                                                                                                                          |
| --------- | ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Hosting   | Application management | Full remote CRUD and control — cgroup limits, OS user, environment variables, Docker apps, stdin/stdout — with monitoring of start counts, exit codes, errors, and [health checks](https://app-mesh.readthedocs.io/)                                                                  |
| Hosting   | Scheduling             | Long- and short-running apps, periodic jobs, cron expressions, custom timings, and policy-driven [start/exit behaviors](https://app-mesh.readthedocs.io/en/latest/success/customize_app_startup_behavior.html)                                                                        |
| Computing | Remote execution       | Run commands and scripts on any node; send [in-memory tasks](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html) to running applications for high-performance computing                                                                                                        |
| Computing | Workflow engine        | GitHub-Actions-style [YAML pipelines](https://app-mesh.readthedocs.io/en/latest/Workflow.html) with DAG scheduling, running natively on App Mesh                                                                                                                                      |
| Platform  | Security               | OAuth/OIDC bearer authentication (RFC 6750) with Principal-based RBAC and multi-tenant isolation; SSL/TLS on TCP/HTTP/WebSocket; HMAC-PSK internal verification                                                                                                                       |
| Platform  | Observability          | Built-in [Prometheus exporter](https://app-mesh.readthedocs.io/en/latest/PROMETHEUS.html), [Grafana datasource](https://app-mesh.readthedocs.io/en/latest/GrafanaDataSource.html), [Loki](https://app-mesh.readthedocs.io/en/latest/Loki.html) integration, host/app resource metrics |
| Platform  | Extras                 | File upload/download API, remote shell execution, hot config reload, bash completion                                                                                                                                                                                                  |

Runs on Linux, macOS, and Windows (x86 and ARM).

## 🔄 Workflow Pipeline

Define CI/CD pipelines as YAML — similar to GitHub Actions, but running natively on App Mesh with the built-in [Workflow Engine](https://app-mesh.readthedocs.io/en/latest/Workflow.html):

- **DAG scheduling** — jobs run in dependency order, independent jobs in parallel
- **4 step types** — shell commands, existing Apps, Task API messages, sub-workflows
- **Error handling** — retry with exponential backoff, `continue-on-error`, `finally` cleanup blocks
- **Expressions** — `${{ inputs.env }}`, `${{ steps.build.stdout }}`, `success()`, `failure()`, `always()`
- **Remote execution** — target specific nodes by label or hostname

```bash
appm workflow add -f pipeline.yaml        # register
appm workflow run pipeline -e env=prod -f # run and follow output
appm workflow runs pipeline               # view history
```

## 🤖 AI & LLM Integration

Agents are just managed Apps: the same RBAC, scheduling, secrets, health checks, and cluster forwarding as any other process — no sidecar, no privileged pod.

**Agent runtime — not Claude-only**

- **[LLM agent runtime](src/apps/llm-agent)** — a thin wrapper over the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk/python) hosted as a managed App. Runs Claude (Anthropic API, Amazon Bedrock, Google Vertex), or any other model — DeepSeek, Qwen, GLM, MiniMax, or anything OpenAI-compatible behind a gateway. Model credentials stay in secured (`-z`) env vars, never in files.
- **Sessions are stable working directories** — send again with the same `session_id` to continue a conversation, `session_close` to wipe it; the agent itself stores no history.

**Two consumption models, one substrate** ([design](docs/source/workflow/LLMAgentWorkflowDesign.md), [SOP](src/apps/llm-agent/SOP.md))

- **Batch / DAG** — a shared long-lived App answers each call with a final structured result; ideal for pipelines and batch scoring.
- **Interactive chat** — a per-session worker App streams tokens live to the web UI's Chat page; direct Task API + subscribe, no workflow engine in the path.

**LLM as a workflow step**

- The engine's [`message` step](docs/source/workflow/WorkflowSchema.md#step-type-message) puts the model into the DAG: `session_send` / `session_close` payloads, per-run session ids (`${{ workflow.run_id }}`), timeouts, failure propagation, and step-level resume — schedule it with cron, fan it out across nodes, or gate later steps on its answer.

**Cluster-native LLM nodes**

- The `laoshanxi/appmesh:llm` image ships the agent preinstalled and enabled. Run it as a dedicated node (see `appmesh_llm` in the [compose cluster](script/docker/docker-compose.yaml)); every peer reaches it with ordinary forwarding — `appm -F appmesh_llm …` routes exec, files, and tasks to the LLM node, and the web UI registers providers from a guided form (Agents → Register).

**AI tooling around the mesh**

- **[Remote sandbox for AI coding assistants](https://app-mesh.readthedocs.io/en/latest/REMOTE_SANDBOX.html)** — give agents an isolated build-and-run environment instead of your local shell.
- **[MCP server](src/integrations/mcp-server)** — manage App Mesh from AI clients over Model Context Protocol (Streamable HTTP with OAuth 2.1, RBAC enforced by the daemon).
- **[Remote execution skill](.agents/skills/appmesh-remote)** for Codex and Claude Code, **[MCP bridge](src/integrations/mcp-bridge)** for relaying stdio MCP servers over WebSocket, and **[MQTT bridge](src/integrations/mqtt)** for IoT scenarios.

## 🧰 Interfaces & SDKs

| Interface | Details                                                                                                                                                                                                                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| CLI       | [`appm` command reference](https://app-mesh.readthedocs.io/en/latest/CLI.html)                                                                                                                                                                                                                           |
| REST      | [REST APIs](https://app-mesh.readthedocs.io/en/latest/RESTAPI.html) · [OpenAPI spec](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/rest/openapi.yaml)                                                                              |
| Web GUI   | [app-mesh-ui](https://github.com/laoshanxi/app-mesh-ui)                                                                                                                                                                                                                                                  |
| SDKs      | [Python](https://app-mesh.readthedocs.io/en/latest/api/appmesh.html#module-appmesh.client_http) · [Golang](src/sdk/go/client_http.go) · [Rust](src/sdk/rust) · [Java](https://github.com/laoshanxi/app-mesh/packages/2227502) · [JavaScript](https://www.npmjs.com/package/appmesh) |

## 💡 Success Stories

**AI & automation**

- [Remote build-and-run sandbox for AI coding assistants](https://app-mesh.readthedocs.io/en/latest/REMOTE_SANDBOX.html)
- [LLM agent runtime hosted as an App Mesh app](src/apps/llm-agent) · [architecture and workflow design](docs/source/workflow/LLMAgentWorkflowDesign.md) ([SOP](src/apps/llm-agent/SOP.md))
- [Manage App Mesh from AI clients via MCP (HTTP + OAuth)](src/integrations/mcp-server)

**Computing**

- [In-memory remote task execution](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html)
- [Remote command and Python script execution](https://app-mesh.readthedocs.io/en/latest/success/remote_run_cli_and_python.html)
- [Parallel task execution with the Python SDK](https://app-mesh.readthedocs.io/en/latest/success/python_parallel_run.html)

**Operations & observability**

- [Observability stack with Grafana, Prometheus, and Loki](https://app-mesh.readthedocs.io/en/latest/success/build_powerful_monitor_system_with_Grafana_Prometheus_Loki.html)
- [Customize application startup and exit behavior](https://app-mesh.readthedocs.io/en/latest/success/customize_app_startup_behavior.html)
- [Promote a native application into a managed microservice](https://app-mesh.readthedocs.io/en/latest/success/promote_native_app_to_microservice_app.html)
- [Secure REST-based file server](https://app-mesh.readthedocs.io/en/latest/success/secure_REST_file_server.html)

**Platform & Kubernetes**

- [Run non-container applications on Kubernetes](https://app-mesh.readthedocs.io/en/latest/success/kubernetes_run_native_application.html)
- [Kubernetes local-PV provisioning via Open Service Broker](https://app-mesh.readthedocs.io/en/latest/success/open_service_broker_support_local_pv_for_K8S.html)

## 🆚 Comparison

| Feature                  | App Mesh | [systemd](https://systemd.io/) | [crontab](https://crontab.guru/) |
| ------------------------ | -------- | ------------------------------ | -------------------------------- |
| Schedule accuracy        | Seconds  | Seconds                        | Minutes                          |
| Language                 | C++17    | C                              | C                                |
| Web GUI                  | √        |                                |                                  |
| Command lines            | √        | √                              | √                                |
| SDK                      | √        |                                |                                  |
| Cron schedule expression | √        |                                | √                                |
| Manage docker app        | √        |                                |                                  |
| Session login            | √        |                                |                                  |
| Manage stdout/stderr     | √        | √                              |                                  |
| Health check             | √        |                                |                                  |
| Authentication           | √        |                                |                                  |
| Multi-tenant             | √        |                                | √                                |

## 📚 Documentation

- [Read the Docs](https://app-mesh.readthedocs.io/) — full documentation
- [Feature Overview](docs/source/FeatureOverview.md) — the full capability map behind Hosting and Computing
- [Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html)
- [Security](https://app-mesh.readthedocs.io/en/latest/Security.html)
- [Workflow Guide](https://app-mesh.readthedocs.io/en/latest/Workflow.html)

<details>
<summary>🔗 Library dependencies</summary>

- [MessagePack](https://github.com/msgpack/msgpack-c)
- [boostorg/boost](https://github.com/boostorg/boost)
- [Thalhammer/jwt-cpp](https://github.com/Thalhammer/jwt-cpp)
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [nfpm](https://github.com/goreleaser/nfpm)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)
- [zemasoft/wildcards](https://github.com/zemasoft/wildcards)
- [mariusbancila/croncpp](https://github.com/mariusbancila/croncpp)
- [spdlog](https://github.com/gabime/spdlog)
- [concurrentqueue](https://github.com/cameron314/concurrentqueue)
- [drogon](https://github.com/drogonframework/drogon)
- [trantor](https://github.com/an-tao/trantor)
- [jsoncpp](https://github.com/open-source-parsers/jsoncpp)

</details>

## Community & License

Questions and discussions are welcome on [Gitter](https://gitter.im/app-mesh/community). Licensed under the [MIT License](LICENSE).

[language.url]: https://isocpp.org/
[language.badge]: https://img.shields.io/badge/language-C++-blue.svg
[standard.url]: https://en.wikipedia.org/wiki/C%2B%2B#Standardization
[standard.badge]: https://img.shields.io/badge/C%2B%2B-11%2F14%2F17%2F20-blue.svg
[release.url]: https://github.com/laoshanxi/app-mesh/releases
[release.badge]: https://img.shields.io/github/v/release/laoshanxi/app-mesh?label=Github%20package
[docker.url]: https://hub.docker.com/repository/docker/laoshanxi/appmesh
[docker.badge]: https://img.shields.io/docker/pulls/laoshanxi/appmesh.svg
[cockpit.url]: https://github.com/laoshanxi/app-mesh-ui
[cockpit.badge]: https://img.shields.io/badge/Web%20GUI-app--mesh--ui-blue
[unittest.url]: https://github.com/catchorg/Catch2
[unittest.badge]: https://img.shields.io/badge/UnitTest-Catch2-blue?logo=appveyor
[pypi.badge]: https://img.shields.io/pypi/v/appmesh?label=PyPI%3Aappmesh
[pypi.url]: https://pypi.org/project/appmesh/
[npm.badge]: https://img.shields.io/npm/v/appmesh?label=npm%3Aappmesh
[npm.url]: https://www.npmjs.com/package/appmesh
[cargo.badge]: https://img.shields.io/crates/v/appmesh
[cargo.url]: https://crates.io/crates/appmesh
