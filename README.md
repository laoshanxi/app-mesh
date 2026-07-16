[![language.badge]][language.url] [![standard.badge]][standard.url] [![unittest.badge]][unittest.url] [![Coverity](https://img.shields.io/coverity/scan/21528.svg)](https://scan.coverity.com/projects/laoshanxi-app-mesh) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh/badge)](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh) [![OpenSSF Baseline](https://www.bestpractices.dev/projects/12481/baseline)](https://www.bestpractices.dev/projects/12481) [![Documentation Status](https://readthedocs.org/projects/app-mesh/badge/?version=latest)](https://app-mesh.readthedocs.io/en/latest/?badge=latest)

[![release.badge]][release.url] [![docker.badge]][docker.url] [![pypi.badge]][pypi.url] [![npm.badge]][npm.url] [![cargo.badge]][cargo.url] [![cockpit.badge]][cockpit.url] [![Join the chat at https://gitter.im/app-mesh/community](https://badges.gitter.im/app-mesh/community.svg)](https://gitter.im/app-mesh/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

# App Mesh

**App Mesh = systemd + cron + remote execution + API.**

A lightweight, secure platform that runs, schedules, and remote-controls applications across machines — one C++ daemon with JWT/RBAC security, a CLI, REST APIs, SDKs in 6 languages, and a built-in workflow engine.

Use App Mesh to:

- **Operate services** — manage long-running processes like systemd does, plus health checks, cgroup limits, Docker apps, multi-tenancy, and a [Web GUI](https://github.com/laoshanxi/app-mesh-ui).
- **Execute remotely** — run commands, scripts, or [in-memory tasks](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html) on any node via CLI, REST, or SDK.
- **Power AI agents** — provide [sandboxed build-and-run environments](https://app-mesh.readthedocs.io/en/latest/REMOTE_SANDBOX.html) for AI coding assistants, [MCP servers](src/sdk/mcp_server), and [LLM agent runtimes](src/sdk/llm-agent).

<div align=center><img src="https://github.com/laoshanxi/picture/raw/master/appmesh/diagram.png" align=center /></div>

## ⚡ Quick Start

Start the daemon in Docker:

```shell
docker run -d -p 6060:6060 --restart=always --name=appmesh --net=host -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh:latest
```

Manage applications with the `appm` CLI:

```shell
# List registered applications
$ appm ls
ID  NAME    OWNER  STATUS    HEALTH  PID  USER  MEMORY    %CPU  RETURN  AGE  DURATION  STARTS  COMMAND
1   pyexec  mesh   disabled  -       -    -     -         -     -       37s  -         0       "python3 ../../bin/py_exec.py"
2   ping    mesh   enabled   OK      747  root  5.9 MiB   0     -       37s  37s       1       "ping cloudflare.com"
3   pytask  mesh   enabled   OK      748  root  29.7 MiB  0     -       37s  37s       1       "python3 ../../bin/py_task.py"

# Register a new application
$ appm add -a myapp -c "ping www.baidu.com"

# View its live output
$ appm ls -a myapp -o
PING www.baidu.com (183.2.172.17) 56(84) bytes of data.
64 bytes from 183.2.172.17 (183.2.172.17): icmp_seq=1 ttl=52 time=34.9 ms

# appm -h for more usage
```

Send tasks to a running application and get responses back through the SDK:

```python
from appmesh import AppMeshClient
client = AppMeshClient()
client.login("USER-NAME", "USER-PWD")

result_from_server = "0"
for i in range(10):
    task_data = f"print({result_from_server} + {i}, end='')"
    result_from_server = client.run_task(app_name="pytask", data=task_data)
    print(result_from_server)
```

For native packages (`.deb`/`.rpm`), systemd setup, and cluster initialization, see the [Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html) and the [Dockerfile](Dockerfile).

## 🚀 Core Capabilities

| Capability             | What you get                                                                                                                                                                                                        |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Application management | Full remote CRUD and control — cgroup limits, OS user, environment variables, Docker apps, stdin/stdout — with monitoring of start counts, exit codes, errors, and [health checks](https://app-mesh.readthedocs.io/) |
| Scheduling             | Long- and short-running apps, periodic jobs, cron expressions, custom timings, and policy-driven [start/exit behaviors](https://app-mesh.readthedocs.io/en/latest/success/customize_app_startup_behavior.html)       |
| Remote execution       | Run commands and scripts on any node; send [in-memory tasks](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html) to running applications for high-performance computing                                       |
| Workflow engine        | GitHub-Actions-style [YAML pipelines](https://app-mesh.readthedocs.io/en/latest/Workflow.html) with DAG scheduling, running natively on App Mesh                                                                     |
| Security               | [JWT](https://app-mesh.readthedocs.io/en/latest/JWT.html) + [RBAC](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html) with multi-tenant isolation; [OAuth](src/sdk/python/test/test_oauth2.py), [2FA](https://app-mesh.readthedocs.io/en/latest/MFA.html); YAML-based user storage (local, or Consul for clustering); SSL/TLS on TCP/HTTP/WebSocket; CSRF tokens; HMAC-PSK verification |
| Observability          | Built-in [Prometheus exporter](https://app-mesh.readthedocs.io/en/latest/PROMETHEUS.html), [Grafana datasource](https://app-mesh.readthedocs.io/en/latest/GrafanaDataSource.html), [Loki](https://app-mesh.readthedocs.io/en/latest/Loki.html) integration, host/app resource metrics |
| Clustering             | [Consul-based cluster management](https://app-mesh.readthedocs.io/en/latest/CONSUL.html) and request forwarding across nodes                                                                                         |
| Extras                 | File upload/download API, remote shell execution, hot config reload, bash completion                                                                                                                                 |

Runs on Linux, macOS, and Windows (x86 and ARM).

## 🤖 AI & LLM Integration

App Mesh's secure remote-execution core makes it a natural runtime for AI workloads:

- **[Remote sandbox for AI coding assistants](https://app-mesh.readthedocs.io/en/latest/REMOTE_SANDBOX.html)** — give agents an isolated build-and-run environment instead of your local shell.
- **[MCP server](src/sdk/mcp_server)** — manage App Mesh from AI clients over Model Context Protocol (Streamable HTTP with OAuth 2.1, RBAC enforced by the daemon).
- **[LLM agent runtime](src/sdk/llm-agent)** — host Claude-Agent-SDK-based agents as managed App Mesh applications; see the [architecture design](docs/source/workflow/LLMAgentWorkflowDesign.md).
- **[Claude Code plugin](src/sdk/claude-plugin)** and **[MQTT bridge](src/sdk/mqtt)** for IoT scenarios.

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

## 🧰 Interfaces & SDKs

| Interface | Details                                                                                                                                     |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| CLI       | [`appm` command reference](https://app-mesh.readthedocs.io/en/latest/CLI.html)                                                               |
| REST      | [REST APIs](https://app-mesh.readthedocs.io/en/latest/Development.html#rest-apis) · [OpenAPI spec](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/rest/openapi.yaml) |
| Web GUI   | [app-mesh-ui](https://github.com/laoshanxi/app-mesh-ui)                                                                                       |
| SDKs      | [Python](https://app-mesh.readthedocs.io/en/latest/api/appmesh.html#module-appmesh.client_http) · [Golang](src/sdk/go/client_http.go) · [Rust](src/sdk/rust) · [Java](https://github.com/laoshanxi/app-mesh/packages/2227502) · [JavaScript](https://www.npmjs.com/package/appmesh) · [C++](src/sdk/cpp) |

## 💡 Success Stories

**AI & automation**

- [Remote build-and-run sandbox for AI coding assistants](https://app-mesh.readthedocs.io/en/latest/REMOTE_SANDBOX.html)
- [LLM agent runtime hosted as an App Mesh app](src/sdk/llm-agent) · [architecture and workflow design](docs/source/workflow/LLMAgentWorkflowDesign.md)
- [Manage App Mesh from AI clients via MCP (HTTP + OAuth)](src/sdk/mcp_server)

**Remote computing**

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
- [Secure multi-node cluster with Consul](https://app-mesh.readthedocs.io/en/latest/success/secure_consul_cluster.html)
- [Standalone JWT authentication server](https://app-mesh.readthedocs.io/en/latest/success/standalone_JWT_server.html) · [JWT auth service with REST API and web UI](script/docker/docker-compose-auth-service.yaml)

## 🆚 Comparison

| Feature                  | App Mesh | [Supervisor](http://supervisord.org/) | [crontab](https://crontab.guru/) |
| ------------------------ | -------- | ------------------------------------- | -------------------------------- |
| Schedule accuracy        | Seconds  | Seconds                               | Minutes                          |
| Language                 | C++17    | Python                                | C                                |
| Web GUI                  | √        | √                                     |                                  |
| Command lines            | √        | √                                     | √                                |
| SDK                      | √        |                                       |                                  |
| Cron schedule expression | √        |                                       | √                                |
| Manage docker app        | √        |                                       |                                  |
| Session login            | √        |                                       |                                  |
| Manage stdout/stderr     | √        | √                                     |                                  |
| Health check             | √        |                                       |                                  |
| Authentication           | √        | √                                     |                                  |
| Multi-tenant             | √        |                                       | √                                |

## 📚 Documentation

- [Read the Docs](https://app-mesh.readthedocs.io/) — full documentation
- [Installation Guide](https://app-mesh.readthedocs.io/en/latest/Install.html)
- [Security](https://app-mesh.readthedocs.io/en/latest/Security.html)
- [Workflow Guide](https://app-mesh.readthedocs.io/en/latest/Workflow.html)

<details>
<summary>🔗 Library dependencies</summary>

- [MessagePack](https://github.com/msgpack/msgpack-c)
- [boostorg/boost](https://github.com/boostorg/boost)
- [ACE_TAO/ACE](https://github.com/DOCGroup/ACE_TAO)
- [Thalhammer/jwt-cpp](https://github.com/Thalhammer/jwt-cpp)
- [nlohmann/json](https://json.nlohmann.me)
- [yaml-cpp](https://github.com/jbeder/yaml-cpp)
- [nfpm](https://github.com/goreleaser/nfpm)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)
- [zemasoft/wildcards](https://github.com/zemasoft/wildcards)
- [mariusbancila/croncpp](https://github.com/mariusbancila/croncpp)
- [spdlog](https://github.com/gabime/spdlog)
- [Crypto++](https://www.cryptopp.com)
- [concurrentqueue](https://github.com/cameron314/concurrentqueue)
- [libwebsockets](https://libwebsockets.org/)

</details>

## Community & License

Questions and discussions are welcome on [Gitter](https://gitter.im/app-mesh/community). Licensed under the [MIT License](LICENSE).

[language.url]: https://isocpp.org/
[language.badge]: https://img.shields.io/badge/language-C++-blue.svg
[standard.url]: https://en.wikipedia.org/wiki/C%2B%2B#Standardization
[standard.badge]: https://img.shields.io/badge/C%2B%2B-14%2F17%2F20-blue.svg
[release.url]: https://github.com/laoshanxi/app-mesh/releases
[release.badge]: https://img.shields.io/github/v/release/laoshanxi/app-mesh?label=Github%20package
[docker.url]: https://hub.docker.com/repository/docker/laoshanxi/appmesh
[docker.badge]: https://img.shields.io/docker/pulls/laoshanxi/appmesh.svg
[cockpit.url]: https://github.com/laoshanxi/app-mesh-ui
[cockpit.badge]: https://img.shields.io/badge/Cockpit-app--mesh--ui-blue?logo=appveyor
[unittest.url]: https://github.com/catchorg/Catch2
[unittest.badge]: https://img.shields.io/badge/UnitTest-Catch2-blue?logo=appveyor
[pypi.badge]: https://img.shields.io/pypi/v/appmesh?label=PyPI%3Aappmesh
[pypi.url]: https://pypi.org/project/appmesh/
[npm.badge]: https://img.shields.io/npm/v/appmesh?label=npm%3Aappmesh
[npm.url]: https://www.npmjs.com/package/appmesh
[cargo.badge]: https://img.shields.io/crates/v/appmesh
[cargo.url]: https://crates.io/crates/appmesh
