[![language.badge]][language.url] [![standard.badge]][standard.url] [![unittest.badge]][unittest.url] [![docker.badge]][docker.url] [![cockpit.badge]][cockpit.url]
[![Documentation Status](https://readthedocs.org/projects/app-mesh/badge/?version=latest)](https://app-mesh.readthedocs.io/en/latest/?badge=latest) [![Join the chat at https://gitter.im/app-mesh/community](https://badges.gitter.im/app-mesh/community.svg)](https://gitter.im/app-mesh/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
<a href="https://scan.coverity.com/projects/laoshanxi-app-mesh">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/21528.svg"/>
</a>
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh/badge)](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh)
[![release.badge]][release.url] [![pypi.badge]][pypi.url] [![npm.badge]][npm.url] [![cargo.badge]][cargo.url]

# Advanced Application Management Platform

App Mesh is a secure platform for running, managing, and interacting with applications as managed services.

## 1. Application Management

Manages applications similarly to systemd services or Docker-managed processes with more advanced features:

```shell
# List registered applications
$ appc ls
ID  NAME    OWNER  STATUS    HEALTH  PID  USER  MEMORY    %CPU  RETURN  AGE  DURATION  STARTS  COMMAND
1   pyexec  mesh   disabled  -       -    -     -         -     -       37s  -         0       "python3 ../../bin/py_exec.py"
2   ping    mesh   enabled   OK      747  root  5.9 MiB   0     -       37s  37s       1       "ping cloudflare.com"
3   pytask  mesh   enabled   OK      748  root  29.7 MiB  0     -       37s  37s       1       "python3 ../../bin/py_task.py"
# Add app
$ appc add -a myapp -c "ping www.baidu.com"
# View app
$ appc ls -a myapp -o
PING www.baidu.com (183.2.172.17) 56(84) bytes of data.
64 bytes from 183.2.172.17 (183.2.172.17): icmp_seq=1 ttl=52 time=34.9 ms
64 bytes from 183.2.172.17 (183.2.172.17): icmp_seq=2 ttl=52 time=35.1 ms
64 bytes from 183.2.172.17 (183.2.172.17): icmp_seq=3 ttl=52 time=35.3 ms
# appc -h for more usage
```

## 2. Sending Tasks to a Running Application

Interacting with your app instance, send data to your app and recieve response via SDK:

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

App Mesh is a multi-tenant application management platform designed for cloud-native environments. It efficiently manages, schedules, and monitors both microservices and traditional applications, offering a lightweight alternative to Kubernetes. App Mesh bridges the gap between simple process managers and complex container orchestration systems, making it ideal for organizations seeking to modernize their infrastructure without adopting full container-native complexity. Supporting both containerized and native applications, it provides a versatile solution for diverse enterprise needs.

## Features

Feature | Description
---|---
Application management <br> (Advanced systemd) | 🧩 <b>Application Management (CURD) with Full Remote Control</b> – including cgroup, OS user, environment variables, Docker, stdin, and stdout – along with comprehensive monitoring (start counts, exit codes, error messages, health checks). <br> 🧩 <b>Fine-Grained Application Behavior Control & Scheduling</b> – supports long- and short-running tasks, periodic jobs, cron schedules, custom timings, and robust error handling. <br> 🧩 <b>Multi-Tenancy</b> –  built-in user ownership model and access controls. <br> 🧩 <b>Unified Access Interface</b> – interact via [CLI](https://app-mesh.readthedocs.io/en/latest/CLI.html), [REST](https://app-mesh.readthedocs.io/en/latest/Development.html#rest-apis), [SDK](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk) or [WebGUI](https://github.com/laoshanxi/app-mesh-ui).<br>
Computing | 🚀 [High-performance in-memory computing](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html) <br> ▶️ [Remote execution](https://app-mesh.readthedocs.io/en/latest/success/remote_run_cli_and_python.html)
Security |  🔐 Authentication: [OAuth](src/sdk/python/test/test_oauth2.py), [2FA](https://app-mesh.readthedocs.io/en/latest/MFA.html), YAML-based storage (local file or Consul for clustering) <br> 🔐 Authorization: [JWT](https://app-mesh.readthedocs.io/en/latest/JWT.html), [RBAC](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html), multi-tenant isolation <br> 🔐 Protection: SSL/TLS for `TCP`/`HTTP`/`WebSocket`, CSRF tokens, HMAC with PSK for non-token verification
Cloud Native | Schedule cloud-level applications to run on multiple hosts with resource size requests. <br> 🌩️ [Prometheus Exporter (build-in)](https://app-mesh.readthedocs.io/en/latest/PROMETHEUS.html) <br> 🌩️ [Grafana SimpleJson datasource](https://app-mesh.readthedocs.io/en/latest/GrafanaDataSource.html) <br> 🌩️ [Grafana Loki](https://app-mesh.readthedocs.io/en/latest/Loki.html) <br> 🌩️ [Dockerfile](https://github.com/laoshanxi/app-mesh/blob/main/Dockerfile) <br> 🧱 [Consul micro-service cluster management](https://app-mesh.readthedocs.io/en/latest/CONSUL.html)
Extra Features | Collect host/app resource usage <br> Remote shell command execution <br> File upload/download interface <br> Hot-update support `systemctl reload appmesh` <br> Bash completion <br> Reverse proxy <br> 🌐[Web GUI](https://github.com/laoshanxi/app-mesh-ui)
Platform support | X86_64, ARM32, ARM64
SDK | [C++](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/cpp) <br> [Rust](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/rust) <br> [Python](https://app-mesh.readthedocs.io/en/latest/api/appmesh.html#module-appmesh.client_http) <br> [Golang](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/go/client_http.go) <br> [JavaScript](https://www.npmjs.com/package/appmesh) <br> [Java](https://github.com/laoshanxi/app-mesh/packages/2227502) <br> [Swagger OpenAPI Specification](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/rest/openapi.yaml)
Echosystem | [Model Context Protocol (MCP)](src/sdk/mcp) <br> [IoT MQTT](src/sdk/mqtt)

## Getting started

Refer to the [Installation doc](https://app-mesh.readthedocs.io/en/latest/Install.html) to learn how to install App Mesh via Docker Compose or natively and set up an App Mesh cluster.

<div align=center><img src="https://github.com/laoshanxi/picture/raw/master/appmesh/diagram.png" align=center /></div>

## Documentation

- [Read the Docs](https://app-mesh.readthedocs.io/)
- [REST API](https://app-mesh.readthedocs.io/en/latest/Development.html#rest-apis)
- [Command lines](https://app-mesh.readthedocs.io/en/latest/CLI.html)
- [Security](https://app-mesh.readthedocs.io/en/latest/Security.html)

## Comparison

### Standalone mode

| Feature                  | App Mesh | [Supervisor](http://supervisord.org/) | [crontab](https://crontab.guru/) |
| ------------------------ | -------- | ------------------------------------- | -------------------------------- |
| Accuracy                 | Seconds  | Seconds                               | Minutes                          |
| Language                 | C++11    | Python                                | C                                |
| Web GUI                  | √        | √                                     |
| Command lines            | √        | √                                     | √                                |
| SDK                      | √        |                                       |
| Cron schedule expression | √        |                                       | √                                |
| Manage docker app        | √        |                                       |
| Session login            | √        |                                       |
| Manage stdout/stderr     | √        | √                                     |
| Health check             | √        |                                       |
| Authentication           | √        | √                                     |
| Multi-tenant             | √        |                                       | √                                |

### Cluster mode

| Feature           | App Mesh | Kubernetes |
| ----------------- | -------- | ---------- |
| Easy deploy       | √        |
| Non-container app | √        |
| Service expose    | √        | √          |
| Scheduler         | √        | √          |
| Definition file   | YAML     | YAML       |
| GUI               | √        | √          |
| Virtual Network   |          | √          |
| Monitor tools     | √        | √          |
| [Remote task](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html)   | √        |            |

---

### Mind diagram

![mind-diagram](https://github.com/laoshanxi/picture/raw/master/appmesh/mind.png)

---

## Success

- [In-memory remote task execute](https://app-mesh.readthedocs.io/en/latest/RemoteTask.html)
- [Build a powerful monitor system with Grafana/Prometheus/Loki](https://app-mesh.readthedocs.io/en/latest/success/build_powerful_monitor_system_with_Grafana_Prometheus_Loki.html)
- [Customize application start behavior](https://app-mesh.readthedocs.io/en/latest/success/customize_app_startup_behavior.html)
- [Open service broker support local PV for Kubernetes](https://app-mesh.readthedocs.io/en/latest/success/open_service_broker_support_local_pv_for_K8S.html)
- [Promote native application to microservice application](https://app-mesh.readthedocs.io/en/latest/success/promote_native_app_to_microservice_app.html)
- [Secure REST file server](https://app-mesh.readthedocs.io/en/latest/success/secure_REST_file_server.html)
- [Standalone JWT server](https://app-mesh.readthedocs.io/en/latest/success/standalone_JWT_server.html)
- [Kubernetes run none-container applications](https://app-mesh.readthedocs.io/en/latest/success/kubernetes_run_native_application.html)
- [Remote execute](https://app-mesh.readthedocs.io/en/latest/success/remote_run_cli_and_python.html)
- [Python parallel run](https://app-mesh.readthedocs.io/en/latest/success/python_parallel_run.html)
- [Secure consul cluster](https://app-mesh.readthedocs.io/en/latest/success/secure_consul_cluster.html)
- [JWT service with REST and UI](https://github.com/laoshanxi/app-mesh/blob/main/script/docker-compose-auth-service.yaml)

---

## Library dependency

- [MessagePack](https://msgpack.org/)
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
- [uWebSockets](https://github.com/uNetworking/uWebSockets)

[language.url]: https://isocpp.org/
[language.badge]: https://img.shields.io/badge/language-C++-blue.svg
[standard.url]: https://en.wikipedia.org/wiki/C%2B%2B#Standardization
[standard.badge]: https://img.shields.io/badge/C%2B%2B-11%2F14%2F17-blue.svg
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
