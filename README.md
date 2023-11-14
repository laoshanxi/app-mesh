[![language.badge]][language.url] [![standard.badge]][standard.url] [![release.badge]][release.url] [![pypi.badge]][pypi.url] [![unittest.badge]][unittest.url] [![docker.badge]][docker.url] [![cockpit.badge]][cockpit.url]
[![Documentation Status](https://readthedocs.org/projects/app-mesh/badge/?version=latest)](https://app-mesh.readthedocs.io/en/latest/?badge=latest) [![Join the chat at https://gitter.im/app-mesh/community](https://badges.gitter.im/app-mesh/community.svg)](https://gitter.im/app-mesh/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
<a href="https://scan.coverity.com/projects/laoshanxi-app-mesh">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/21528.svg"/>
</a>
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh/badge)](https://api.securityscorecards.dev/projects/github.com/laoshanxi/app-mesh)

# App Mesh

App Mesh is a `Multi-Tenant`, `Cloud Native`, `Micro Service` application management platform, used to manage, schedule and monitor applications. Each app can be a specific microservice for service discovery or a normal app with replication, the app-mesh will guarantee all defined applications run on time with defined behavior and resource requests. The platform can run in standalone or cluster mode, and provide REST APIs, command-line and web-ui.

App Mesh is similar to Kubernetes but much more lightweight, supporting both container apps and native apps.

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/diagram.jpg" align=center /></div>

## Features

Feature | Description
---|---
Application management | 1. Manage independent applications and guard the process running, similar with systemd but more flexible (long/short running, periodic long running, cron schedule, customized day time and error handling control) and comprehensive monitoring (number of starts, return code, error message, health-check) for both native and docker application. <br> 2. Use SDK/CLI run application on a remote host with sync/async mode and fetch result to client. <br> 3. Full control of application lifecycle (cgroup for resource limitation, specific OS user for execution user). <br> 4. Interactive application start support specify input data by pipe and environment variables.<br> 5. All functionality provides by [CLI](https://app-mesh.readthedocs.io/en/latest/CLI.html), [REST](https://app-mesh.readthedocs.io/en/latest/Development.html#rest-apis), [SDK](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk) and [WebGUI](https://github.com/laoshanxi/app-mesh-ui) interface.<br>
Security |  ⚡️ [JWT authentication](https://app-mesh.readthedocs.io/en/latest/JWT.html) for CLI and REST interface <br> ⚡️ [LDAP support](https://app-mesh.readthedocs.io/en/latest/LDAP.html) <br> ⚡️ [Role based permission control](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html) <br> ⚡️ [Multi-factor authentication](https://app-mesh.readthedocs.io/en/latest/MFA.html)<br> SSL support (ECDH and secure ciphers) for REST http connection  <br> Multi-tenant support
Cloud native | Schedule cloud level applications for running on multile hosts with resource size request.<br> ⚡️ [Prometheus Exporter (build-in)](https://app-mesh.readthedocs.io/en/latest/PROMETHEUS.html) <br> ⚡️ [Grafana SimpleJson datasource](https://app-mesh.readthedocs.io/en/latest/GrafanaDataSource.html) <br> ⚡️ [Grafana Loki](https://app-mesh.readthedocs.io/en/latest/Loki.html) <br>⚡️ [Dockerfile](https://github.com/laoshanxi/app-mesh/blob/main/Dockerfile)
Micro service application | ⚡️ [Consul micro-service cluster management](https://app-mesh.readthedocs.io/en/latest/CONSUL.html)
Extra Features | Collect host/app resource usage <br> Remote run shell commands <br> Download/Upload files interface <br> Hot-update support `systemctl reload appmesh` <br> Bash completion <br> Reverse proxy <br> [Web GUI](https://github.com/laoshanxi/app-mesh-ui)
Platform support | X86_64 <br> ARM32 <br> ARM64
SDK | [Python](https://app-mesh.readthedocs.io/en/latest/api/appmesh_client.html) <br> [Golang](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/go/appmesh_client.go)

## Getting started

The [Installation doc](https://app-mesh.readthedocs.io/en/latest/Install.html) introduces how
to install App Mesh via docker-compose or native way and setup App Mesh cluster.

## Documentation

- [Read the Docs](https://app-mesh.readthedocs.io/)
- [REST API](https://app-mesh.readthedocs.io/en/latest/Development.html#rest-apis)
- [Command lines](https://app-mesh.readthedocs.io/en/latest/CLI.html)
- [Security](https://app-mesh.readthedocs.io/en/latest/JWT.html)

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
| Manage daemon process    |          |                                       | √                                |
| Manage docker app        | √        |                                       |
| Start check (avoid leak) | √        | √                                     |
| Session login            |          |                                       |
| Manage stdout/stderr     | √        | √                                     |
| Health check             | √        |                                       |
| Rich control options     | √        |                                       |
| Authentication           | √        | √                                     |
| Multi-tenant             | √        |                                       | √                                |

### Cluster mode

| Feature           | App Mesh | Kubernetes |
| ----------------- | -------- | ---------- |
| Easy deploy       | √        |
| More features     |          | √          |
| Non-container app | √        |
| Service expose    | √        | √          |
| Scheduler         | √        | √          |
| Definition file   | JSON     | YAML       |
| GUI               | √        | √          |
| Virtual Network   |          | √          |
| Monitor tools     | √        | √          |

---

### Component diagram

![block-diagram](https://github.com/laoshanxi/app-mesh/raw/main/docs/source/block_diagram.png)

---

## Success

- [Build a powerful monitor system with Grafana/Prometheus/Loki](https://app-mesh.readthedocs.io/en/latest/success/build_powerful_monitor_system_with_Grafana_Prometheus_Loki.html)
- [Customize application start behavior](https://app-mesh.readthedocs.io/en/latest/success/customize_app_startup_behavior.html)
- [Manage cluster-level microservice applications](https://app-mesh.readthedocs.io/en/latest/success/manage_cluster_level_microservice_applications.html)
- [Open service broker support local PV for Kubernetes](https://app-mesh.readthedocs.io/en/latest/success/open_service_broker_support_local_pv_for_K8S.html)
- [Promote native application to microservice application](https://app-mesh.readthedocs.io/en/latest/success/promote_native_app_to_microservice_app.html)
- [Secure REST file server](https://app-mesh.readthedocs.io/en/latest/success/secure_REST_file_server.html)
- [Standalone JWT server](https://app-mesh.readthedocs.io/en/latest/success/standalone_JWT_server.html)
- [Kubernetes run none-container applications](https://app-mesh.readthedocs.io/en/latest/success/kubernetes_run_native_application.html)
- [Remote execute](https://app-mesh.readthedocs.io/en/latest/success/remote_run_cli_and_python.html)
- [Python parallel run](https://app-mesh.readthedocs.io/en/latest/success/python_parallel_run.html)

---

## Library dependency

- [MessagePack](https://msgpack.org/)
- [boostorg/boost](https://github.com/boostorg/boost)
- [DOCGroup/ACE_TAO/ACE](https://github.com/DOCGroup/ACE_TAO)
- [libcpr/cpr](https://github.com/libcpr/cpr)
- [Thalhammer/jwt-cpp](https://github.com/Thalhammer/jwt-cpp)
- [nlohmann/json](https://json.nlohmann.me/)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)
- [zemasoft/wildcards](https://github.com/zemasoft/wildcards)
- [mariusbancila/croncpp](https://github.com/mariusbancila/croncpp)
- [log4cpp](http://log4cpp.sourceforge.net)
- [Crypto++](https://www.cryptopp.com)
- [ldap-cpp](https://github.com/AndreyBarmaley/ldap-cpp)
- [OATH Toolkit](http://www.nongnu.org/oath-toolkit/liboath-api)

[language.url]:   https://isocpp.org/
[language.badge]: https://img.shields.io/badge/language-C++-blue.svg
[standard.url]:   https://en.wikipedia.org/wiki/C%2B%2B#Standardization
[standard.badge]: https://img.shields.io/badge/C%2B%2B-11%2F14%2F17-blue.svg
[release.url]:    https://github.com/laoshanxi/app-mesh/releases
[release.badge]:  https://img.shields.io/github/v/release/laoshanxi/app-mesh.svg
[docker.url]:     https://hub.docker.com/repository/docker/laoshanxi/appmesh
[docker.badge]:   https://img.shields.io/docker/pulls/laoshanxi/appmesh.svg
[cockpit.url]:    https://github.com/laoshanxi/app-mesh-ui
[cockpit.badge]:  https://img.shields.io/badge/Cockpit-app--mesh--ui-blue?logo=appveyor
[unittest.url]:   https://github.com/catchorg/Catch2
[unittest.badge]: https://img.shields.io/badge/UnitTest-Catch2-blue?logo=appveyor
[pypi.badge]: https://img.shields.io/pypi/v/appmesh?label=PyPI%3Aappmesh
[pypi.url]: https://pypi.org/project/appmesh/
