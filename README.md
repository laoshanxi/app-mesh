[![language.badge]][language.url] [![standard.badge]][standard.url] [![release.badge]][release.url] [![unittest.badge]][unittest.url] [![docker.badge]][docker.url] [![cockpit.badge]][cockpit.url]
[![Documentation Status](https://readthedocs.org/projects/app-mesh/badge/?version=latest)](https://app-mesh.readthedocs.io/en/latest/?badge=latest) [![Join the chat at https://gitter.im/app-mesh/community](https://badges.gitter.im/app-mesh/community.svg)](https://gitter.im/app-mesh/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
<a href="https://scan.coverity.com/projects/laoshanxi-app-mesh">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/21528.svg"/>
</a>

# App Mesh

App Mesh is a `Multi Tenant`, `Cloud Native`, `Micro Service` application management platform, used to manage, schedule and monitor applications. Each app can be a specific micro service for service discover or normal app with replication, the app-mesh will guarantee all defined applications running on-time with defined behavior and resources requests. The platform can run as standalone or cluster mode, provide REST APIs, command-line and web-ui.

App Mesh is similar with Kubernetes but much light weight, support both container app and native app.

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/diagram.png" align=center /></div>

## Features

Scope | Behavior
---|---
Support applications | Long running <br> Short running <br> Periodic long running <br> Cron schedule
Application attributes | Extra init and cleanup commands <br> Available time range in a day and more rich time options <br> Environment variables <br> Health check command to identify app health <br> Pipe input string data to pass data to application <br> Resource (memory & CPU) limitation (cgroup on Linux) to request resources <br> Support Docker container app
Security |  ⚡️ [JWT authentication](https://app-mesh.readthedocs.io/en/latest/JWT.html) for CLI and REST interface <br> ⚡️ [LDAP support](https://app-mesh.readthedocs.io/en/latest/LDAP.html) <br> ⚡️ [Role based permission control](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html) <br> SSL support (ECDH and secure ciphers) for REST http connection <br> Multi-tenant support 
Cloud native | ⚡️ [Prometheus Exporter (build-in)](https://app-mesh.readthedocs.io/en/latest/PROMETHEUS.html) <br> ⚡️ [Grafana Loki](https://app-mesh.readthedocs.io/en/latest/Loki.html) <br> REST service with IPv4/IPv6 support 
Micro service application | ⚡️ [Consul micro-service cluster management](https://app-mesh.readthedocs.io/en/latest/CONSUL.html) 
Extra Features | Collect host/app resource usage <br> Remote run shell commands <br> Download/Upload files interface <br> Hot-update support `systemctl reload appmesh` <br> Bash completion <br> Reverse proxy <br> [Web GUI](https://github.com/laoshanxi/app-mesh-ui)
Platform support | X86_64 <br> ARM32 <br> ARM64
SDK | [Python](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/python/appmesh_client.py) <br> [Golang](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/go/appmesh_client.go)

## Getting started
The [Installation doc](https://app-mesh.readthedocs.io/en/latest/Install.html) introduce how
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

## Library dependency
- [ACE](https://github.com/DOCGroup/ACE_TAO)
- [Microsoft/cpprestsdk](https://github.com/Microsoft/cpprestsdk)
- [boost](https://github.com/boostorg/boost)
- [log4cpp](http://log4cpp.sourceforge.net)
- [Thalhammer/jwt-cpp](https://thalhammer.it/projects/jwt_cpp)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)
- [zemasoft/wildcards](https://github.com/zemasoft/wildcards)
- [Crypto++](https://www.cryptopp.com)
- [mariusbancila/croncpp](https://github.com/mariusbancila/croncpp)
- [ldap-cpp](https://github.com/AndreyBarmaley/ldap-cpp)
- [google/protobuf](https://github.com/protocolbuffers/protobuf)

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

