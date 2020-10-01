[![language.badge]][language.url] [![standard.badge]][standard.url] [![release.badge]][release.url] [![docker.badge]][docker.url] [![cockpit.badge]][cockpit.url]
<a href="https://scan.coverity.com/projects/laoshanxi-app-mesh">
  <img alt="Coverity Scan Build Status"
       src="https://img.shields.io/coverity/scan/21528.svg"/>
</a>

# App Mesh

App Mesh is a `Multi Tenant`, `Cloud Native`, `Micro Service` application management platform, used to on-board, schedule, start and monitor applications. Each app can be a specific micro service for service discover or normal app with replication, the app-mesh will guarantee all defined applications running on-time with defined behavior and resources. The platform can run as standalone or cluster mode, provide REST APIs, command-line and web-ui.

App Mesh is similar with Kubernetes but much light weight, support both container app and native app.

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/master/doc/diagram.png" width=600 height=400 align=center /></div>

## Features
Scope  | Behavior
---|---
Support applications | Long running <br> Short running <br> Periodic long running
Application behavior | Application support initial and cleanup command <br> Application can define available time range in a day <br> Application can define environment variables <br> Application can define health check command <br> Application can define resource (memory & CPU) limitation (cgroup on Linux) <br> Docker container app support
Security |  ⚡️ [JWT authentication](https://github.com/laoshanxi/app-mesh/blob/master/doc/JWT_DESC.md) <br> ⚡️ [Role based permission control](https://github.com/laoshanxi/app-mesh/blob/master/doc/USER_ROLE_DESC.md) <br> SSL support (ECDH and secure ciphers) <br> Multi-tenant support 
Cloud native | ⚡️ [Prometheus Exporter (build-in)](https://github.com/laoshanxi/app-mesh/blob/master/doc/PROMETHEUS.md) <br> ⚡️ [Grafana Loki](https://github.com/laoshanxi/app-mesh/blob/master/doc/Loki.md) <br> REST service with IPv6 support 
Microservice application | ⚡️ [Consul micro-service cluster management](https://github.com/laoshanxi/app-mesh/blob/master/doc/CONSUL.md) 
Extra Features | Collect host/app resource usage <br> Remote run shell commands <br> Download/Upload files interface <br> Hot-update support `systemctl reload appmesh` <br> Bash completion <br> Reverse proxy <br> [Web GUI](https://github.com/laoshanxi/app-mesh-ui)
Platform support | X86_64 <br> ARM32 <br> ARM64

## Getting started
The [Installation doc](https://github.com/laoshanxi/app-mesh/blob/master/doc/Install.md) introduce how
to install App Mesh via docker-compose or native way and setup App Mesh cluster.

## Documentation
- [Command Lines](https://github.com/laoshanxi/app-mesh/blob/master/doc/CLI.md) provide all the interfaces to manage App Mesh.
- [Development](https://github.com/laoshanxi/app-mesh/blob/master/doc/Development.md) define REST APIs and show how to build App Mesh.

---

## 3rd party deependencies
- [C++11](http://www.cplusplus.com/articles/cpp11)
- [ACE](https://github.com/DOCGroup/ACE_TAO)
- [Microsoft/cpprestsdk](https://github.com/Microsoft/cpprestsdk)
- [boost](https://github.com/boostorg/boost)
- [log4cpp](http://log4cpp.sourceforge.net)
- [Thalhammer/jwt-cpp](https://thalhammer.it/projects/jwt_cpp)
- [jupp0r/prometheus-cpp](https://github.com/jupp0r/prometheus-cpp)
- [zemasoft/wildcards ](https://github.com/zemasoft/wildcards)

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

