# Build powerful monitor system with Grafana/Prometheus/Loki
App Mesh can manage all app applications running on Linux and provide build-in Prometheus exporter the metrics can be used to monitor hosted application detail running behavior. Loki can be used to collect all applications and App Mesh logs.

Grafana can be used as Prometheus and Loki web portal, with those components, we can build a runtime metrics and log aggregate system with a flexible GUI.
<div align=center><img src="https://raw.githubusercontent.com/laoshanxi/app-mesh/main/doc/diagram.png" width=600 height=400 align=center /></div>

## Deploy all component by docker compose

### install docker-compose
```
sudo curl -L "https://github.com/docker/compose/releases/download/v2.11.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### Clone App Mesh source files
```
git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
cd app-mesh
```

### Deploy all in one YAML
```
cd app-mesh/script
$ docker-compose -f docker-compose-all-in-one.yaml up -d
Creating script_prometheus_1    ... done
Creating script_loki_1          ... done
Creating script_consul_1        ... done
Creating script_grafana_1       ... done
Creating script_node_exporter_1 ... done
Creating script_alertmanager_1  ... done
Creating script_promtail_1      ... done
Creating script_appmesh_1       ... done
Creating script_appmesh-ui_1    ... done

```

Then you can access App Mesh UI (https://192.168.3.24/) with initial user (admin/admin123).

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/appmesh/1.png" />

Monitor system: Grafana, Prometheus, Node Exporter, promtail, Alert Manager

<img src="https://prometheus.io/assets/architecture.png" />

## Login Grafana
Open target host http://192.168.3.24:3000/

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/01.png" />

Input initial password admin/admin and change a new password for Grafana

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/02.png" />

Add Prometheus Data Source with default address(http://localhost:9090/)

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/03.png" />

In Grafana Explorer page, you can query App Mesh metrics

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/04.png" />

Add Loki Data Source with default address(http://localhost:3100/)

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/05.png" />

In Grafana Exploere page, you can query all app stdout of App Mesh managed applications and App Mesh logs

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/06.png" />

## Prometheus UI (alertmanager)
Open Prometheus WEB portal at http://192.168.3.24:9090/

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/prometheus01.png" />

Query metrics: appmesh_prom_process_memory_gauge

<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/prometheus02.png" />

Stop node exporter to trigger alertmanager, you will get bellow email:
```
$ docker stop script_node_exporter_1
```
<img src="https://raw.githubusercontent.com/laoshanxi/picture/master/wiki/email.png" />

### Clean docker compose started containers
```
$ cd app-mesh/script
$ docker-compose -f docker-compose-all-in-one.yaml stop
$ docker-compose -f docker-compose-all-in-one.yaml rm -f
```
