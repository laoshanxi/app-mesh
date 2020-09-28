# Prometheus Exporter

Prometheus, a Cloud Native Computing Foundation project, is a systems and service monitoring system. It collects metrics from configured targets at given intervals, evaluates rule expressions, displays the results, and can trigger alerts if some condition is observed to be true.

![Architecture](https://prometheus.io/assets/architecture.png)

------

### What is supported:
> * App Mesh provide a build-in Prometheus exporter
> * Prometheus exporter is a build-in REST server for Prometheus to scrap methics

### What is **not** supported:
> * Exporter SSL is not supported as community

### start Grafana, Prommetheus
```
git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
cd app-mesh/script
docker-compose -f docker-compose.yaml up -d
```

### Configure Grafana
1. Access Prometheus 9090 UI (http://prom_node:9090/) to verify
2. Open Grafana on 3000 port (http://grafana_node:3000/)
3. Add DataSource: Loki
4. Input Loki address: http://script_prometheus_1:9090 (this address is Grafana access Loki docker container name)
5. Select Explore -> Metrics

## Design
`Prometheus` is monitoring system and time series database, every metric (unique by lable) will be a time seris data in DB, and use pull way to scrap data from Server to Client, client provide a exporter service listen on a local port, the exporter is build with Application together to read metric data from memory. appmesh provide a exporter service listen at 6061 by default. The exporter run build-in with appmesh and no need extra process.
In order to collect node metrics, an extra node-exporter can be started on each node and listen on 9100 to provide node metrics service.

### Defined Metrics
http://127.0.0.1:6061/metrics
```html
# HELP appmesh_prom_scrape_count prometheus scrape count
# TYPE appmesh_prom_scrape_count counter
appmesh_prom_scrape_count{host="appmesh",pid="10791"} 6.000000
# HELP appmesh_prom_process_start_count application process spawn count
# TYPE appmesh_prom_process_start_count counter
appmesh_prom_process_start_count{application="appweb",host="appmesh",pid="10791"} 1.000000
appmesh_prom_process_start_count{application="timer",host="appmesh",pid="10791"} 0.000000
# HELP appmesh_http_request_count app mesh http request count
# TYPE appmesh_http_request_count counter
appmesh_http_request_count{host="appmesh",method="POST",pid="10791"} 0.000000
appmesh_http_request_count{host="appmesh",method="DELETE",pid="10791"} 0.000000
appmesh_http_request_count{host="appmesh",method="PUT",pid="10791"} 0.000000
appmesh_http_request_count{host="appmesh",method="GET",pid="10791"} 0.000000
# HELP appmesh_prom_scrape_up prometheus scrape alive
# TYPE appmesh_prom_scrape_up gauge
appmesh_prom_scrape_up{host="appmesh",pid="10791"} 1.000000
# HELP appmesh_prom_process_memory_gauge application process memory bytes
# TYPE appmesh_prom_process_memory_gauge gauge
appmesh_prom_process_memory_gauge{application="appweb",host="appmesh",pid="10791"} 3268759.000000
appmesh_prom_process_memory_gauge{application="timer",host="appmesh",pid="10791"} 0.000000
```

![Prometheus Configuration](https://raw.githubusercontent.com/laoshanxi/picture/master/prometheus/Prometheus-Configuration.png)
![Prometheus Targets](https://raw.githubusercontent.com/laoshanxi/picture/master/prometheus/Prometheus-Targets.png)