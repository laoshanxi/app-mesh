# Prometheus Exporter

------

### What is supported:

> * App Mesh provide a build-in Prometheus exporter
> * Prometheus exporter is a build-in REST server for Prometheus to scrap methics

### What is **not** supported:
> * Exporter SSL is not supported as community

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