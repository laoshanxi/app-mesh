# Prometheus Exporter

------

### What is supported:

> * Application Manager provide a build-in Prometheus exporter
> * Prometheus exporter is a build-in REST server for Prometheus to scrap methics

### What is **not** supported:
> * Exporter SSL is not supported as community

### Defined Metrics
http://127.0.0.1:6061/metrics
```html
# HELP appmgr_prom_scrape_count prometheus scrape count
# TYPE appmgr_prom_scrape_count counter
appmgr_prom_scrape_count{host="appmgr",pid="10791"} 6.000000
# HELP appmgr_prom_process_start_count application process spawn count
# TYPE appmgr_prom_process_start_count counter
appmgr_prom_process_start_count{application="appweb",host="appmgr",pid="10791"} 1.000000
appmgr_prom_process_start_count{application="timer",host="appmgr",pid="10791"} 0.000000
# HELP appmgr_http_request_count application manager http request count
# TYPE appmgr_http_request_count counter
appmgr_http_request_count{host="appmgr",method="POST",pid="10791"} 0.000000
appmgr_http_request_count{host="appmgr",method="DELETE",pid="10791"} 0.000000
appmgr_http_request_count{host="appmgr",method="PUT",pid="10791"} 0.000000
appmgr_http_request_count{host="appmgr",method="GET",pid="10791"} 0.000000
# HELP appmgr_prom_scrape_up prometheus scrape alive
# TYPE appmgr_prom_scrape_up gauge
appmgr_prom_scrape_up{host="appmgr",pid="10791"} 1.000000
# HELP appmgr_prom_process_memory_gauge application process memory bytes
# TYPE appmgr_prom_process_memory_gauge gauge
appmgr_prom_process_memory_gauge{application="appweb",host="appmgr",pid="10791"} 3268759.000000
appmgr_prom_process_memory_gauge{application="timer",host="appmgr",pid="10791"} 0.000000
```