# Prometheus Exporter

Prometheus, a Cloud Native Computing Foundation project, is a systems and service monitoring system. It collects metrics from configured targets at given intervals, evaluates rule expressions, displays the results, and can trigger alerts if some condition is observed to be true.

![Architecture](https://prometheus.io/assets/architecture.png)

------

## What is supported
>
> * App Mesh provides a built-in Prometheus exporter
> * The exporter exposes current daemon, persistent-application, and HTTP metrics

## What is **not** supported
>
> * The Prometheus listener does not provide TLS

## Start Grafana and Prometheus

```shell
git clone --depth=1 https://github.com/laoshanxi/app-mesh.git
cd app-mesh/script/docker
docker-compose -f docker-compose-all-in-one.yaml up -d
```

### Configure Grafana

1. Access Prometheus 9090 UI (http://prom_node:9090/) to verify
2. Open Grafana on 3000 port (http://grafana_node:3000/)
3. Add DataSource: Prometheus
4. Input Prometheus address: http://script_prometheus_1:9090 (this address is Grafana access Prometheus docker container name)
5. Select Explore -> Metrics

### Design

The daemon owns the in-memory registry. The Go agent listens on
`REST.PrometheusExporterListenPort` and proxies `/metrics` to the daemon's local transport.
REST must be enabled. Port `0` disables the listener; `6061` is a typical value. Use
node-exporter separately when full host metrics are required.
The dedicated listener accepts only `GET`/`HEAD` and always targets the local daemon;
the agent forwarding header is rejected on this endpoint.

### Defined Metrics

<http://127.0.0.1:6061/metrics>

| Metric | Type | Description |
| --- | --- | --- |
| `appmesh_metrics_scrapes_total` | counter | Metrics scrapes served by App Mesh |
| `appmesh_metrics_collection_errors_total` | counter | Collector failures |
| `appmesh_process_id` | gauge | Daemon PID |
| `appmesh_build_info{version}` | gauge | Build metadata |
| `appmesh_process_open_fds` | gauge | Open FDs in the daemon process tree |
| `appmesh_http_requests_total{method,route,status_code,status_class}` | counter | Completed HTTP requests; dynamic path segments are normalized and metrics endpoints are excluded |
| `appmesh_http_request_duration_seconds{method,route}` | histogram | End-to-end HTTP response latency with eight fixed buckets from 10 ms to 30 s |
| `appmesh_http_requests_in_flight{method,route}` | gauge | Requests that have started but have not completed |
| `appmesh_application_process_starts_total{application}` | counter | Process start attempts including attach/recovery |
| `appmesh_application_metrics_collection_errors_total{application}` | counter | Process metric collection failures, including exit-during-scrape races |
| `appmesh_application_process_id{application}` | gauge | Current PID, or zero while stopped |
| `appmesh_application_process_resident_memory_bytes{application}` | gauge | Process-tree RSS |
| `appmesh_application_process_cpu_usage_cores{application}` | gauge | CPU use where `1.0` is one fully used core |
| `appmesh_application_process_open_fds{application}` | gauge | Process-tree open FDs |
| `appmesh_application_enabled{application}` | gauge | Enabled state |
| `appmesh_application_running{application}` | gauge | Running state |
| `appmesh_application_healthy{application}` | gauge | `1` only while the process is running and its health check passes |

Every series has the stable `host` label. Application metrics are registered only for persisted
applications and the fixed-name agent; one-off runs do not create Prometheus series. This keeps the
`application` label bounded. HTTP routes use registered templates such as `/appmesh/app/:param`; unknown
paths use `route="unmatched"`. `status_class` is one of `1xx` through `5xx` or `unreplied`.
PID, raw URL values, query strings, and random one-off application IDs are values or omitted from labels,
so requests and restarts do not create unbounded time series.

HTTP observation starts at the worker boundary, so CSRF rejection, forwarding, unsupported methods,
and normal REST handling all participate in the same RED series. The two metrics endpoints are excluded.

The standard HTTP RED queries are based on:

- Rate: `rate(appmesh_http_requests_total[5m])`
- Errors: `rate(appmesh_http_requests_total{status_class=~"4xx|5xx|unreplied"}[5m])`
- Duration p95: `histogram_quantile(0.95, sum by (le, route) (rate(appmesh_http_request_duration_seconds_bucket[5m])))`

Metric names changed to Prometheus base-unit and `_total` conventions. Dashboards and alerting
rules using the former `appmesh_prom_*` or `appmesh_http_request_count` names must be migrated.
`REST.PrometheusExporterListenPort` updates are accepted and persisted, but the Go exporter binds
its listener only during startup. The running exporter and in-process metric registration keep
their startup state until App Mesh is restarted.

![Prometheus Configuration](https://raw.githubusercontent.com/laoshanxi/picture/master/prometheus/Prometheus-Configuration.png)
![Prometheus Targets](https://raw.githubusercontent.com/laoshanxi/picture/master/prometheus/Prometheus-Targets.png)
