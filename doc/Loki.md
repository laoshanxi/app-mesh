![Logo](https://grafana.com/docs/loki/latest/logo_and_name.png)

## Loki: like Prometheus, but for logs.
Loki is a horizontally-scalable, highly-available, multi-tenant log aggregation system inspired by Prometheus. It is designed to be very cost effective and easy to operate. It does not index the contents of the logs, but rather a set of labels for each log stream. Loki differs from Prometheus by focusing on logs instead of metrics, and delivering logs via push, instead of pull.

![architecture](https://grafana.com/static/assets/img/blog/image4.png)

## Install docker-compose
```
sudo curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

## Start Loki, Grafana, Promtail
```
cd /opt/appmesh/script
docker-compose -f docker-compose.yaml up -d
```

## Configure Grafana
1. Open Grafana on 3000 port (http://grafana_node:3000/)
2. Add DataSource: Loki
3. Input Loki address: http://script_loki_1:3100 (this address is Grafana access Loki docker container name)
4. Select Explore -> Log labels -> job

## Stop and clean
```
cd /opt/appmesh/script
docker-compose stop
docker-compose rm -f
```

## Design
Loki is a log aggregation system, component `loki` run as Server and `promtail` run as log connect and push agent. `promtail` is always run as daemonset on each log collection node. For appmesh node, bellow logs need to be collected together:
1. Default system log in /var/log
2. appmesh service log in /opt/appmesh/log/appsvc.log
3. Managed application output log in /opt/appmesh/work/*.log
So override promtail configuration (/etc/promtail/config.yml) to combine the 3 log target in one promtail configuration, each node only start one `promtail` docker container.

## Reference
- [Loki Query Language](https://grafana.com/docs/loki/latest/logql/)
- [Promtail doc](https://grafana.com/docs/loki/latest/clients/promtail/)
- [Docker compose](https://github.com/grafana/loki/tree/master/production)
- [Loki / Promtail / Grafana vs EFK](https://grafana.com/docs/loki/latest/overview/comparisons/)
- [Labels in Loki](https://grafana.com/blog/2020/04/21/how-labels-in-loki-can-make-log-queries-faster-and-easier/)