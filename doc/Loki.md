![Logo](https://grafana.com/docs/loki/latest/logo_and_name.png)

## Loki: like Prometheus, but for logs.
Loki is a horizontally-scalable, highly-available, multi-tenant log aggregation system inspired by Prometheus. It is designed to be very cost effective and easy to operate. It does not index the contents of the logs, but rather a set of labels for each log stream.

![architecture](https://grafana.com/static/assets/img/blog/image4.png)

### install docker-compose
```
sudo curl -L "https://github.com/docker/compose/releases/download/1.23.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

### start Loki, Grafana, Promtail
```
cd /opt/appmesh/script
docker-compose -f docker-compose.yaml up -d
```

### Configure Grafana
1. Open Grafana on 3000 port (http://grafana_node:3000/)
2. Add DataSource: Loki
3. Input Loki address: http://script_loki_1:3100 (this address is Grafana access Loki docker container name)
4. Select Explore -> Log labels -> job

### Stop
```
cd /opt/appmesh/script
docker-compose stop
docker-compose rm -f
```

### Reference
- [Loki Query Language](https://grafana.com/docs/loki/latest/logql/)
- [Promtail doc](https://grafana.com/docs/loki/latest/clients/promtail/)
- [Docker compose](https://github.com/grafana/loki/tree/master/production)
- [Loki / Promtail / Grafana vs EFK](https://grafana.com/docs/loki/latest/overview/comparisons/)
- [Labels in Loki](https://grafana.com/blog/2020/04/21/how-labels-in-loki-can-make-log-queries-faster-and-easier/)