# Grafana json REST data source to monitor App Mesh

## [Install Grafana simplejson plugin](https://github.com/grafana/simple-json-datasource)

```
sudo grafana-cli plugins install grafana-simple-json-datasource
sudo service grafana-server restart
```
After that, you could see simplejson data source from Grafana.

![datasource](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/01_add_data_source.png)

[Grafana simple json plugin description](https://grafana.com/grafana/plugins/grafana-simple-json-datasource/)


## Add App Mesh data source

![datasource](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/02_add_appmesh.png)

Note that authentication token could add as Custom HTTP Headers `Authorization` without `Bearer ` prefix.

## Add dashboard
![appmesh](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/03_appmesh_dashboard.png)
