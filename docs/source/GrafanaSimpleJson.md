# Grafana json REST data source to monitor App Mesh

## [Simple JSON Datasource - a generic backend datasource](https://grafana.com/grafana/plugins/grafana-simple-json-datasource/)

Grafana support use REST API to perform a generic REST API as a customerized data source instead of develop a new plugin

## [Install Grafana simplejson plugin](https://github.com/grafana/simple-json-datasource)

Use the grafana-cli tool to install SimpleJson from the commandline:
```
grafana-cli plugins install grafana-simple-json-datasource
service grafana-server restart
```
After that, you could see simplejson data source plugin from Grafana.

![simplejson](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/01_add_data_source.png)

[Grafana simple json plugin description](https://grafana.com/grafana/plugins/grafana-simple-json-datasource/)


## Add App Mesh data source to monitor applications

![datasource](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/02_add_appmesh.png)

Note: Add authentication token as Custom HTTP Headers `Authorization` without `Bearer ` prefix for authenticate with App Mesh, the result just show the applications visible to the token user.

## Add dashboard
![appmesh](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/03_appmesh_dashboard.png)
