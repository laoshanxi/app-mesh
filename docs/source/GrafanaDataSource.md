# Grafana json REST data source to monitor App Mesh

## [Simple JSON Datasource - a generic backend datasource](https://grafana.com/grafana/plugins/grafana-simple-json-datasource/)

Grafana support use REST API to perform a generic REST API as a customerized data source instead of develop a new plugin

### [Install Grafana simplejson plugin](https://github.com/grafana/simple-json-datasource)

Use the grafana-cli tool to install SimpleJson from the commandline:
```
grafana-cli plugins install grafana-simple-json-datasource
service grafana-server restart
```
After that, you could see simplejson data source plugin from Grafana.

![simplejson](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/01_add_data_source.png)

[Grafana simple json plugin description](https://grafana.com/grafana/plugins/grafana-simple-json-datasource/)


### Add App Mesh data source to monitor applications

Add simplejson data source with URL `http://appmesh_server:6060/appmesh/grafana`

![datasource](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/02_add_appmesh.png)

Note: Add authentication token as Custom HTTP Headers `Authorization` with `Bearer ` prefix for authenticate with App Mesh, the result just show the applications visible to the token user.

### Add dashboard
![appmesh](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/03_appmesh_dashboard.png)

## [Grafana Infinity Datasource](https://grafana.com/grafana/plugins/yesoreyeram-infinity-datasource/)

Grafana support visualize data from JSON, CSV, XML, GraphQL, HTML & REST APIs. Especially support REST API return [JSON data](https://sriramajeyam.com/grafana-infinity-datasource/wiki/json/) which is similar with App Mesh API: `GET` `/appmesh/applications`

Same as SimpleJson, add authentication token as Custom HTTP Headers `Authorization` with `Bearer ` prefix for authenticate with App Mesh, the result just show the applications visible to the token user.

Use URL `http://127.0.0.1:6060/appmesh/applications` to query applications from App Mesh.

![infinity](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/04_infinity_datasource.PNG)

Date time string attributes support convert to local ISO date time:
![date_column](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/05_grafana_date_time.png)

Note: for https without import root CA, please select "Skip TLS Verify"

This plugin also support HTML format for application output
Use URL `https://appmesh:6060/appmesh/app/ping/output`, add Query Parameter `html=true`, input `Rows / Root` as `body > pre`, add one column `pre` to shown output by line.
![infinity_html](https://raw.githubusercontent.com/laoshanxi/picture/master/grafana/06_infinity_html.png)

This plugin also support JSON format for application output
Use URL `https://appmesh:6060/appmesh/app/ping/output`, add Query Parameter `json=true`
