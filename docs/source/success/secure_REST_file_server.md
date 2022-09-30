# Secure REST file server
App Mesh provide file download/upload REST APIs, also those APIs can be authenticated by JWT.

## Solution
Use below API to manage file:
| Method | URI                    | Body/Headers                                                           | Desc                                                  |
| ------ | ---------------------- | ---------------------------------------------------------------------- | ----------------------------------------------------- |
| GET    | /appmesh/file/download | Header: <br> File-Path=/opt/remote/filename                            | Download a file from REST server and grant permission |
| POST   | /appmesh/file/upload   | Header: <br> File-Path=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission     |

* The simple way is use [Python SDK](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/python/appmesh_client.py)
* Use appmesh cli is also fine: `appc put -l /opt/appmesh/log/appsvc.log -r /tmp/1.log`

### Use nginx to deploy a file server

`nginx.conf`
```
user  root;
worker_processes  1;

error_log  /var/log/nginx/error.log warn;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

http {
    include           /etc/nginx/mime.types;
    default_type      application/octet-stream;
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log        /var/log/nginx/access.log  main;
    sendfile          on;
    #tcp_nopush       on;
    keepalive_timeout 65;
    #gzip             on;
    include           /etc/nginx/conf.d/*.conf;
}
```
`default.conf`

```
server {
    listen 8080;
    server_name localhost;

    # for SSL listen port only
    #ssl_certificate                /etc/nginx/conf.d/server.pem;
    #ssl_certificate_key            /etc/nginx/conf.d/server-key.pem;
    #ssl_protocols                  TLSv1.2;
    #ssl_prefer_server_ciphers      on;
    #ssl_session_timeout            5m;
    #ssl_ciphers                    ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    #underscores_in_headers         on;

    charset utf-8;
    root /data;
    location / {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }
}
```

start nginx:
```shell
#!/bin/bash
mkdir data
docker stop nginx_file_server
docker rm nginx_file_server

docker run -d -p 8081:8080\
        --name nginx_file_server \
        -v $(pwd)/data:/data \
        -v $(pwd)/nginx.conf:/etc/nginx/nginx.conf \
        -v $(pwd)/default.conf:/etc/nginx/conf.d/default.conf \
        nginx:stable-alpine
```

Access file server from URL `http://127.0.0.1:8081/`
