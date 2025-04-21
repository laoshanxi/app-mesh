# Secure REST file server

App Mesh provide file download/upload REST APIs, also those APIs can be authenticated by JWT.

## Solution

Use below API to manage file:

| Method | URI                    | Body/Headers                                                             | Desc                                                  |
| ------ | ---------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| GET    | /appmesh/file/download | Header: <br> X-File-Path=/opt/remote/filename                            | Download a file from REST server and grant permission |
| POST   | /appmesh/file/upload   | Header: <br> X-File-Path=/opt/remote/filename <br> Body: <br> file steam | Upload a file to REST server and grant permission     |

- The simple way is use [Python SDK](https://github.com/laoshanxi/app-mesh/blob/main/src/sdk/python/appmesh_client.py)
- Use appmesh cli is also fine: `appc put -l /opt/appmesh/log/appsvc.log -r /tmp/1.log`

### Nginx can be used to be file download server

`nginx.conf`

```text
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

```text
server {
    listen 443 ssl;
    server_name localhost;

    ssl_certificate                /etc/nginx/conf.d/server.pem;
    ssl_certificate_key            /etc/nginx/conf.d/server-key.pem;
    ssl_protocols                  TLSv1.2;
    ssl_prefer_server_ciphers      on;
    ssl_session_timeout            5m;
    ssl_ciphers                    ECDHE-RSA-AES128-GCM-SHA256:ECDHE:ECDH:AES:HIGH:!NULL:!aNULL:!MD5:!ADH:!RC4;
    underscores_in_headers         on;

    charset utf-8;
    root /data;
    location / {
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }
}
```

App Mesh used as a secure file upload server which share storage with Nginx.
Use `docker-compose up -d` to start appmesh and nginx service.

`compose.yml`:

```yaml
version: "3"

services:
  appmesh_upload_svc:
    image: laoshanxi/appmesh:latest
    hostname: appmesh.hostname.com
    restart: always
    privileged: true
    user: root
    volumes:
      - ./data/:/data/
      - /etc/ssl/ca.pem:/opt/appmesh/ssl/ca.pem
      - ./server-key.pem:/opt/appmesh/ssl/server-key.pem
      - ./server.pem:/opt/appmesh/ssl/server.pem
    ports:
      - "6060:6060"
    environment:
      - APPMESH_REST_RestListenAddress=appmesh.hostname.com

  nginx_download_svc:
    image: nginx:stable-alpine
    restart: always
    ports:
      - "8443:443"
    volumes:
      - ./data/:/data/
      - ./server-key.pem:/etc/nginx/conf.d/server-key.pem
      - ./server.pem:/etc/nginx/conf.d/server.pem
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./default.conf:/etc/nginx/conf.d/default.conf
```

View file server from URL `https://127.0.0.1:8443/`
