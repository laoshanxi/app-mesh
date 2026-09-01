# Promote native application to microservice application

App Mesh is designed for manage micro service applications, for a native application without any refactor and adapt, can promote as a micro service application with App Mesh, other app can use HTTP request to call this native application.

## Solution

App Mesh support POST [/appmesh/app/run] API used to run a command remotely, with this feature, we can launch native app in server side and get result via REST response, App Mesh framework will guarantee the security and permission.

The interactive with native application can use std input, App Mesh support pass text (json) data to application process.

## Deploy App Mesh by Docker container

* Assume native app is `/usr/share/myapp.py`, mount native app binary to container.
* Expose 6060 for App Mesh service port
* Start Docker container in backend:

```shell
docker run -d -m 8g --restart=always \
  -v /usr/share/myapp.py:/usr/share/myapp.py:ro \
  -v appmesh-work:/opt/appmesh/work \
  --name=myapp -p 6060:6060 laoshanxi/appmesh
```

* If we have any special configuration changes for App Mesh container, we can add `-v /opt/user/config.yaml:/opt/appmesh/config/config.yaml:ro`.
* The raw host Docker socket is not mounted by default. This example manages the
  native application as UID/GID 482; `docker_image` management therefore remains
  disabled in this deployment.

## Use native application

### Security

App Mesh accepts OAuth access tokens. Acquire a token through the standard
Authorization Code with PKCE, Device Authorization, or an approved service-client flow,
then provide it through the environment. The issuer and the authentication-service route
may be configured independently; see [Security](../Security.md).

```shell
export APPMESH_BEARER_TOKEN="$(your-oauth-client)"
```

App Mesh never receives an identity-provider password. Manage users and password policy upstream;
manage App Mesh Principal roles in `authorization.yaml` or through the Principal APIs.

### Call microservice

With the bearer, call the native app through App Mesh REST. The body can include the
remote application command and metadata for stdin:

```shell
curl --cacert "$APPMESH_CA" -X POST -H "Authorization: Bearer $APPMESH_BEARER_TOKEN" \
-d '{ "command" : "python3 /usr/share/myapp.py", "metadata": "std input text data" }' \
https://appmesh-host:6060/appmesh/app/syncrun?timeout=30
```

You will get result by REST response.
