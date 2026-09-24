# AppMesh Agent REST API

The agent provides access to Docker daemon through two methods:

## AppMesh agent Docker REST API

### Docker API Proxy (/appmesh/docker/\*)

The agent proxies Docker daemon REST API requests under the `/appmesh/docker` prefix. The daemon is the only caller. Each request must carry the PSK headers `X-Request-ID` and `X-Request-HMAC`. The agent rejects a request without valid PSK headers with status 407.

| Endpoint                       | Method | Description                |
| ------------------------------ | ------ | -------------------------- |
| `/appmesh/docker/containers/*` | any    | Container operations       |
| `/appmesh/docker/images/*`     | any    | Image operations           |
| `/appmesh/docker/volumes/*`    | any    | Volume operations          |
| `/appmesh/docker/networks/*`   | any    | Network operations         |
| `/appmesh/docker/system/*`     | any    | System operations          |
| `/appmesh/docker/version`      | any    | Docker version info        |
| `/appmesh/docker/_ping`        | any    | Docker daemon health check |

The agent registers one unrestricted path prefix and forwards every method. The
table above therefore lists no allow-list. The daemon itself uses GET and POST,
and DELETE for `/containers/{id}`.

Implementation Details:

- The daemon (`DockerApiProcess`) sends the PSK headers. It signs the `X-Request-ID` value with the shared process HMAC key.
- The agent registers these routes only when `/var/run/docker.sock` exists.
- The agent proxies requests to Docker daemon socket at /var/run/docker.sock
- TLS encryption is handled by the agent's main HTTPS server
- All Docker API operations are available through the /appmesh/docker prefix
- Request/response formats follow the Docker Engine API specification

Reference:

[Docker Engine API Documentation](https://docs.docker.com/reference/api/engine/)

### Nginx Proxy Implementation

`nginx` implement a docker proxy demo with Nginx
