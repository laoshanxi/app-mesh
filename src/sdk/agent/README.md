# AppMesh Agent REST API

The agent provides access to Docker daemon through two methods:

## AppMesh agent Docker REST API

### Docker API Proxy (/appmesh/docker/\*)

The agent proxies Docker daemon REST API requests under the `/appmesh/docker` prefix. The daemon is the only caller. Each request must carry the PSK headers `X-Request-ID` and `X-Request-HMAC`. The agent rejects a request without valid PSK headers with status 407.

| Endpoint                       | Method   | Description                |
| ------------------------------ | -------- | -------------------------- |
| `/appmesh/docker/containers/*` | GET/POST | Container operations       |
| `/appmesh/docker/images/*`     | GET/POST | Image operations           |
| `/appmesh/docker/volumes/*`    | GET/POST | Volume operations          |
| `/appmesh/docker/networks/*`   | GET/POST | Network operations         |
| `/appmesh/docker/system/*`     | GET      | System operations          |
| `/appmesh/docker/version`      | GET      | Docker version info        |
| `/appmesh/docker/_ping`        | GET      | Docker daemon health check |

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
