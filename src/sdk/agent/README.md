# AppMesh Agent REST API

The agent provides access to Docker daemon through two methods:

## AppMesh agent Docker REST API

### Docker API Proxy (/appmesh/docker/\*)

The agent proxies Docker daemon REST API requests under the `/appmesh/docker` prefix.

| Endpoint                       | Method   | Description                |
| ------------------------------ | -------- | -------------------------- |
| `/appmesh/docker/containers/*` | GET/POST | Container operations       |
| `/appmesh/docker/images/*`     | GET/POST | Image operations           |
| `/appmesh/docker/volumes/*`    | GET/POST | Volume operations          |
| `/appmesh/docker/networks/*`   | GET/POST | Network operations         |
| `/appmesh/docker/system/*`     | GET      | System operations          |
| `/appmesh/docker/version`      | GET      | Docker version info        |
| `/appmesh/docker/_ping`        | GET      | Docker daemon health check |

Examples:

```bash
# List all Docker containers
curl -k https://127.0.0.1:6060/appmesh/docker/containers/json

# List all Docker images
curl -k https://127.0.0.1:6060/appmesh/docker/images/json

# Get Docker version
curl -k https://127.0.0.1:6060/appmesh/docker/version
```

Implementation Details:

- The agent proxies requests to Docker daemon socket at /var/run/docker.sock
- TLS encryption is handled by the agent's main HTTPS server
- All Docker API operations are available through the /appmesh/docker prefix
- Request/response formats follow the Docker Engine API specification

Reference:

[Docker Engine API Documentation](https://docs.docker.com/reference/api/engine/)

### Nginx Proxy Implementation

`docker_nginx` implement a docker proxy demo with Nginx
