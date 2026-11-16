# AppMesh Agent REST API

The agent provides access to Docker daemon through two methods:

## Response headers

The agent is the browser entry origin for the App Mesh UI, so its headers follow
the daemon's rules:

- CORS is opt-in: `Access-Control-Allow-Origin` echoes a request `Origin` only
  when it is listed in `REST.CorsAllowOrigins` in the shared `config.yaml`
  (comma-separated `APPMESH_REST_CorsAllowOrigins` works too). With the default
  empty list — or a non-listed Origin, or a request without an `Origin` — the
  agent sends no CORS header at all. `REST.CorsDisabled: true` stays available
  as the explicit off switch and reproduces the same zero-header behavior.
- Every response carries `X-Content-Type-Options: nosniff`, including proxied
  surfaces (Grafana data source, docker proxy, authentication service).
- App Mesh API responses (the catch-all forwarded to the daemon) additionally
  carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`;
  the API serves JSON and files, never active content. The `/oauth/callback`
  relay page carries its own CSP that pins its inline script by SHA-256 hash.

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
- Responses are classified per request: live streams (pull progress, builds, a
  following `logs?follow=1`, events) pass through unbuffered, while finite
  documents — including non-following `/logs` — are buffered and
  Content-Length framed so buffered HTTP clients read them reliably

Reference:

[Docker Engine API Documentation](https://docs.docker.com/reference/api/engine/)

### Nginx Proxy Implementation

`nginx` implement a docker proxy demo with Nginx
