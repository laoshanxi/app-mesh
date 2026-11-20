# AppMesh Agent REST API

The agent fronts the daemon's REST surface locally and owns the Docker
conversation for the node.

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
  surfaces (Grafana data source, container service, authentication service).
- App Mesh API responses (the catch-all forwarded to the daemon) additionally
  carry `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`;
  the API serves JSON and files, never active content. The `/oauth/callback`
  relay page carries its own CSP that pins its inline script by SHA-256 hash.

## Container lifecycle service (/appmesh/container/*)

The agent embeds the official Docker Go client and drives the Docker Engine
API itself. The daemon is the only caller of this narrow App-Mesh-level
surface — raw Engine API paths are never exposed. Requests from any other
host are rejected with 403 (the peer must be loopback or this agent's own
listen address, the same private-transport rule the daemon applies on its
internal routes); a local request must also carry the PSK headers
`X-Request-ID` and `X-Request-HMAC`, and anything else is rejected with
status 407.

| Endpoint | Method | Description |
| --- | --- | --- |
| `/appmesh/container/ping` | GET | Engine reachability and negotiated API version |
| `/appmesh/container/image?ref=` | GET | Image presence (404 when missing) |
| `/appmesh/container/image/ensure` | POST | Pull if missing; per-reference single flight, deduped and bounded progress in the reply; registry credentials ride the body, never logs |
| `/appmesh/container/run` | POST | One signed call: remove owned leftovers of the names (labels verified, tail logs returned for the archive), create, start and inspect; a failed start cleans up after itself |
| `/appmesh/container/{idOrName}` | GET | Inspect projection: `id`, `pid`, `running`, `exitCode`, `health`, `labels` |
| `/appmesh/container/{id}/logs?sinceNs=&tail=` | GET | Demultiplexed log lines with RFC3339 timestamps resolved to epoch nanoseconds |
| `/appmesh/container/{id}/stop` | POST | Graceful stop (`graceSeconds`) |
| `/appmesh/container/{id}/kill` | POST | SIGKILL |
| `/appmesh/container/{id}` | DELETE | Remove (`force`, `volumes`) |
| `/appmesh/container/{id}/exec` | POST | Run an argv inside the container, return its exit code (health probes) |
| `/appmesh/container/list` | GET | All `appmesh.managed` labeled containers |

Implementation notes:

- The daemon (`DockerApiProcess`) signs the `X-Request-ID` value with the
  shared process HMAC key.
- The routes exist only when `Docker.Enable` is true (the default; the
  `APPMESH_DOCKER_Enable` environment variable overrides it, mirroring the
  daemon's switch) and a Docker endpoint is configured: `DOCKER_HOST` set,
  or the default `/var/run/docker.sock` present. `DOCKER_HOST` also
  covers a podman compatibility socket or a remote engine.
- The Docker client negotiates the Engine API version itself; the daemon
  holds no version knowledge.
- The agent stamps the ownership labels (`appmesh.managed`, `appmesh.app`)
  at create and verifies them before any owned delete: cleanup can never
  remove a foreign container.

## Container events push

The agent subscribes to Docker events filtered to `appmesh.managed`
containers and pushes `die` events plus a periodic liveness marker to the
daemon's internal route `/appmesh/internal/container-event` over the pooled
local connection, signed with the boot PSK. While the markers arrive, the
daemon's every-tick container exit poll stands down; a stale marker (for
example during an agent restart) re-arms the poll automatically.

Reference:

[Docker Engine API Documentation](https://docs.docker.com/reference/api/engine/)
