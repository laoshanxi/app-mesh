# Cluster Authentication with the Bundled Auth Stack

- Status: Accepted
- Date: 2026-08-29
- Related: [ADR 0009](https://github.com/laoshanxi/app-mesh/blob/main/docs/adr/0009-authentication-service.md)
  (authentication service), [Security](../Security.md)
  (trust model), [Authentication](../Authentication.md) (password and token
  operations), [Install](../Install.md) (deployment procedures)

## Problem

This section describes the state before this design was implemented.

ADR 0009 defines one logical issuer per cluster. It defines the node roles
`standalone`, `owner`, and `follower`. The runtime already contains the
required pieces: role resolution, the inert `identity` App on followers,
and bearer validation at the gateway and at the target. Three gaps remain.
Each gap blocks a working multi-node deployment of the bundled stack.

1. `script/docker/docker-compose.yaml` starts a master and three slaves.
   Every node keeps the default role `standalone`. Each node then runs its
   own Dex process with its own signing keys. The issuer string is identical
   on all nodes, but the keys are different. A token from one node fails
   signature validation on another node. Cross-node forwarding cannot
   authenticate.
2. Joining a node to the owner requires manual edits of `auth-stack.yaml`
   and of environment variables. There is no standard setup action.
   `setup.sh` has no role option.
3. Authorization data (`authorization.yaml`) is node-local. No sync
   mechanism exists. The documentation requires "shared authorization
   data". It does not say how an operator keeps the nodes consistent.

## Goals

- Provide one standard install-time action. The action configures a node as
  the authentication owner or as a follower of an owner.
- Followers must not run Dex. Followers must not create built-in
  credentials. Followers must verify tokens from the owner's issuer.
- Show the owner/follower model and authenticated forwarding in the
  packaged docker-compose cluster.
- Document the consistency procedure for authorization data.

## Non-goals

- Automatic authorization-data replication between nodes. Every mutation
  endpoint writes node-local state today. Replication needs a separate
  design. This document defines the manual procedure only.
- Active-active authentication. One active writer is allowed. See ADR 0009
  and `Security.md`.
- Windows. The bundled stack ships on Linux and macOS. Windows
  installations stay external-issuer consumers. `setup.ps1` stays
  unchanged.

## Topology

```
                 ┌─ owner node ────────────────────────────────┐
 clients ──────► │ Agent :6060 (public TLS)                    │
                 │   └─ /auth/* ──► Dex 127.0.0.1:6062 (loopback) │
                 │ Engine :6058 HTTPS + WSS / :6059 TCP         │
                 └──────────────┬───────────────────────────────┘
                                │ forwarded requests (TLS TCP :6059,
                                │ msgpack, bearer unchanged)
                 ┌─ follower nodes ────────────────────────────┐
                 │ Engine only. identity App holds inert.       │
                 │ Discovery/JWKS fetched from the owner.       │
                 └──────────────────────────────────────────────┘
```

- Exactly one node is `standalone` or `owner` (`is_auth_owner`). Only that
  node runs Dex. Only that node bootstraps credentials
  (`src/apps/identity/appmesh-auth.sh`).
- Every node configures the same issuer string. Tokens carry `iss` equal to
  that string. Every Engine validates tokens locally against it.
- `access_url` is per-node routing. It can differ from the issuer: the
  owner can use its loopback Dex, and followers use a route to the owner.

Two routes give followers access to the owner:

| Route | issuer / access_url | When to use |
|---|---|---|
| A. Agent proxy (default) | `https://owner.example.com:6060/auth` | TLS front door. This route matches the rule "the issuer listener stays on loopback, Agent is the only public proxy". |
| B. Protected network | `http://<owner-cluster-address>:6062/auth` with `APPMESH_AUTH_LISTEN` bound to the cluster interface | Container or compose networks and private networks only. Do not expose the plaintext listener publicly. |

The docker-compose cluster uses route B. The compose network is a protected
cluster network.

## Install and configuration

The authoritative operator procedure is in
[Install](../Install.md#cluster-authentication-service). This section records
the design behind it.

### Owner

```shell
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role owner
# Optional public issuer (default: http://127.0.0.1:6062/auth):
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role owner \
     --oidc-issuer https://owner.example.com:6060/auth
```

- `--auth-role owner` persists `APPMESH_AUTH_ROLE=owner` in the daemon
  environment file. The resolution order stays: environment first, then
  `auth-stack.yaml` (`AuthorizationStore::resolveAuthRole`,
  `appmesh-auth.sh`).
- The issuer is one setting that controls three things: the issuer that
  Dex advertises in discovery, the `iss` value that the Engine verifies,
  and the path that the Agent reverse proxy mounts.

### Follower (the join action)

```shell
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role follower \
     --oidc-issuer   https://owner.example.com:6060/auth \
     --oidc-access-url https://owner.example.com:6060/auth \
     --oidc-browser-entry https://owner.example.com
```

Effects:

- The `identity` App stays enabled and inert (`hold_system_app`). It
  stays healthy, starts no local Dex, writes no authentication state, and
  does not trigger the restart policy.
- The Engine fetches discovery and JWKS through `access_url`. It rejects
  every token whose `iss` differs from the configured issuer.
- Startup tolerates an unreachable owner for 120 seconds
  (`AppMeshDaemon::prewarmAuthentication`). Startup fails after that
  period. Start followers after the owner, or rely on the restart policy.

If you omit `--auth-role`, the setup keeps the current role selection. The
packaged `auth-stack.yaml` default (`standalone`) then applies.

### Configuration matrix

| Setting | Owner | Follower |
|---|---|---|
| `AuthStack.role` / `APPMESH_AUTH_ROLE` | `owner` | `follower` |
| `OIDC.issuer` / `APPMESH_AUTH_ISSUER` | canonical issuer | identical string |
| `OIDC.access_url` / `APPMESH_AUTH_ACCESS_URL` | loopback `http://127.0.0.1:6062/auth` is valid | a route that reaches the owner's Dex |
| `OIDC.tls_verify`, `OIDC.ca_path` | as the route requires | as the route requires |
| Dex process | runs as `identity` System App | never runs |
| first-admin enrollment window | open until claimed, loopback only | none (`AuthorizationStore` opens it only for standalone/owner) |

## Forward authentication

The sequence below describes `appm -H <gateway> -F <target> ...`.

1. The CLI sends `GET /appmesh/auth/config` with `X-Target-Host: <target>`.
   Two GET requests can forward without a bearer:
   `GET /appmesh/auth/config` and
   `GET /.well-known/oauth-protected-resource`. The gateway rejects every
   other anonymous forward request (`Worker::isPublicForwardRequest`).
2. The CLI gets tokens directly from the shared authentication service.
   Issuer-side discovery is a direct client-to-issuer fetch. It never
   forwards. Session reuse requires a match of issuer, client ID, and
   audience with the stored session.
3. The CLI sends the request with `Authorization: Bearer` and
   `X-Target-Host: <target>`.
4. The gateway validates the bearer before it opens an outbound
   connection. HTTP and TCP requests are verified at the gateway
   (`Worker::process`). A WSS session is authenticated at the upgrade. A
   forwarded WSS frame repeats the same bearer. The bearer must resolve to
   the principal that is pinned to the connection.
5. The gateway erases `X-Target-Host` and injects
   `X-AppMesh-Forwarded: 1` plus a route UUID for event correlation. The
   target never sees a forwarding selector. The target cannot re-forward.
   A forwarding loop cannot occur. No TTL and no visited list is
   necessary.
6. The gateway forwards the request over its TLS TCP (msgpack) channel to
   the target's TCP port. The `Authorization` header is forwarded without
   a change.
7. The target validates the same bearer through the normal route path. It
   checks `iss` for an exact match, checks `aud: appmesh-api`, and fetches
   JWKS from its own `access_url`, which points to the owner. It resolves
   the principal from its local authorization data and applies
   permissions. `X-AppMesh-Forwarded` marks the request as forwarded.
   Direct-only operations reject it. Examples: first-admin enrollment and
   workflow capability.

Gateway validation is admission control. It prevents anonymous use of the
outbound connection. Target validation is the authorization decision. The
gateway and the target share no secret. They only agree on the issuer.

## Authorization data consistency

`authorization.yaml` is node-local. The principal and role APIs write the
node that serves the request. A forwarded `POST /appmesh/principal/<id>`
changes only the target node. Apply this rule:

- Mutate authorization data on one node. The owner is the natural
  administrative entry point.
- Distribute the change in one of two ways: apply the same API calls on
  every node, or copy the owner's runtime
  `work/config/authorization.yaml` to the followers. Copy the file before
  the follower first serves an authenticated request. The first resolve of
  an unknown principal auto-provisions a role-less record and saves it.
  That in-memory record then shadows a later copy until the follower
  restarts or an administrator re-applies the binding through the
  principal API. A copy that lands first needs no
  restart: the follower adopts the entry from disk when it first resolves
  the principal, and a later save keeps the entry. Keep the file mode at
  0600. Keep the runtime user as owner.
  A follower bootstrap creates no `work/config` directory; create it
  first (`mkdir -p <home>/work/config`) before the first copy.
- A follower without a principal entry authenticates a user. It grants
  nothing beyond the configured provisioning policy
  (`explicit-or-minimal` by default).

Automated replication is out of scope here. It needs its own design, for
example watch-and-push or mutation forwarding to a configured writer node.

## docker-compose cluster

`script/docker/docker-compose.yaml` runs one owner, two followers, one LLM
node (`laoshanxi/appmesh:llm`, follower role, llm-agent preinstalled), and one
MCP server, with the bundled authentication service.

Listeners of `appmesh_master`. Host ports are remapped (+10000) so a local
daemon keeps the defaults:

| Port (container → host) | Service | Used by |
| --- | --- | --- |
| 6060 → 16060 | Go agent REST front | REST clients and SDKs; it applies its own `X-Target-Host` forwarding |
| 6058 → 16058 | engine WSS/HTTPS listener | the CLI (`appm` speaks WSS) and SDK WSS clients, including event subscriptions |
| 6059 → 16059 | engine TCP API | SDK TCP transport: event subscriptions and task workers |
| 6062 → 127.0.0.1:16062 | Dex authentication listener | followers in-network; host loopback only, for password and device flows |
| 443 → 443 | web UI | browsers; the UI shares the master network namespace |

The engine listeners 6058 and 6059 are TLS and bearer-authenticated, the
same posture as the REST front. Host clients trust the master CA once
(`docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem`). Only
the first sign-in runs inside the container (see below). The `appmesh_mcp`
service publishes its own Streamable HTTP endpoint at `127.0.0.1:16071` for
host AI clients.

Environment variables:

| Variable | Master | Follower |
| --- | --- | --- |
| `APPMESH_AUTH_ROLE` | `owner` — runs Dex and owns the SQLite identity state | `follower` — no local Dex |
| `APPMESH_AUTH_ISSUER` | `http://appmesh_master:6062/auth` — one identical string on every node and client | same |
| `APPMESH_AUTH_ACCESS_URL` | unset — discovery defaults to the issuer | the issuer string; the packaged default points at loopback and is wrong on a follower |
| `APPMESH_AUTH_BROWSER_ENTRY` | `https://127.0.0.1/auth` — the published UI that fronts the issuer path | the owner value; a follower cannot derive the entry itself |
| `APPMESH_AUTH_LISTEN` | `0.0.0.0:6062` — reachable on the compose network only, never publish it publicly | unset — a follower starts no listener |
| `APPMESH_REST_PrometheusExporterListenPort` | `6061` | `6061` |

A container healthcheck calls `appmesh-auth.sh service-health`. Followers gate
on `depends_on: appmesh_master: service_healthy`.

Clients reach the issuer in-network at `http://appmesh_master:6062/auth`. The
REST port 6060 serves host REST clients and SDKs through the Go agent. For
password and device flows only, the Dex port is bound to host loopback.

### MCP service

The `appmesh_mcp` service runs the MCP server from the published
`laoshanxi/appmesh:mcp` image: an OAuth resource server that validates caller
tokens against the master's Dex and forwards the same token to the engine,
which enforces RBAC. The compose file needs no source checkout. The master's
TLS material lives in the `appmesh_tls` named volume; the service mounts the
volume read-only and verifies the engine with the master CA. Followers keep
their own CAs.

The OAuth metadata advertises the in-network issuer, which a host client
cannot resolve. A host client therefore passes a token from the password flow
instead of running the browser flow:

```shell
curl -s -u "appmesh-mcp-user:" -X POST http://127.0.0.1:16062/auth/token \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@appmesh.local" \
    --data-urlencode "password=<password>" \
    --data-urlencode "scope=openid audience:server:client_id:appmesh-api"
```

Point the MCP client at `http://127.0.0.1:16071/mcp` with the returned access
token as the bearer. The endpoint is plaintext on host loopback only, the same
posture as the Dex port.

### First sign-in in the compose cluster

The compose network runs the issuer over plain HTTP. The enrollment
accepts a loopback client only. Do the first sign-in inside the master
container. Use the loopback WSS listener and the packaged administrator
password:

```shell
docker exec appmesh_master sh -c 'printf "%s\n" "$(grep "^password=" /opt/appmesh/work/auth/secrets/initial-admin-credentials | cut -d= -f2-)" | /opt/appmesh/bin/appm -H wss://127.0.0.1:6058 logon --username admin@appmesh.local --password-stdin --auth-allow-http'
```

- `--auth-allow-http` is necessary. The issuer uses plain HTTP on the
  protected compose network.
- The server certificate of the master covers `127.0.0.1`, the container
  address, `appmesh_master`, and `localhost`.
- After the enrollment, host-side CLI work uses the published WSS port. The
  issuer hostname does not resolve on the host, so point the CLI at the
  published Dex route:

  ```shell
  docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem
  appm -H wss://127.0.0.1:16058 --ca-cert ./master-ca.pem logon \
      --auth-access-url http://127.0.0.1:16062/auth --auth-allow-http
  appm view
  ```

  The CA is remembered with the endpoint at logon; later commands need
  neither `-H` nor `--ca-cert`.
- Then copy the owner's `work/config/authorization.yaml` to every
  follower before the follower first serves an authenticated request. A
  copy that lands first needs no restart: a follower adopts an entry from
  disk when it first resolves that principal. A follower that already
  served a request needs a restart after the copy. See "Authorization
  data consistency" above. A fresh follower has no `work/config`
  directory. Create the directory before the first copy.

### Cluster TLS trust

Every node generates its own CA at first start. An SDK on one node
verifies a peer certificate against the local CA by default. That CA did
not sign the peer certificate. The check fails with `BadSignature`. Use
one of these patterns.

Pattern 1. Trust the target CA on the client only:

1. Copy the target CA out: `docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem`.
2. Name it on the CLI: `appm -H wss://appmesh_master:6058 --ca-cert ./master-ca.pem logon --auth-allow-http`.
3. The CLI remembers the CA with the endpoint at logon. Later commands need no `--ca-cert`.

Pattern 2. Share one CA across the cluster:

1. On the owner, run `script/ssl/generate_ssl_cert.sh` once. Set
   `APPMESH_SSL_EXTRA_SAN` to the comma-separated names of every peer,
   for example `APPMESH_SSL_EXTRA_SAN=appmesh_slave1,appmesh_slave2`. The
   server certificate then covers every node name.
2. Copy the whole `ssl` directory from the owner to every follower. All
   nodes then serve certificates that the same CA signed.
3. To add a node later, keep the existing CA and sign fresh leaf
   certificates. Set `APPMESH_SSL_CA_CERT` and `APPMESH_SSL_CA_KEY` to the
   existing CA files and set `APPMESH_SSL_EXTRA_SAN` to the new node name.
   Copy the new leaf files and `ca.pem` to the new node. Never distribute
   `ca-key.pem`.

Do not copy only `ca.pem` onto a follower. The follower then trusts the
shared CA, but it still serves its old self-signed certificate. Clients
that verify against the shared CA reject it.

A macOS client rejects leaf certificates with a validity above 825 days.
The packaged script sets 825 days for leaf certificates and 3650 days for
the CA.

### Web UI entry

The `appmesh_ui` service shares the network namespace of
`appmesh_master` and serves HTTPS on port 443. Point a browser at
`https://<host>/`. The UI proxies `/appmesh/` to the master agent on
6060 and `/auth/` to the master Dex listener. The UI image waits for
the API upstream before nginx starts. If the upstream stays
unreachable for 60 seconds, the container exits. The restart policy
then attaches a new container to the live namespace of the master.

## Verification

The verification runs in the `appmesh-e2e` environment against a
`make pack` output (package root). Two instances share one host. Different
port ranges separate the instances.

1. The owner uses the default ports. The follower uses offset ports. Both
   instances come from the same package root.
2. Check the follower process list for a Dex process. Check the
   authentication state directory. It must stay empty of identity files.
3. Run the first-admin sign-in on the owner with the built-in password method:
   `appm logon --username admin@appmesh.local`. Use a loopback connection.
4. Send a forwarded request from the owner Engine to the follower. Use
   `X-Target-Host: 127.0.0.1:<follower-tcp-port>`. Expect a successful
   response. Check the follower log for its own validation of the same
   bearer.
5. Send the same token directly to the follower. Expect a successful
   response.
6. Send a tampered token to both nodes. Expect rejection.

This procedure was verified in the `appmesh-e2e` environment against the
packaged compose cluster.

## Limitations

- HTTP-protocol SDK clients append their own base port to
  `X-Target-Host`. The Go Agent handles this case: port 6060 becomes an
  HTTPS hop. The Engine gateway does not handle this case: it selects a
  TCP-msgpack forward to port 6060, and no listener serves that protocol
  on the port. WSS clients, TCP clients, and explicit `:6059` targets
  work against the Engine gateway. This limitation is documented and is
  not changed here.
- Browser flows (authorization code with PKCE) require browser access to
  the issuer origin. Off-network clients are limited to password and
  device flows through `--auth-access-url` rewriting.
- Owner failover stays the manual fence-and-promote sequence in
  `Security.md`.
