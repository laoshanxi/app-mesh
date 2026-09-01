# Cluster Authentication with the Bundled Auth Stack

- Status: Accepted
- Date: 2026-08-29
- Related: ADR 0009 (authentication service), `docs/source/Security.md`

## Problem

ADR 0009 defines one logical issuer per cluster. It defines the node roles
`standalone`, `owner`, and `follower`. The runtime already contains the
required pieces: role resolution, the inert `auth-service` App on followers,
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
                 │ Engine :6060 HTTPS / :6059 TCP / :6058 WSS   │
                 └──────────────┬───────────────────────────────┘
                                │ forwarded requests (TLS TCP :6059,
                                │ msgpack, bearer unchanged)
                 ┌─ follower nodes ────────────────────────────┐
                 │ Engine only. auth-service App holds inert.   │
                 │ Discovery/JWKS fetched from the owner.       │
                 └──────────────────────────────────────────────┘
```

- Exactly one node is `standalone` or `owner` (`is_auth_owner`). Only that
  node runs Dex. Only that node bootstraps credentials
  (`src/auth/appmesh-auth.sh`).
- Every node configures the same issuer string. Tokens carry `iss` equal to
  that string. Every Engine validates tokens locally against it.
- `access_url` is per-node routing. It can differ from the issuer: the
  owner can use its loopback Dex, and followers use a route to the owner.

Two routes give followers access to the owner:

| Route | issuer / access_url | When to use |
|---|---|---|
| A. Agent proxy (default) | `https://owner.example.com:6060/auth` | TLS front door. This route matches the rule "the issuer listener stays on loopback, Agent is the only public proxy". |
| B. Protected network | `http://<owner-cluster-address>:6062/auth` with `APPMESH_AUTH_DEX_LISTEN` bound to the cluster interface | Container or compose networks and private networks only. Do not expose the plaintext listener publicly. |

The docker-compose cluster uses route B. The compose network is a protected
cluster network.

## Install and configuration

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
     --oidc-access-url https://owner.example.com:6060/auth
```

Effects:

- The `auth-service` App stays enabled and inert (`hold_system_app`). It
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
| Dex process | runs as `auth-service` System App | never runs |
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
node that serves the request. A forwarded `PUT /appmesh/principal/<id>`
changes only the target node. Apply this rule:

- Mutate authorization data on one node. The owner is the natural
  administrative entry point.
- Distribute the change in one of two ways: apply the same API calls on
  every node, or copy the owner's runtime
  `work/config/authorization.yaml` to the followers and restart their
  daemons. Keep the file mode at 0600. Keep the runtime user as owner.
  A follower bootstrap creates no `work/config` directory; create it
  first (`mkdir -p <home>/work/config`) before the first copy.
- A follower without a principal entry authenticates a user. It grants
  nothing beyond the configured provisioning policy
  (`explicit-or-minimal` by default).

Automated replication is out of scope here. It needs its own design, for
example watch-and-push or mutation forwarding to a configured writer node.

## docker-compose cluster

`script/docker/docker-compose.yaml` changes:

- `appmesh_master`: `APPMESH_AUTH_ROLE=owner`,
  `APPMESH_AUTH_ISSUER=http://appmesh_master:6062/auth`, and
  `APPMESH_AUTH_DEX_LISTEN=0.0.0.0:6062`. The compose network only reaches
  this listener. Do not publish the port publicly. A container healthcheck
  calls `appmesh-auth.sh service-health`.
- `appmesh_slave*`: `depends_on: appmesh_master: service_healthy`,
  `APPMESH_AUTH_ROLE=follower`, the identical issuer, and an explicit
  `APPMESH_AUTH_ACCESS_URL=http://appmesh_master:6062/auth`. The packaged
  `oidc.yaml` default points at loopback. That default is wrong on a
  follower.
- Clients reach the issuer in-network at
  `http://appmesh_master:6062/auth`. Host-side CLI usage publishes the
  master REST port. For password and device flows only, bind the Dex port
  to host loopback. The CLI then passes `--auth-access-url`. This argument
  is routing-only. The published endpoints still must sit on the issuer
  origin.

## Verification

The verification runs in the `appmesh-e2e` environment against a
`make pack` output (package root). Two instances share one host. Different
port ranges separate the instances.

1. The owner uses the default ports. The follower uses offset ports. Both
   instances come from the same package root.
2. Check the follower process list for a Dex process. Check the
   authentication state directory. It must stay empty of identity files.
3. Run first-admin `appm logon` on the owner. Use a loopback connection.
4. Send a forwarded request from the owner Engine to the follower. Use
   `X-Target-Host: 127.0.0.1:<follower-tcp-port>`. Expect a successful
   response. Check the follower log for its own validation of the same
   bearer.
5. Send the same token directly to the follower. Expect a successful
   response.
6. Send a tampered token to both nodes. Expect rejection.

The results are recorded in `ClusterAuthProgress.md`.

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
