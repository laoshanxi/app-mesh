# Cluster

This document specifies multi-node operation: node roles, joining, authenticated request forwarding, authorization-data consistency, and the packaged docker-compose cluster. The trust model and the failover sequence live in [Security](../security/Security.md); the deployment procedure lives in [Install](../deploy/Install.md#cluster-authentication-service).

## 1. Topology

```text
                 ┌─ owner node ────────────────────────────────┐
 clients ──────► │ Agent :6060 (public TLS)                    │
                 │   └─ /auth/* ──► Dex 127.0.0.1:6065 (loopback) │
                 │ Engine :6062 TCP / :6063 HTTPS + WSS         │
                 └──────────────┬───────────────────────────────┘
                                │ forwarded requests (TLS TCP :6062,
                                │ msgpack, bearer unchanged)
                 ┌─ follower nodes ────────────────────────────┐
                 │ Engine only. identity App holds inert.       │
                 │ Discovery/JWKS fetched from the owner.       │
                 └──────────────────────────────────────────────┘
```

- A node role is `standalone`, `owner`, or `follower`. Exactly one node is `standalone` or `owner`: only that node runs Dex and bootstraps built-in credentials.
- Every node configures the same issuer string. Tokens carry `iss` equal to that string; every Engine validates tokens locally against it.
- `access_url` is per-node routing. It can differ from the issuer: the owner can use its loopback Dex, and followers use a route to the owner.

Two routes give followers access to the owner:

| Route | issuer / access_url | When to use |
| --- | --- | --- |
| A. Agent proxy (default) | `https://owner.example.com:6060/auth` | TLS front door. The issuer listener stays on loopback; the Agent is the only public proxy |
| B. Protected network | `http://<owner-cluster-address>:6065/auth` with `APPMESH_AUTH_LISTEN` bound to the cluster interface | Container or compose networks and private networks only. Do not expose the plaintext listener publicly |

## 2. Owner and follower setup

```shell
# Owner
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role owner
# Optional public issuer (default: http://127.0.0.1:6065/auth):
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role owner \
     --oidc-issuer https://owner.example.com:6060/auth

# Follower (the join action)
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role follower \
     --oidc-issuer   https://owner.example.com:6060/auth \
     --oidc-access-url https://owner.example.com:6060/auth \
     --oidc-browser-entry https://owner.example.com
```

| Setting | Owner | Follower |
| --- | --- | --- |
| `AuthStack.role` / `APPMESH_AUTH_ROLE` | `owner` | `follower` |
| `OIDC.issuer` / `APPMESH_AUTH_ISSUER` | canonical issuer | identical string |
| `OIDC.access_url` / `APPMESH_AUTH_ACCESS_URL` | loopback `http://127.0.0.1:6065/auth` is valid | a route that reaches the owner's Dex |
| `OIDC.tls_verify`, `OIDC.ca_path` | as the route requires | as the route requires |
| Dex process | runs as `identity` System App | never runs |
| first-admin enrollment window | open until claimed, loopback only | none |

- The issuer is one setting that controls three things: the issuer Dex advertises in discovery, the `iss` value the Engine verifies, and the path the Agent reverse proxy mounts.
- On a follower the `identity` App stays enabled and inert: it stays healthy, starts no local Dex, and writes no authentication state.
- The follower Engine fetches discovery and JWKS through `access_url` and rejects every token whose `iss` differs from the configured issuer.
- Startup tolerates an unreachable owner for 120 seconds, then fails. Start followers after the owner, or rely on the restart policy.
- Omitting `--auth-role` keeps the current role selection; the packaged `auth-stack.yaml` default (`standalone`) then applies.

## 3. Request forwarding

The sequence below describes `appm -H <gateway> -F <target> …` and the SDK equivalent (`X-Target-Host`).

1. The CLI sends `GET /appmesh/auth/config` with `X-Target-Host: <target>`. Two GET requests can forward without a bearer: `GET /appmesh/auth/config` and `GET /.well-known/oauth-protected-resource`. The gateway rejects every other anonymous forward request.
2. The CLI gets tokens directly from the shared authentication service. Issuer-side discovery is a direct client-to-issuer fetch; it never forwards.
3. The CLI sends the request with `Authorization: Bearer` and `X-Target-Host: <target>`.
4. The gateway validates the bearer before it opens an outbound connection. The authenticated principal must hold the `host-forward` permission — the outbound connection is itself a capability, and the grant prevents port-scan probing through open/closed/timeout answers. The Go agent enforces the same grant on its 6060 entry.
5. The gateway erases `X-Target-Host` and injects `X-AppMesh-Forwarded: 1` plus a route UUID for event correlation. The target never sees a forwarding selector, cannot re-forward, and a forwarding loop cannot occur.
6. The gateway forwards the request over its TLS TCP (msgpack) channel to the target's TCP port. The `Authorization` header is forwarded unchanged.
7. The target validates the same bearer through the normal route path, resolves the principal from its local authorization data, and applies permissions. `X-AppMesh-Forwarded` marks the request as forwarded; direct-only operations (first-admin enrollment, workflow capability) reject it.

Gateway validation is admission control; target validation is the authorization decision. The gateway and the target share no secret — they agree only on the issuer. Forwarded subscriptions require TCP or WSS (events need a persistent connection); the gateway keeps the subscription route and sends later event frames to the subscribing client.

## 4. Authorization data consistency

`authorization.yaml` is node-local: the principal and role APIs write the node that serves the request, and a forwarded change affects only the target node.

### 4.1 Cluster replication (recommended)

The owner is the single writer; followers pull its policy and converge like read replicas. The engine implements the pull — no external tooling.

- The owner publishes the replication accept list into `APPMESH_AUTH_REPLICATION_TOKEN_FILE` when that variable is set: one bearer per line, each with a follower label. Per-follower tokens close the shared-secret exposure: one compromised follower is revoked alone, without re-keying the cluster. Issuing, rotating, and revoking take effect without a restart:

  ```shell
  # on the owner: print a new per-follower token exactly once
  /opt/appmesh/script/appmesh-auth.sh replication-token slave1
  # with a provisioned <label>.token slot present, the same command rotates
  # the token in place (the follower picks it up on its next pull)
  /opt/appmesh/script/appmesh-auth.sh replication-token-list
  /opt/appmesh/script/appmesh-auth.sh replication-token-revoke slave1
  # Vault source only: undo a revocation (deletes the tombstone, re-issues
  # the token, AppRole and credential file)
  /opt/appmesh/script/appmesh-auth.sh replication-token-restore slave1
  ```

  A pull with a revoked token is rejected with `401`; other followers keep pulling. The matched label is written to the owner log, so the audit trail names the follower behind every snapshot served. The packaged compose cluster provisions per-follower tokens at bootstrap and projects each follower's own `<label>.token` out of the `appmesh_replication` volume as a read-only subpath mount — a follower sees exactly its one credential file.
- **Vault source (optional).** Deployments that run a secrets service select `APPMESH_AUTH_REPLICATION_TOKEN_SOURCE=vault` plus `APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR` and `APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE` on every node; the accepted tokens then live in Vault KV v2 under `secret/appmesh/replication`. Each follower holds one scoped Vault machine identity (an AppRole whose policy reads its own KV entry and issues its TLS leaf certificates from the cluster PKI). Revocation under this source is persistent — `replication-token-revoke` writes a tombstone, deletes the token, and destroys the follower's AppRole; `replication-token-restore` re-enables it explicitly. A Vault outage fails closed: pulls answer `503` and retry on the next cycle.
  - The follower AppRole secret_id is deliberately reusable: the node logs in with the same pair on every pull and every restart, so one-time secret_ids would strand the follower mid-operation unless an operator re-delivers credentials.
  - The compose layer ships Vault as an opt-in addition: `docker compose -f docker-compose.yaml -f docker-compose.vault.yaml up -d`. The base cluster stays file-based with no Vault dependency. The Vault listener in the compose layer is plaintext on the trusted bridge network (a demo posture); production enables listener TLS, auto-unseal, periodic tokens, wrapped secret_id delivery, and an HSM-backed seal.
  - Operating without Vault: `appmesh-auth.sh service` dies when Vault is unreachable and the restart policy retries — fail closed, never serve replication decisions from a stale source. Restore Vault (the compose layer re-unseals automatically), or fall back to the file source by unsetting `APPMESH_AUTH_REPLICATION_TOKEN_SOURCE=vault` and the `APPMESH_*_VAULT_*` variables on every node and recreating the follower containers so each remounts its projected token. Issued TLS material stays valid; only new issuance needs Vault again.
- A follower with `APPMESH_AUTH_REPLICATION_FROM` (the owner's engine listener, `https://appmesh_master:6063` in compose, verified with the owner CA through `APPMESH_AUTH_REPLICATION_CA`) plus the token file pulls the full policy snapshot every `APPMESH_AUTH_REPLICATION_INTERVAL` seconds (default 30), and immediately when a login presents a principal the follower has never seen.
- The follower validates the snapshot before committing, and the owner snapshot always wins — including over a locally auto-provisioned role-less record. The synced policy is cached under its own name, `work/config/replica-policy.yaml`, so a restart authorizes immediately. While replication is configured, the principal and role APIs on the follower reject writes with a pointer to the owner.
- The snapshot endpoint `GET /appmesh/auth/replication/policy` answers only the replication token (compared in constant time); without the token file configured, the route behaves as if it did not exist.

### 4.2 Manual distribution (fallback)

Without replication, apply the rule by hand:

- Mutate authorization data on one node; the owner is the natural administrative entry point.
- Copy the owner's runtime `work/config/authorization.yaml` to the followers as the runtime user (the daemon runs as `appmesh` in containers and cannot read a `root:root 0600` file):

  ```shell
  docker exec -i -u appmesh appmesh_slave1 sh -c \
      'mkdir -p /opt/appmesh/work/config && cat > /opt/appmesh/work/config/authorization.yaml' \
      < authorization.yaml
  ```

- Copy the file before the follower first serves an authenticated request: the first resolve of an unknown principal auto-provisions a role-less record that shadows a later copy until the follower restarts or an administrator re-applies the binding. A copy that lands first needs no restart. Keep the file mode at `0600` with the runtime user as owner.
- A follower without a principal entry authenticates a user but grants nothing beyond the configured provisioning policy (`explicit-or-minimal` by default).

## 5. docker-compose cluster

`script/docker/docker-compose.yaml` runs one owner, two followers, one LLM node (`laoshanxi/appmesh:llm`, follower role, llm-agent preinstalled), and one MCP server, with the bundled authentication service.

Listeners of `appmesh_master`:

| Port (container → host) | Service | Used by |
| --- | --- | --- |
| 6060 → 6060 | Go agent REST front | REST clients and SDKs; applies its own `X-Target-Host` forwarding |
| 6062 → 6062 | engine TCP API | SDK TCP transport: event subscriptions and task workers |
| 6063 → 6063 | engine WSS/HTTPS listener | the CLI (`appm` speaks WSS) and SDK WSS clients |
| 6065 → 127.0.0.1:6065 | Dex authentication listener | followers in-network; host loopback only, for password and device flows |
| 443 → 443 | web UI | browsers; the UI shares the master network namespace |

The engine listeners 6062 and 6063 are TLS and bearer-authenticated. Environment variables:

| Variable | Master | Follower |
| --- | --- | --- |
| `APPMESH_AUTH_ROLE` | `owner` — runs Dex and owns the SQLite identity state | `follower` — no local Dex |
| `APPMESH_AUTH_ISSUER` | `http://appmesh_master:6065/auth` — one identical string on every node and client | same |
| `APPMESH_AUTH_ACCESS_URL` | unset — discovery defaults to the issuer | the issuer string (the packaged default points at loopback and is wrong on a follower) |
| `APPMESH_AUTH_BROWSER_ENTRY` | `https://127.0.0.1/auth` — the published UI that fronts the issuer path | the owner value; a follower cannot derive the entry itself |
| `APPMESH_AUTH_LISTEN` | `0.0.0.0:6065` — reachable on the compose network only, never publish it publicly | unset — a follower starts no listener |

A container healthcheck calls `appmesh-auth.sh service-health`; followers gate on `depends_on: appmesh_master: service_healthy`.

### 5.1 MCP service

The `appmesh_mcp` service runs the MCP server from the published `laoshanxi/appmesh:mcp` image: an OAuth resource server that validates caller tokens against the master's Dex and forwards the same token to the engine, which enforces RBAC. The master's TLS material lives in the `appmesh_tls` named volume; the MCP service and the followers mount exactly its `ca.pem` (a read-only subpath mount) to verify the engine — the master's private keys never cross a service boundary. Followers serve TLS under their own identities; only verification trust is shared.

The OAuth metadata advertises the in-network issuer, which a host client cannot resolve. A host client passes a token from the password flow instead of running the browser flow:

```shell
curl -s -u "appmesh-mcp-user:" -X POST http://127.0.0.1:6065/auth/token \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@appmesh.local" \
    --data-urlencode "password=<password>" \
    --data-urlencode "scope=openid audience:server:client_id:appmesh-api"
```

Point the MCP client at `http://127.0.0.1:6070/mcp` with the returned access token as the bearer. The endpoint is plaintext on host loopback only, the same posture as the Dex port.

### 5.2 First sign-in in the compose cluster

The compose network runs the issuer over plain HTTP and enrollment accepts a loopback client only. Do the first sign-in inside the master container:

```shell
docker exec appmesh_master sh -c 'printf "%s\n" "$(grep "^password=" /opt/appmesh/work/auth/secrets/initial-admin-credentials | cut -d= -f2-)" | /opt/appmesh/bin/appm -H wss://127.0.0.1:6063 logon --username admin@appmesh.local --password-stdin --auth-allow-http'
```

- `--auth-allow-http` is necessary: the issuer uses plain HTTP on the protected compose network.
- The master's server certificate covers `127.0.0.1`, the container address, `appmesh_master`, and `localhost`.
- After enrollment, host-side CLI work uses the published WSS port. The issuer hostname does not resolve on the host, so point the CLI at the published Dex route:

  ```shell
  docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem
  appm -H wss://127.0.0.1:6063 --ca-cert ./master-ca.pem logon \
      --auth-access-url http://127.0.0.1:6065/auth --auth-allow-http
  appm view
  ```

  The CLI remembers the CA with the endpoint at logon, pinned to an absolute path, so later commands need neither `-H` nor `--ca-cert`.
- Then distribute the owner's `work/config/authorization.yaml` to every follower (see "Authorization data consistency"). A fresh follower has no `work/config` directory; create it before the first copy.

### 5.3 Cluster TLS trust

See [TLS and certificates](../security/TLS.md) for the key reference and the client matrix. Every node generates its own CA at first start; an SDK on one node verifies peers against the local CA and fails with `BadSignature` against another node's certificate. Use one of these patterns.

Pattern 1 — trust the target CA on the client only:

1. Copy the target CA out: `docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem`.
2. Name it on the CLI: `appm -H wss://appmesh_master:6063 --ca-cert ./master-ca.pem logon`.
3. The CLI remembers the CA with the endpoint; later commands need no `--ca-cert`.

Pattern 2 — share one CA across the cluster:

1. On the owner, run `script/ssl/generate_ssl_cert.sh` once with `APPMESH_SSL_EXTRA_SAN` set to the comma-separated names of every peer (for example `appmesh_slave1,appmesh_slave2`). The server certificate then covers every node name.
2. Copy the whole `ssl` directory from the owner to every follower.
3. To add a node later, keep the existing CA and sign fresh leaf certificates: set `APPMESH_SSL_CA_CERT` and `APPMESH_SSL_CA_KEY` to the existing CA files, set `APPMESH_SSL_EXTRA_SAN` to the new node name, and copy the new leaf files and `ca.pem` to the new node. Never distribute `ca-key.pem`.

Pattern 3 — central issuance (Vault PKI, one trust domain):

1. Select the source with `APPMESH_SSL_SOURCE=vault` plus `APPMESH_SSL_VAULT_ADDR` and `APPMESH_SSL_VAULT_TOKEN_FILE`. The Vault PKI engine holds one cluster CA and a single issuing role (`appmesh-node`; `APPMESH_SSL_VAULT_PKI_ROLE` to change it).
2. The role issues both server and client leaves with the same name coverage as the self-signed generator — hostname, FQDN, local addresses, and `APPMESH_SSL_EXTRA_SAN` peers — but is domain-scoped, never `allow_any_name`: issuance is limited to the names in `APPMESH_PKI_ALLOWED_DOMAINS`. A compromised node therefore cannot mint a cluster-CA certificate for an arbitrary DNS name.
3. Every node's `appmesh-auth.sh bootstrap` requests its own five files: `ca.pem` plus the server and client pairs. There is no `ca-key.pem` by design: the CA private key never leaves Vault.
4. Bootstrap is idempotent by trust, not by file presence: existing material that does not chain to the current Vault CA is re-issued. Renew on demand with `appmesh-auth.sh tls-renew`, then restart the node (the engine loads certificates once at start); a physical host can run the action from a systemd timer or cron.
5. Vault drops underscore DNS names from certificates outright, so the compose layer dials a hyphenated network alias (`appmesh-master`) instead of the underscore service name; the issuer string follows the same alias. The generated root must carry a subject (`common_name="AppMesh Root CA"`): an empty issuer name fails strict chain verification. The owner's service token is minted with a 10-year TTL matching the CA root's horizon, so the compose layer sets the cluster `max_lease_ttl` to the same value.

Do not copy only `ca.pem` onto a follower: it then trusts the shared CA but still serves its old self-signed certificate, which clients that verify against the shared CA reject (pattern 3 is the exception: a follower re-issues its own leaves from the same CA).

A macOS client rejects leaf certificates with a validity above 825 days. The packaged script sets 825 days for leaves and 3650 days for the CA; the Vault role mirrors both.

### 5.4 Web UI entry

The `appmesh_ui` service shares the network namespace of `appmesh_master` and serves HTTPS on port 443. Point a browser at `https://<host>/`. The UI proxies `/appmesh/` to the master agent on 6060 and `/auth/` to the master Dex listener. The UI image waits for the API upstream before nginx starts; if the upstream stays unreachable for 60 seconds the container exits, and the restart policy attaches a new container to the live namespace of the master.

## 6. Limitations

- HTTP-protocol SDK clients append their own base port to `X-Target-Host`. The Go agent handles this case (port 6060 becomes an HTTPS hop); the engine gateway selects a TCP-msgpack forward to port 6060 and no listener serves that protocol there. WSS clients, TCP clients, and explicit `:6062` targets work against the engine gateway.
- Browser flows (authorization code with PKCE) require browser access to the issuer origin. Off-network clients are limited to password and device flows through `--auth-access-url` rewriting.
- Owner failover is the manual fence-and-promote sequence specified in [Security](../security/Security.md#shared-authentication-service).
