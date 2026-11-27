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
| B. Protected network | `http://<owner-cluster-address>:6065/auth` with `APPMESH_AUTH_LISTEN` bound to the cluster interface | Container or compose networks and private networks only. Do not expose the plaintext listener publicly. |

The docker-compose cluster uses route B. The compose network is a protected
cluster network.

## Install and configuration

The authoritative operator procedure is in
[Install](../Install.md#cluster-authentication-service). This section records
the design behind it.

### Owner

```shell
sudo /opt/appmesh/script/setup.sh --auth-mode builtin --auth-role owner
# Optional public issuer (default: http://127.0.0.1:6065/auth):
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
| `OIDC.access_url` / `APPMESH_AUTH_ACCESS_URL` | loopback `http://127.0.0.1:6065/auth` is valid | a route that reaches the owner's Dex |
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
   the principal that is pinned to the connection. The principal must also
   hold the `host-forward` permission — the outbound connection is itself a
   capability, and without the gate any authenticated principal could probe
   the network through open/closed/timeout answers (blind port-scan oracle).
   The Go agent enforces the same grant on its 6060 entry by checking the
   `/appmesh/principal/self` permissions.
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
changes only the target node. Two ways keep the nodes consistent:

### Cluster replication (recommended)

The owner is the single writer; followers pull its policy and converge like
read replicas. The engine implements the pull (no external tooling):

- The owner publishes the replication accept list into
  `APPMESH_AUTH_REPLICATION_TOKEN_FILE` when that variable is set: one
  bearer per line, each with a follower label. The packaged compose cluster
  provisions per-follower tokens at bootstrap
  (`APPMESH_AUTH_REPLICATION_FOLLOWERS` names the follower set) and
  projects each follower's own `<label>.token` out of the
  `appmesh_replication` volume as a read-only subpath mount — the
  projected-secret pattern used by Kubernetes Secrets: a follower sees
  exactly its one credential file, never the accept list, the owner's
  material, or a sibling's token.
- Per-follower tokens close the shared-secret exposure: one compromised
  follower is revoked alone, without re-keying the cluster. The engine
  re-reads the accept list on every pull and the follower re-reads its own
  token on every pull, so issuing, rotating and revoking take effect
  without a restart:

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

  A pull with a revoked token is rejected with `401`; other followers keep
  pulling. The matched label is written to the owner log, so the audit
  trail names the follower behind every snapshot served.
- **Vault source (optional secrets-service integration).** The file mode
  above is the default and needs nothing else. Deployments that run a
  secrets service can select it instead:
  `APPMESH_AUTH_REPLICATION_TOKEN_SOURCE=vault` plus
  `APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR` and
  `APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE` on every node (the
  accept-list file behind `APPMESH_AUTH_REPLICATION_TOKEN_FILE` is not part
  of the vault-only configuration); the
  accepted tokens then live in Vault KV v2 under `secret/appmesh/replication`:

  - The owner lists the KV entries and verifies against them on every pull
    request; a follower reads its own entry (named by
    `APPMESH_AUTH_REPLICATION_LABEL`) on every pull. Issuing, rotating and
    revoking are KV operations through the same tooling, take effect on
    the next pull, and land in the Vault audit log. An entry whose data was
    deleted (a revoked follower) is skipped by the list; the other
    followers keep pulling.
  - Each follower holds one scoped Vault machine identity — an AppRole
    (role_id plus a secret_id that stays reusable for repeated logins
    until the role is destroyed; see the note below) whose policy reads
    its own KV entry and issues its TLS leaf certificates from the cluster
    PKI — created by the owner bootstrap and delivered once through the
    replication volume. This is the single bootstrap credential; the
    replication bearers themselves are never materialized. The policy is
    rewritten on every bootstrap, so a follower provisioned before the PKI
    source gains its issue path on the next bootstrap.

    The secret_id is deliberately NOT one-time: the node logs in with the
    same pair on every pull and on every restart, so `secret_id_ttl` or
    `secret_id_num_uses` would strand the follower mid-operation unless an
    operator re-delivers credentials. Deployments that need bounded
    secret_ids must pair them with a re-delivery path; the default trades
    that strictness for unattended restarts.
  - Revocation under this source is persistent, not a soft KV delete:
    `replication-token-revoke <label>` writes a tombstone entry
    (`<label>.revoked`) before deleting the accepted token, then destroys
    the follower's AppRole and its policy. A restarted owner bootstrap
    checks the tombstone first and never re-issues a revoked follower; a
    follower still holding the old credential cannot log in (the role is
    gone). Re-enabling is explicit: `replication-token-restore <label>`
    deletes the tombstone and re-runs the issuance chain (fresh token,
    AppRole, credential file). `replication-token-list` marks tombstoned
    entries as `(revoked)`.
  - A Vault outage fails closed: pulls answer `503` and retry on the next
    cycle. Nothing opens without the source.
  - The packaged compose cluster ships this as an opt-in layer:
    `docker compose -f docker-compose.yaml -f docker-compose.vault.yaml
    up -d` runs a real Vault server (file storage, an init sidecar that
    unseals after restarts, KV v2, AppRole and the audit device enabled)
    and switches the token source; the base cluster alone stays
    file-based with no Vault dependency. Credential topology in the layer:
    the engine-owner token lives in its own volume mounted only by the
    master and the init sidecar, and each follower projects exactly its
    own AppRole credential out of the replication volume (a read-only
    subpath mount) — a follower can read neither the owner credential nor
    any sibling's credential. The Vault listener is plaintext on the
    trusted compose bridge network (a demo posture: the unseal key, root
    token and node credentials cross that network in the clear);
    production enables listener TLS and points every client at it with
    `APPMESH_VAULT_CACERT`, plus auto-unseal, periodic tokens, wrapped
    secret_id delivery, and an HSM-backed seal.
- **Operating without Vault (offline recovery).** The Vault source is a
  hard dependency of the owner's auth bootstrap: `appmesh-auth.sh service`
  dies when Vault is unreachable, and the container restart policy retries
  it forever — that is the current recovery loop, and it is deliberate
  (fail closed, never serve replication decisions from a stale or absent
  source). Operator procedures:

  1. Restore Vault itself. The compose layer keeps Vault state in the
     `appmesh_vault_data` volume and the init sidecar re-unseals
     automatically after a restart, so recovery is usually "bring the
     container back"; the owner then converges on its next bootstrap
     attempt with no manual step.
  2. Fall back to the file source when Vault is gone for good: unset
     `APPMESH_AUTH_REPLICATION_TOKEN_SOURCE=vault` (and the
     `APPMESH_*_VAULT_*` variables) on every node, restart, and let the
     owner bootstrap provision the file accept list and per-follower
     `<label>.token` files into `APPMESH_AUTH_REPLICATION_TOKEN_FILE`'s
     directory. The follower credentials change in the switch, so each
     follower must remount its projected token (compose: recreate the
     follower containers) before its next pull. Issued TLS material stays
     valid — leaves keep chaining to the CA already on disk; only new
     issuance needs Vault again.

- A follower with `APPMESH_AUTH_REPLICATION_FROM` (the owner's engine
  listener, `https://appmesh_master:6063` in compose, verified with the
  owner CA through `APPMESH_AUTH_REPLICATION_CA`) plus the token file pulls
  the full policy snapshot every `APPMESH_AUTH_REPLICATION_INTERVAL`
  seconds (default 30), and also right away when a login presents a
  principal the follower has never seen.
- The follower validates the snapshot before committing anything, and the
  owner snapshot always wins — including over a locally auto-provisioned
  role-less record. A replica never touches its node-local
  `authorization.yaml`: the synced policy is cached under its own name,
  `work/config/replica-policy.yaml`, so a restart authorizes immediately
  and the cache can never be mistaken for a hand-edited policy file.
  While replication is configured, the principal and role APIs on the
  follower reject writes with a pointer to the owner.
- The snapshot endpoint `GET /appmesh/auth/replication/policy` answers only
  the replication token (compared in constant time). Without the token
  file configured, the route behaves as if it did not exist.

This follows the single-writer replica model used by configuration
distribution systems (for example OPA bundles or kubelet configuration
pulls): authorization decisions stay local on every node, only the policy
source is centralized.

### Manual distribution (fallback)

Without replication, apply the rule by hand:

- Mutate authorization data on one node. The owner is the natural
  administrative entry point.
- Distribute the change by copying the owner's runtime
  `work/config/authorization.yaml` to the followers. The daemon no longer
  exits when that file is unreadable: it falls back to the packaged policy,
  logs the reason, and keeps serving. Copy the file as the runtime user
  (the daemon runs as `appmesh` in containers and cannot read a
  `root:root 0600` file):

  ```shell
  docker exec -i -u appmesh appmesh_slave1 sh -c \
      'mkdir -p /opt/appmesh/work/config && cat > /opt/appmesh/work/config/authorization.yaml' \
      < authorization.yaml
  ```

  Copy the file before the follower first serves an authenticated request.
  The first resolve of an unknown principal auto-provisions a role-less
  record and saves it. That in-memory record then shadows a later copy
  until the follower restarts or an administrator re-applies the binding
  through the principal API. A copy that lands first needs no
  restart: the follower adopts the entry from disk when it first resolves
  the principal, and a later save keeps the entry. Keep the file mode at
  0600. Keep the runtime user as owner.
- A follower without a principal entry authenticates a user. It grants
  nothing beyond the configured provisioning policy
  (`explicit-or-minimal` by default).

## docker-compose cluster

`script/docker/docker-compose.yaml` runs one owner, two followers, one LLM
node (`laoshanxi/appmesh:llm`, follower role, llm-agent preinstalled), and one
MCP server, with the bundled authentication service.

Listeners of `appmesh_master`. Host ports use the daemon defaults:

| Port (container → host) | Service | Used by |
| --- | --- | --- |
| 6060 → 6060 | Go agent REST front | REST clients and SDKs; it applies its own `X-Target-Host` forwarding |
| 6062 → 6062 | engine TCP API | SDK TCP transport: event subscriptions and task workers |
| 6063 → 6063 | engine WSS/HTTPS listener | the CLI (`appm` speaks WSS) and SDK WSS clients, including event subscriptions |
| 6065 → 127.0.0.1:6065 | Dex authentication listener | followers in-network; host loopback only, for password and device flows |
| 443 → 443 | web UI | browsers; the UI shares the master network namespace |

The engine listeners 6062 and 6063 are TLS and bearer-authenticated, the
same posture as the REST front. Host clients trust the master CA once
(`docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem`). Only
the first sign-in runs inside the container (see below). The `appmesh_mcp`
service publishes its own Streamable HTTP endpoint at `127.0.0.1:6070` for
host AI clients.

Environment variables:

| Variable | Master | Follower |
| --- | --- | --- |
| `APPMESH_AUTH_ROLE` | `owner` — runs Dex and owns the SQLite identity state | `follower` — no local Dex |
| `APPMESH_AUTH_ISSUER` | `http://appmesh_master:6065/auth` — one identical string on every node and client | same |
| `APPMESH_AUTH_ACCESS_URL` | unset — discovery defaults to the issuer | the issuer string; the packaged default points at loopback and is wrong on a follower |
| `APPMESH_AUTH_BROWSER_ENTRY` | `https://127.0.0.1/auth` — the published UI that fronts the issuer path | the owner value; a follower cannot derive the entry itself |
| `APPMESH_AUTH_LISTEN` | `0.0.0.0:6065` — reachable on the compose network only, never publish it publicly | unset — a follower starts no listener |
| `APPMESH_REST_PrometheusExporterListenPort` | `6061` | `6061` |

A container healthcheck calls `appmesh-auth.sh service-health`. Followers gate
on `depends_on: appmesh_master: service_healthy`.

Clients reach the issuer in-network at `http://appmesh_master:6065/auth`. The
REST port 6060 serves host REST clients and SDKs through the Go agent. For
password and device flows only, the Dex port is bound to host loopback.

### MCP service

The `appmesh_mcp` service runs the MCP server from the published
`laoshanxi/appmesh:mcp` image: an OAuth resource server that validates caller
tokens against the master's Dex and forwards the same token to the engine,
which enforces RBAC. The compose file needs no source checkout. The master's
TLS material lives in the `appmesh_tls` named volume; the MCP service and the
followers mount exactly its `ca.pem` (a read-only subpath mount) to verify
the engine — the master's private keys never cross a service boundary.
Followers serve TLS under their own identities (self-signed, or Vault-issued
under the optional layer); only verification trust is shared.

The OAuth metadata advertises the in-network issuer, which a host client
cannot resolve. A host client therefore passes a token from the password flow
instead of running the browser flow:

```shell
curl -s -u "appmesh-mcp-user:" -X POST http://127.0.0.1:6065/auth/token \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@appmesh.local" \
    --data-urlencode "password=<password>" \
    --data-urlencode "scope=openid audience:server:client_id:appmesh-api"
```

Point the MCP client at `http://127.0.0.1:6070/mcp` with the returned access
token as the bearer. The endpoint is plaintext on host loopback only, the same
posture as the Dex port.

### First sign-in in the compose cluster

The compose network runs the issuer over plain HTTP. The enrollment
accepts a loopback client only. Do the first sign-in inside the master
container. Use the loopback WSS listener and the packaged administrator
password:

```shell
docker exec appmesh_master sh -c 'printf "%s\n" "$(grep "^password=" /opt/appmesh/work/auth/secrets/initial-admin-credentials | cut -d= -f2-)" | /opt/appmesh/bin/appm -H wss://127.0.0.1:6063 logon --username admin@appmesh.local --password-stdin --auth-allow-http'
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
  appm -H wss://127.0.0.1:6063 --ca-cert ./master-ca.pem logon \
      --auth-access-url http://127.0.0.1:6065/auth --auth-allow-http
  appm view
  ```

  The CLI remembers the CA with the endpoint at logon, pinned to an absolute
  path, so later commands need neither `-H` nor `--ca-cert`.
- Then copy the owner's `work/config/authorization.yaml` to every
  follower before the follower first serves an authenticated request. A
  copy that lands first needs no restart: a follower adopts an entry from
  disk when it first resolves that principal. A follower that already
  served a request needs a restart after the copy. See "Authorization
  data consistency" above. A fresh follower has no `work/config`
  directory. Create the directory before the first copy.

### Cluster TLS trust

See [TLS and certificates](../TLS.md) for the key reference and the client
matrix. Every node generates its own CA at first start. An SDK on one node
verifies a peer certificate against the local CA by default. That CA did
not sign the peer certificate. The check fails with `BadSignature`. Use
one of these patterns.

Pattern 1. Trust the target CA on the client only:

1. Copy the target CA out: `docker cp appmesh_master:/opt/appmesh/ssl/ca.pem ./master-ca.pem`.
2. Name it on the CLI: `appm -H wss://appmesh_master:6063 --ca-cert ./master-ca.pem logon --auth-allow-http`.
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

Pattern 3. Central issuance (Vault PKI, one trust domain for the cluster); the
setting reference is [TLS and certificates](../TLS.md#vault-pki-source):

1. Select the source with `APPMESH_SSL_SOURCE=vault` plus
   `APPMESH_SSL_VAULT_ADDR` and `APPMESH_SSL_VAULT_TOKEN_FILE` (both
   default to their `APPMESH_AUTH_REPLICATION_TOKEN_VAULT_*` counterparts,
   so the vault compose layer needs no extra address configuration). A
   deployment mixing this source with file-sourced replication tokens, or
   a physical cluster without the compose init sidecar, must deliver the
   token file itself — one line for a service token with the issuing
   policy, two lines for an AppRole pair.
2. The Vault PKI engine holds one cluster CA and a single issuing role
   (`appmesh-node` by name, `APPMESH_SSL_VAULT_PKI_ROLE` to change it).
   The role issues both server and client leaves with the same name
   coverage as the self-signed generator — hostname, FQDN, local
   addresses, and `APPMESH_SSL_EXTRA_SAN` peers — but is domain-scoped,
   never `allow_any_name`: issuance is limited to the names in
   `APPMESH_PKI_ALLOWED_DOMAINS` (comma-separated; the compose default
   covers the cluster's hyphenated node names plus `localhost`), with
   bare-domain matches only (`allow_bare_domains=true`,
   `allow_subdomains=false`). A compromised node therefore cannot mint a
   cluster-CA certificate for an arbitrary DNS name — a public domain or
   another node's alias. A node whose name is not in the list fails its
   issuance loudly; the init sidecar prints the effective domain list at
   startup.
3. Every node's `appmesh-auth.sh bootstrap` (the docker entrypoint runs it
   before the TLS check) requests its own five files: `ca.pem` plus the
   server and client pairs. There is no `ca-key.pem` by design: the CA
   private key never leaves Vault. The node verifies its owner through its
   own copy of the same CA (`APPMESH_AUTH_REPLICATION_CA` may point at
   `/opt/appmesh/ssl/ca.pem`), and any node verifies any peer.
4. Bootstrap is idempotent by trust, not by file presence: existing
   material that does not chain to the current Vault CA is re-issued. An
   upgrade from the self-signed volume therefore converges on the next
   start instead of splitting the trust domain.
5. Renew on demand with `appmesh-auth.sh tls-renew`, then restart the node
   (the engine loads certificates once at start). A physical host can run
   the action from a systemd timer or cron; a shorter role TTL pairs well
   with that.

Two Vault behaviors shape the naming. Vault drops underscore DNS names
from certificates outright — an early validation no role knob disables
(hashicorp/vault#31925) — so the compose layer dials a hyphenated network
alias (`appmesh-master`) instead of the underscore service name and adds
it to the owner's `APPMESH_SSL_EXTRA_SAN`; the issuer string follows the
same alias so every node and client carries one canonical value. The
issuing role enforces hostnames again (`enforce_hostnames` at its default),
so the bootstrap maps an underscore hostname onto its hyphenated form for
the certificate's common_name. Physical clusters with RFC-legal FQDNs are
unaffected. And the generated root must carry a subject
(`common_name="AppMesh Root CA"`): an empty issuer name fails strict chain
verification.

The node credentials are the same Vault machine identities the
replication tokens use: the owner issues with its service token, a
follower with its AppRole (policy: read its own KV entry, issue TLS
leaves). The owner's service token is minted with a 10-year TTL matching
the CA root's horizon — nothing renews it — so the compose layer sets the
cluster `max_lease_ttl` to the same value; without it the system default
would clamp the token to 32 days and replication would silently die a
month in. A Vault outage fails closed — bootstrap dies and the restart
policy retries (see "Operating without Vault" above). Production
hardening: replace the generated root with an intermediate CA signed by
the organization root, shorten the role TTL under a renewal timer, and
keep auto-unseal on the server.

Do not copy only `ca.pem` onto a follower. The follower then trusts the
shared CA, but it still serves its old self-signed certificate. Clients
that verify against the shared CA reject it. (Pattern 3 is the exception:
a follower re-issues its own leaves from the same CA.)

A macOS client rejects leaf certificates with a validity above 825 days.
The packaged script sets 825 days for leaf certificates and 3650 days for
the CA; the Vault role mirrors both (825-day leaves, 10-year root).

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
  on the port. WSS clients, TCP clients, and explicit `:6062` targets
  work against the Engine gateway. This limitation is documented and is
  not changed here.
- Browser flows (authorization code with PKCE) require browser access to
  the issuer origin. Off-network clients are limited to password and
  device flows through `--auth-access-url` rewriting.
- Owner failover stays the manual fence-and-promote sequence in
  `Security.md`.
