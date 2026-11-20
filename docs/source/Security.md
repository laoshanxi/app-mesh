# Security

App Mesh is an OAuth 2.0 protected resource. It trusts one OpenID Connect issuer. It keeps authentication separate from App Mesh authorization.

This document defines security behavior. Use [CLI](CLI.md) for sign-in commands. Use [Deployment](Install.md) for installation procedures. Use [Authentication](Authentication.md) for password and token operations in the built-in mode. Use [Cluster Authentication](cluster/ClusterAuthDesign.md) for the multi-node owner/follower design. Use [ADR 0009](https://github.com/laoshanxi/app-mesh/blob/main/docs/adr/0009-authentication-service.md) for the authentication-service implementation decision.

## Trust boundaries

| Component | Responsibility | Excluded responsibility |
| --- | --- | --- |
| Authentication service | Authenticate identities. Issue signed access tokens. Operate OAuth and OpenID Connect flows. | App Mesh permissions and process execution. |
| Engine | Validate access tokens. Resolve principals. Enforce roles, ownership, and execution policy. | Passwords, MFA, users, and token issuance. |
| Agent | Route authentication paths. Forward the caller bearer without a change. | Token exchange, token storage, and token issuance. |
| MCP server | Validate a bearer at the MCP boundary. Forward the same bearer to the Engine. | App Mesh authorization decisions and token issuance. |
| SDK | Attach a caller-owned bearer. Python and Rust can also manage an OAuth token lifecycle. | Engine-owned login or token signing. |

An external identity provider can connect to the authentication service. The Engine and SDK do not depend on that upstream provider.

## Issuer and access URL

The issuer and access URL have different purposes.

- The `issuer` is the identity in the token `iss` claim. All cluster nodes must use the same value.
- The `access_url` is the route that one process uses to reach the same authentication service.

The access URL can use a private route. This route must resolve to the same issuer. Discovery must publish the canonical issuer.

Use HTTPS for a remote access URL. Keep TLS verification enabled. Supply a CA file when the service uses a private CA.

## Token validation

The Engine accepts an RFC 6750 `Authorization: Bearer` value. The Engine performs these checks:

1. It reads OpenID Connect discovery from the configured access URL.
2. It compares the discovered issuer with the configured issuer.
3. It accepts only configured asymmetric signature algorithms. The default is RS256.
4. It selects a signing key by `kid`.
5. It verifies the signature, issuer, audience, expiry, and not-before values.
6. It derives a principal ID from the immutable issuer and subject.
7. It loads the current App Mesh authorization data for that principal.

Every token must contain the `appmesh-api` audience. A display name, email address, group, or token role does not grant an App Mesh permission.

Refresh tokens stay between the client and the authentication service. The Engine never sees one. The built-in service issues refresh tokens only for flows that request `offline_access`, and only while `refresh_token` is enabled in `oidc.yaml` (`APPMESH_AUTH_REFRESH_TOKEN`). `refresh_token_max_lifetime` (`APPMESH_AUTH_REFRESH_TOKEN_MAX_LIFETIME`, default 168h) caps the whole refresh chain, not one rotation. `/appmesh/auth/config` advertises `"refresh_token": false` when the feature is disabled; an older daemon omits the key, which means enabled.

The built-in service keeps one refresh-token chain for each account, connector, and client ID. A new sign-in with the same account and the same client ID replaces the earlier chain. The earlier session then fails its next refresh with `invalid_grant`; the CLI removes that session and asks for `appm logon` again. Each surface uses its own client ID so that one sign-in does not end another: the CLI uses `appmesh-cli`, the web UI uses `appmesh-web` for both the browser flow and the password form, and MCP clients use `appmesh-mcp-user`. Two CLI sign-ins with the same account on two hosts do replace each other. A script must not request `offline_access` with the CLI client ID. Use the `appmesh-automation` client, or an SDK password provider, which re-authenticates without a refresh token.

The Engine caches discovery data and signing keys for a limited time. An unknown key ID can cause one controlled refresh. A bounded negative cache limits repeated refresh attempts. The Engine does not fall back to local token signing or a second issuer.

## Transport behavior

- REST validates the bearer on each protected request.
- TCP carries the bearer in each request envelope. The Engine validates it for each request.
- WSS validates the bearer during the WebSocket upgrade. The Engine pins the principal to that connection.

A direct WSS frame does not need to repeat the bearer. A forwarded WSS frame must contain the same bearer. The gateway rejects a frame that resolves to a different principal. The target validates the bearer again.

Reconnect after a token refresh. A WSS frame cannot change the pinned principal.

File upload and download endpoints validate the bearer before file access. They also enforce the required file permission.

The CLI remembers a remote endpoint with its transport settings, so later
commands need no `-H`, `--ca-cert`, or `--no-verify`. See
[TLS and certificates](TLS.md) for the listener configuration and the client
matrix.

## Deployment behind a TLS-terminating gateway

Enterprise networks usually centralize TLS at an edge layer: a load balancer,
API gateway, or service-mesh sidecar terminates TLS and forwards plaintext HTTP
to the services behind it. App Mesh supports this shape explicitly.

Set `REST.SSL.SSLEnabled: false` (default `true`). Every listener — the
REST/WebSocket port and the TCP frame port — then accepts plaintext, and the
certificate paths under `SSL` are ignored. The configuration is an explicit
operator choice: a missing certificate file never silently degrades a TLS
deployment to plaintext.

Requirements for this shape:

- The listeners must stay bound to a trusted network segment (a private
  interface, a container overlay network, or a pod network). The gateway owns
  the public surface and the certificate lifecycle.
- The gateway must pass the `Authorization` header, the WebSocket upgrade, and
  — once request signatures are enabled — the `X-Request-Key`, `X-Timestamp`,
  `X-Nonce` and `X-Signature` headers through unchanged. Session affinity is
  not required: every request carries its own bearer.
- The framed TCP port is a custom protocol, not HTTP. A typical HTTP gateway
  does not forward it; reach it directly on the trusted network (SDK clients
  construct it with `plain_transport=True`), or front it with a plain TCP
  proxy.
- Apply one transport mode across the cluster. A follower pulls authorization
  state from the owner over the same listener shape; a plaintext owner cannot
  serve TLS followers (and vice versa). Forwarding follows the same mode: a
  plaintext node forwards plaintext. SDK forward targets given as a bare host
  default to TLS — name the scheme explicitly (`http://host`) on a plaintext
  cluster.

Clients:

- To the gateway, clients keep using `https://` and `wss://` — nothing changes
  for them; TLS ends at the gateway.
- Direct connections to a plaintext daemon are opt-in per client: the CLI uses
  a `ws://` or `http://` `-H` endpoint (the transport mode is remembered with
  the endpoint at logon, like a CA), the Python SDK passes
  `plain_transport=True` to the TCP and WSS clients, the Rust SDK and CLI
  builder use `.plain_transport(true)`, and the Go SDK dials
  `TCPConnection.ConnectPlain` or a `ws://` URL. Every SDK keeps TLS as the
  default; the Java and JavaScript SDKs have no plaintext opt-in (their REST
  transports accept `http://` base URLs, their framed transports are
  TLS-only).

With transport protection moved upstream, enable the request signature layer
(`REST.RequestSignature: enforce`) so tampering on the trusted segment is still
detected: the HMAC signature covers the method, path, query, body hash,
timestamp, and nonce of every request (see "Request replay protection and
signatures").

## Principal and authorization model

The principal ID is stable for one issuer and subject. The Engine does not use a username as an ownership key.

`authorization.yaml` contains:

- principal status;
- role definitions;
- role bindings;
- optional operating-system execution mappings;
- the first-administrator role;
- the durable first-administrator enrollment state;
- API request-signing keys (key id, owner principal, creation time, secret). Secrets are encrypted at rest with the node's secret master key; older files with cleartext secrets still load and are re-saved encrypted.

It does not contain a password, refresh token, MFA seed, or directory group.

An application stores `owner_principal_id`. A response can also contain `owner_display_name`. The display name is for output only. It does not affect authorization.

The Engine refuses to delete a principal that owns an application. A deleted principal becomes a role-free tombstone. This rule prevents automatic provisioning from creating a new owner with the same identity.

## First administrator

The built-in installation creates one packaged administrator identity. This identity has no App Mesh role before enrollment.

The CLI can assign the first administrator role after a successful normal sign-in. The Engine accepts the assignment only when all conditions are true:

- the verified subject is the packaged administrator subject;
- the request uses a direct loopback connection;
- the node is the built-in standalone node or authentication owner;
- the durable enrollment state is open;
- the assignment has not succeeded before.

The Engine does not use the username, email address, display name, group, or token role for this decision. A forwarded request cannot complete enrollment. A direct remote request cannot complete enrollment.

The operation writes the role binding and closes the enrollment state in one atomic change. A later role removal does not reopen enrollment.

Enrollment guidance for operators:

- Run the enrollment from the daemon host, with the packaged administrator signed in, as the first action after installation.
- The enrollment window closes after the first success, after the installation of a pre-existing first-administrator binding, or when the node becomes an authentication replica.
- Keep the packaged administrator credential in the secrets file protected. The file is the bootstrap credential. Limit file access to the installation user.
- If the packaged credential is exposed, treat it as compromised: enroll the first administrator, then disable the password flow or replace the credential before the node serves remote clients.

## Built-in credentials

The built-in profile creates an administrator and a read-only viewer. Setup generates random passwords. It stores each initial password in a private credential file. It stores only the password hash in the authentication-service runtime configuration.

The launcher does not put a password in a command argument or environment variable. It does not write a password to a log.

Use an external authentication deployment when you need user lifecycle management, MFA, password reset, or directory policy.

## Administration interfaces

The `dexuser` administration UI listens on `127.0.0.1:6064` and has no authentication of its own. The loopback binding is the only access control. This is an accepted risk, and it matches the exposure model of the administrative gRPC API the UI drives:

- The gRPC listener (`127.0.0.1:5557`) is protected only by mutual TLS. A caller who can read `ssl/client.pem` and `ssl/client-key.pem` can invoke the gRPC administration API directly, without the UI.
- A local process that can reach the UI can reach the same administrative operations. The UI therefore grants no privilege beyond what local access to the node already provides.

Two rules follow from this model:

1. Never bind the UI to a non-loopback interface (`APPMESH_AUTH_ADMIN_LISTEN`) and never place it behind a reverse proxy. Doing so exposes unauthenticated user and client management to the network.
2. When no operator needs the UI, disable it with `APPMESH_AUTH_ADMIN_UI=off`. The `dexuser` App is a system App, so a disabled UI cannot be re-enabled through the application API. See [Authentication](Authentication.md#disabling-the-administration-ui).

## Secret protection

The package creates a 256-bit master key for application `secret_env` values. The Engine uses AES-256-GCM. The key file must be a regular owner-only file.

Back up the master key with application state. App Mesh cannot recover encrypted values without this key.

## Shared authentication service

A cluster uses one logical issuer. Each Engine validates tokens locally. Each Engine also uses the shared App Mesh authorization data.

A follower does not create built-in credentials. It does not run a second authentication-service writer. It trusts the same issuer as the owner.

Set up the owner and join followers with the `setup.sh --auth-role owner|follower` actions described in [Deployment](Install.md#cluster-authentication-service); the role also applies at package installation time through `APPMESH_AUTH_ROLE`. The packaged `identity` App stays enabled on a follower. It runs inert: it stays healthy, it starts no Dex process, and it writes no authentication state.

Authorization data is node-local. The principal and role APIs write the node that serves the request. A forwarded change therefore affects only the target node. Keep nodes consistent in one of two ways: apply the same changes on every node, or copy the owner's `work/config/authorization.yaml` to the followers. A copied file needs no restart: a follower adopts an entry from disk when it first resolves that principal, and a later save keeps the entry. A fresh follower has no `work/config` directory; create it before the first copy. A follower without a principal entry authenticates a user. It grants nothing beyond the configured provisioning policy.

The built-in database supports one active authentication owner. Use this failover sequence:

1. Stop or fence the old owner.
2. Restore or mount the persisted authentication state on the new owner.
3. Set the new node role to `owner`.
4. Update private access routes.
5. Start the new owner.
6. Verify discovery, signing keys, sign-in, and authorization.

Do not run two active owners against copied or shared writable database state. Use an external service with replicated storage when you need active-active availability.

## Direct and forwarded requests

A direct client gets authentication configuration from the selected Engine. It gets a token from the configured authentication service. The selected Engine validates that token.

A forwarded client sends discovery through the gateway to the target Engine. It then gets a token directly from the shared authentication service. The gateway forwards the bearer without a change. The target Engine validates the token and applies its authorization data.

Forwarded session reuse is safe only when each target advertises the same issuer, client ID, and audience. The CLI checks these values before it uses a stored session.

The gateway validates the bearer before it resolves or connects to the target. The target validates the same bearer again. The gateway does not forward a managed-process proof. It marks the request as forwarded so that the target can reject direct-only operations.

Anonymous forwarding is limited to these discovery requests:

- `GET /.well-known/oauth-protected-resource`;
- `GET /appmesh/auth/config`.

HTTP, TCP, and WSS can forward normal request methods. HTTP supports one response for each request. Forwarded subscriptions require TCP or WSS because events need a persistent connection.

## Internal proofs

Some local operations use a narrow internal proof. Examples include a workflow capability, a per-spawn pre-shared key with per-request HMAC for managed system processes (Agent and Workflow), a managed-process key for the task RPC, and optional mTLS.

An internal proof does not create a principal. It does not replace a user bearer. Each proof has a limited operation and transport scope.

## Request replay protection and signatures

Two independent hardening layers can be enabled per deployment. Both default to `off`. Both accept `off`, `audit`, or `enforce`:

- `REST.RequestReplayProtection` rejects a repeated request nonce.
- `REST.RequestSignature` requires a valid HMAC request signature.

`REST.RequestReplayWindowSeconds` (10 to 3600, default 300) bounds both layers. It defines how long a nonce is remembered and how far an `X-Timestamp` value may drift from the daemon clock (the signature and replay checks add a fixed 30-second grace on top of the window). Reload the daemon configuration (SIGHUP) to change a mode without a restart.

Replay protection works without client changes on TCP and WSS transports. Each framed request already carries a unique `uuid`, and the daemon uses it as the nonce. HTTP clients send the nonce in the `X-Nonce` header. In `enforce` mode an authenticated HTTP request without a nonce is rejected with `401`. A repeated nonce is rejected with `409`.

### API keys

A request signature is produced with a per-principal API key. Manage keys through the REST API:

| Endpoint | Purpose |
| --- | --- |
| `POST /appmesh/security/apikeys` | Issue a key for the caller. An administrator may pass `{"principal": "<id>"}` and issue for another principal. |
| `GET /appmesh/security/apikeys` | List the caller's keys. `?all=1` lists every key and needs the `principal-list` permission. |
| `DELETE /appmesh/security/apikey/<key_id>` | Revoke a key. The owner or the `principal-set` permission may revoke. |

The response of `POST /appmesh/security/apikeys` contains the secret exactly once. Store it at the client. The daemon stores the key in the authorization file with mode `0600` on POSIX and an owner-only ACL on Windows; the secret is encrypted at rest. Cluster replication copies API keys to follower nodes with the rest of the policy — the replication snapshot carries the secrets so followers can verify signatures, so keep the replication listener on TLS. A principal may hold at most 10 keys. A principal that is disabled or deleted stops its keys from verifying; deleting a principal removes its keys.

A key belongs to one principal for issuing and revocation, but the signature does not bind the key to the bearer on the wire: any valid key can sign a request that authenticates with any bearer. Enforce mode adds integrity, not a second authentication factor — it does not contain a stolen bearer token.

### Signature format

A signature is an integrity layer on top of bearer authentication. It does not replace the bearer token. Authorization is still decided by the bearer.

The client sends four headers on each request:

| Header | Content |
| --- | --- |
| `X-Request-Key` | The API key id, for example `ak-3f9c2a81b0d4`. |
| `X-Timestamp` | Unix time in seconds. |
| `X-Nonce` | A random value, unique per request. |
| `X-Signature` | Hex HMAC-SHA256 over the string to sign. |

Build the string to sign with this exact form:

```
METHOD + "\n" + path + "\n" + sortedQuery + "\n" + sha256hex(body) + "\n" + timestamp + "\n" + nonce
```

- `path` is the request path without the query. Use the path exactly as sent. Do not percent-decode it.
- `sortedQuery` joins the query parameters as `key=value` pairs with `&`. Sort the pairs by key, then by value. Use the decoded parameter values. An empty query is an empty string.
- `sha256hex(body)` is the lowercase hex SHA-256 of the request body. A request without a body hashes the empty string.
- The five file routes (`/appmesh/file/download`, `/appmesh/file/upload`, `/appmesh/file/delete`, and the two `/ws` data-channel variants) sign the empty string in place of the body hash, and the signed path is the file route without the trailing `/ws`. The `/ws` suffix selects the transfer channel; it is not part of the signed resource. This exemption is documented: the signature binds the method, path, query, timestamp, and nonce, but not the file content.

TCP and WSS clients carry the four headers in the request header map. The framed message `uuid` may serve as the nonce.

The daemon compares signatures in constant time. A request that fails verification is rejected with `401` in `enforce` mode and logged in `audit` mode.

### Scope and limits

- The nonce cache is node-local. Each node rejects a nonce it has already served. Forwarded write requests reach the owner node, so the effective protection covers the write path.
- Requests that carry no credential are exempt. Public routes stay reachable for browsers and probes.
- Internal workflow capabilities are exempt. They are loopback-only and time-bound.
- The signed surface is the canonical string only: method, path, query, body hash, timestamp, nonce. Request headers are not signed — `X-File-Path`, `X-File-Overwrite`, the file mode, user, and group headers, and `X-Target-Host` can be rewritten by a TLS-terminating proxy without breaking the signature. Signatures protect the request line and body, not header-based routing decisions.
- `sortedQuery` joins decoded `key=value` pairs with `&` and does not re-encode, so two distinct raw query strings can share one canonical form (`a=1%26b%3D2` and `a=1&b=2` both canonicalize to `a=1&b=2`). Query consumers in this API are switches and filters; treat the query layer as replay-safe but not tamper-proof against a rewriting proxy.
- A deployment that terminates TLS at a proxy should enable `RequestSignature` in `enforce` mode. The signature then survives the proxy hop.

## Removed interfaces

The Engine does not provide these interfaces:

- local username and password login;
- daemon-issued identity tokens;
- token renewal or a token blacklist;
- authentication cookies;
- local user and group management;
- password changes;
- Engine-managed TOTP;
- an upstream identity-provider proxy.

The public authentication endpoints are:

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/oauth-protected-resource` | Return resource metadata. |
| `GET /appmesh/auth/config` | Return public issuer, audience, client, scopes, and flow hints. |
| `GET /appmesh/principal/self` | Return the verified principal and effective authorization. |
| `GET /appmesh/principal/self/permissions` | Return effective permission IDs. |

The first-administrator endpoint is a restricted authorization operation. It is not a login endpoint.
