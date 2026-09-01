# Security

App Mesh is an OAuth 2.0 protected resource. It trusts one OpenID Connect issuer. It keeps authentication separate from App Mesh authorization.

This document defines security behavior. Use [CLI](CLI.md) for sign-in commands. Use [Deployment](Install.md) for installation procedures. Use [ADR 0009](../adr/0009-authentication-service.md) for the authentication-service implementation decision.

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

The Engine caches discovery data and signing keys for a limited time. An unknown key ID can cause one controlled refresh. A bounded negative cache limits repeated refresh attempts. The Engine does not fall back to local token signing or a second issuer.

## Transport behavior

- REST validates the bearer on each protected request.
- TCP carries the bearer in each request envelope. The Engine validates it for each request.
- WSS validates the bearer during the WebSocket upgrade. The Engine pins the principal to that connection.

A direct WSS frame does not need to repeat the bearer. A forwarded WSS frame must contain the same bearer. The gateway rejects a frame that resolves to a different principal. The target validates the bearer again.

Reconnect after a token refresh. A WSS frame cannot change the pinned principal.

File upload and download endpoints validate the bearer before file access. They also enforce the required file permission.

## Principal and authorization model

The principal ID is stable for one issuer and subject. The Engine does not use a username as an ownership key.

`authorization.yaml` contains:

- principal status;
- role definitions;
- role bindings;
- optional operating-system execution mappings;
- the first-administrator role;
- the durable first-administrator enrollment state.

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

## Built-in credentials

The built-in profile creates an administrator and a read-only viewer. Setup generates random passwords. It stores each initial password in a private credential file. It stores only the password hash in the authentication-service runtime configuration.

The launcher does not put a password in a command argument or environment variable. It does not write a password to a log.

Use an external authentication deployment when you need user lifecycle management, MFA, password reset, or directory policy.

## Secret protection

The package creates a 256-bit master key for application `sec_env` values. The Engine uses AES-256-GCM. The key file must be a regular owner-only file.

Back up the master key with application state. App Mesh cannot recover encrypted values without this key.

## Shared authentication service

A cluster uses one logical issuer. Each Engine validates tokens locally. Each Engine also uses the shared App Mesh authorization data.

A follower does not create built-in credentials. It does not run a second authentication-service writer. It trusts the same issuer as the owner.

Set the owner with `setup.sh --auth-mode builtin --auth-role owner`. Join a follower with `setup.sh --auth-mode builtin --auth-role follower --oidc-issuer <owner issuer>`. The role also applies at package installation time through `APPMESH_AUTH_ROLE`. The packaged `identity` App stays enabled on a follower. It runs inert: it stays healthy, it starts no Dex process, and it writes no authentication state.

Authorization data is node-local. The principal and role APIs write the node that serves the request. A forwarded change therefore affects only the target node. Keep nodes consistent in one of two ways: apply the same changes on every node, or copy the owner's `work/config/authorization.yaml` to the followers and restart their daemons. A follower without a principal entry authenticates a user. It grants nothing beyond the configured provisioning policy.

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

Some local operations use a narrow internal proof. Examples include a workflow capability, a managed-process key, Agent-to-daemon HMAC, and optional mTLS.

An internal proof does not create a principal. It does not replace a user bearer. Each proof has a limited operation and transport scope.

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
