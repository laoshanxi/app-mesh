# Security

App Mesh is an OAuth 2.0 protected resource. Dex is the only trusted identity
issuer. Linux and macOS main packages include the same bundled Dex stack with
its simple local-password bootstrap profile; Windows packages trust an
externally operated Dex only.

## Trust boundaries

| Component | Responsibility | Not responsible for |
|---|---|---|
| Dex | login, built-in bootstrap credential or external connectors, OAuth/OIDC grants, signed access tokens | App Mesh permissions or process execution |
| App Mesh Engine | validate Dex access tokens, resolve Principal, enforce authorization and ownership | passwords, MFA, users, token issuance, upstream IdP APIs |
| Agent | expose the configured Dex issuer path and transparently forward caller bearers to Engine | OAuth login/code exchange, token storage/refresh, or upstream IdP proxying |
| MCP | publish protected-resource metadata and transparently forward caller bearers to Engine | OAuth login/code exchange, token storage/refresh, token issuance, or independent authorization |
| Python SDK | OAuth client flows and bearer attachment | local password login or token signing |

Keycloak, Entra ID, Okta, SAML bridges, and other identity systems may be Dex
connectors. Engines, agents, SDKs, and MCP never trust or expose those systems
directly.

## Canonical issuer and access route

Every process distinguishes these values:

- `issuer`: the canonical Dex URL embedded in the token `iss` claim. It is a
  security identity and must be identical on all nodes and clients.
- `dex_access_url`: the network route that one process uses to reach the same
  Dex instance. It may be loopback, an App Mesh auth-owner address, a service
  name, or an internal VIP.

For example, a node may validate tokens whose issuer is
`https://appmesh.example.com/dex` while fetching discovery and JWKS from
`http://10.20.0.5:6062/dex`. Discovery must still publish the canonical issuer;
endpoint rewriting is accepted only inside that issuer path.

Engine and Agent read `config/oidc.yaml`. The explicit environment overrides
are:

```text
APPMESH_DEX_ISSUER
APPMESH_DEX_ACCESS_URL
APPMESH_DEX_TLS_VERIFY
APPMESH_DEX_CA_PATH
```

TLS verification is enabled by default for HTTPS Dex routes. Disabling it must be
an explicit deployment choice.

The Python SDK specifies its routes independently:

```python
from appmesh import AppMeshClient, DexOAuthClient

engine = AppMeshClient(base_url="https://engine-node:6060")
oauth = DexOAuthClient.from_appmesh(
    engine,
    dex_access_url="https://dex-network-route/dex",
    verify="/path/to/dex-ca.pem",
)
```

The Engine host and Dex access host are deliberately not inferred from each
other, including for a local Engine.

## Token validation

The Engine accepts only an RFC 6750 `Authorization: Bearer` value. It:

1. reads OIDC discovery from `dex_access_url`;
2. requires discovery `issuer` to exactly match `issuer`;
3. accepts only configured asymmetric algorithms (RS256 by default);
4. selects a Dex JWKS key by `kid`;
5. verifies signature, issuer, expiry/not-before, and audience;
6. derives a stable Principal ID from SHA-256(`issuer NUL subject`);
7. resolves App Mesh authorization by that immutable Principal ID.

Every accepted token requires the `appmesh-api` resource audience; there is no
alternate client-ID audience path for service tokens. The bundled
`appmesh-automation` confidential client requests that same audience through the
`audience:server:client_id:appmesh-api` scope and its client-credentials token
passes the identical signature, issuer, and audience checks. Mutable names,
email addresses, LDAP groups, and token role claims never grant Engine
permissions.

Discovery and keys are cached with bounded refresh. Unknown key IDs share a
global refresh interval and a bounded negative cache, so random key IDs cannot
amplify requests to Dex. If Dex is temporarily unreachable, a previously cached
matching key may continue validating an unexpired token; the Engine never falls
back to local signing or another issuer.

## OAuth flows

- Interactive/browser clients: Authorization Code with PKCE S256.
- Headless native clients: Device Authorization Grant where supported.
- Interactive delegation to Agent, MCP, and Workflow: relay the caller's bearer;
  these components do not mint or exchange it.
- Autonomous workloads: the bundled `appmesh-automation` confidential client
  uses the Client Credentials grant with the App Mesh resource audience; the
  launcher generates and persists its secret, and its Principal is provisioned
  explicitly like any other binding — no Engine role is ever inferred from the
  client id. Machine tokens carry no refresh token. See
  [Deployment Guide](Install.md) for the token exchange.
- Refresh and revocation: clients communicate directly with Dex.

Engine performs the authoritative token validation and authorization, so any
Agent-local privileged operation must first obtain an Engine decision.

The Engine has no login, refresh, logout, password, MFA, token-issuance, or
token-introspection proxy endpoints. The public discovery helpers are:

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| `GET /appmesh/auth/config` | public issuer, audience, scopes, client, and flow hints |
| `GET /appmesh/principal/self` | verified Principal and effective permissions |
| `GET /appmesh/principal/self/permissions` | effective permission IDs |

Built-in mode also has a deliberately non-public, one-time
`POST /appmesh/auth/enroll-first-admin` authorization operation. It accepts an
already verified Dex user Principal; it is not a login or token endpoint. The
operation requires both a direct loopback socket peer and the current mode-0600
runtime enrollment proof. Agent-to-Engine TCP requests must additionally carry
the private Agent envelope before the Engine trusts the Agent-captured socket
peer. `Forwarded` and `X-Forwarded-*` headers are never used for this decision.
The enrollment API is compiled into every non-Windows build (`_WIN32` gating in
the authorization store); Windows never opens it — its operator provisions the
first `authorization.yaml` Principal binding manually.

## Built-in local credential

The built-in v1 profile enables Dex's password database and seeds one static
bootstrap identity. Its random plaintext and bcrypt hash begin in a private
mode-0600 credential file; only the hash is rendered into Dex's mode-0600
runtime YAML. The launcher can explicitly rotate the random credential or
remove the recoverable plaintext after enrollment without disabling the hash.
It never logs the password or passes it in argv or an environment variable.

This is deliberately a small installation bootstrap, not an Engine user store.
Engine, CLI, SDKs, Agent, and MCP expose no password or local-user API. Use an
external Dex deployment and appropriate connectors when multi-user lifecycle,
MFA, self-service reset, or directory policy is required.

## Authorization and execution mapping

`authorization.yaml` stores no credentials. It contains:

- immutable OIDC Principal bindings;
- active/disabled/tombstoned status;
- App Mesh roles and permission sets;
- optional operating-system `execution_user` mapping;
- the first-administrator role and durable single-use enrollment marker.

Principal APIs manage only this authorization overlay:

| Endpoint | Purpose |
|---|---|
| `GET /appmesh/principals` | list overlays |
| `POST /appmesh/principal/{principal_id}` | create/update a binding or policy |
| `DELETE /appmesh/principal/{principal_id}` | tombstone an unowned overlay, never a directory user |
| `GET /appmesh/roles` | list App Mesh roles |
| `POST /appmesh/role/{role}` | update a permission set |
| `DELETE /appmesh/role/{role}` | delete an unbound non-bootstrap role |

Applications are owned by `owner_principal_id`, not a username. Packaged System
Apps are owned by `system:appmesh`; REST callers cannot create System Apps.
Process user selection comes from an explicit application `execution_user`,
then the Principal mapping, then `DefaultExecUser`/daemon identity according to
the platform policy.

Principal deletion is intentionally not a record erase. Engine refuses deletion
while any loaded application is owned by that Principal, then persists a
role-free tombstone with the immutable issuer/subject binding. This prevents
automatic provisioning from recreating the identity as a new owner and leaves
the durable first-administrator enrollment marker closed. Roles likewise cannot
be deleted while referenced by either a Principal or an explicitly configured
service-principal mapping.

The Engine never infers administrator rights from a username, display name,
email address, group, subject literal, or connector claim: in built-in mode a
local operator explicitly enrolls the first verified OIDC Principal. The
assignment and single-use marker are written atomically; disabling or deleting
that Principal does not reopen enrollment.

## Authentication mode and bundled startup

Linux main packages always contain the pinned, checksummed Dex runtime and its
stdin-only bcrypt helper.
Setup records an explicit `APPMESH_AUTH_MODE` in the root-only service environment
file. `builtin` is the out-of-the-box default and enables the runtime as protected
System Apps:

```text
post-install bootstrap (setup.sh / docker entrypoint) -> auth-dex -> ingress/normal apps
```

`external` requires `APPMESH_DEX_ISSUER`, accepts only the public access URL and
TLS/CA routing settings, and disables both local auth System Apps. It never
accepts a password or OAuth client secret. The packaged runtime remains
available so an operator can switch modes deliberately; setup reapplies the
persisted choice after upgrades. See [Deployment Guide](Install.md) for the
non-interactive environment and setup options.

Secrets are generated at runtime with restrictive permissions under
`work/auth/secrets`. The launcher passes the initial password only on the hash
helper's stdin and renders only its bcrypt hash into private runtime YAML; it
never logs either value. The workflow child receives no OAuth client credential;
automatic and recovered runs use short-lived, Engine-local capabilities. Dex
data lives under `work/auth`, so that directory must be on persistent storage.

Container images discard all mutable state created by the package post-install
step before the final layer. The non-root entrypoint initializes only missing
state in `work`, including per-instance TLS material under `work/ssl`; it never
ships a reusable master key, initial password, enrollment proof, issuer database,
or TLS private key. `APPMESH_AUTH_MODE=external` is enforced by both the
entrypoint and the launcher so a stale packaged App status cannot start Dex.

Persisted application `sec_env` values use AES-256-GCM and a node-local 256-bit
SecretProtector master key. Setup atomically creates
`work/auth/secrets/secret-master-key`, records only its path in the service
environment, and preserves the file on upgrade. The daemon verifies a regular,
owner-only file and fails startup if the configured key is missing, unsafe, or
cannot authenticate stored values. Back up this key with the application state;
losing it is intentionally not recoverable through a weaker fallback.

Application files from the username/password security model require an explicit
offline migration: a legacy `owner` username cannot be inferred as an immutable
`(issuer, subject)` binding, and legacy per-user `sec_env` ciphertext cannot be
decrypted without the former credential material. Engine reports every rejected
file and aborts application recovery instead of silently omitting it. Provision
the target Principal, replace `owner` with its `owner_principal_id`, and
re-register secured values through an authenticated application update while the
old deployment can still decrypt them.

Engine initializes the authorization store and OIDC verifier before creating
any TCP or WebSocket listener. A configuration or authorization-state failure
therefore aborts startup without exposing an API listener. Dex itself may come
online afterward because it is a managed dependency; until discovery/JWKS is
reachable, protected requests fail closed as authentication unavailable.

User WebSocket connections authenticate their Dex bearer during the HTTP
upgrade. Engine pins the resulting immutable Principal ID to the session and
checks current RBAC for every framed operation; a frame cannot switch identity.
Token refresh takes effect on the next connection. The only bearer-less upgrade
is a direct loopback managed-worker session, which is restricted to GET/PUT task
RPC and must prove the current process with `X-AppMesh-Process-Key`. Agent strips
that private header and the retired `process_key` query parameter.

The HTTPS streaming endpoints `/appmesh/file/download/ws` and
`/appmesh/file/upload/ws` independently authenticate the bearer and enforce
`file-download` or `file-upload` immediately before filesystem access. A prior
control request is not treated as an authorization grant.

While first-administrator enrollment is open, the daemon keeps
`work/auth/secrets/first-admin-enrollment-token`: a fresh 256-bit CSPRNG value
per daemon start, readable only by the daemon owner (and root), removed as soon
as enrollment commits. External mode, follower nodes, and non-Linux
installations remove/disable this proof and the API. An invalid
``APPMESH_AUTH_MODE`` or ``AuthStack.role`` aborts startup instead of opening
enrollment under an ambiguous deployment role.

Windows does not install the local auth System Apps or launcher, and the setup
script does not auto-register the bundled workflow App on that platform; macOS
installs and bootstraps the same bundled auth stack as Linux.

## Cluster mode

The bundled SQLite configuration is single-active:

- one `standalone` or `owner` node runs Dex;
- `follower` nodes do not receive local credential state and do not start a
  second writer;
- every Engine trusts the same canonical issuer and sets its own
  `dex_access_url` to the owner/private route;
- authorization state must be distributed by the cluster configuration
  mechanism or an operator-controlled configuration rollout.

Failover is controlled, not automatic active-active. Stop or fence the old owner,
restore/mount the persisted `work/auth` state on the promoted node, set its
`AuthStack.role` to `owner`, update node access routes, and then start it.
Never run two SQLite Dex owners against copied or shared writable state.

For deployments that require active-active identity and issuer storage, replace
the bundled persistence design with supported external replicated storage as a
separate architecture decision; the out-of-box mode does not pretend SQLite is a
distributed database.

## Removed interfaces

The following are intentionally gone from the Engine:

- local username/password login and password hashing;
- daemon-issued JWTs, signing salts, token renewal, and blacklist;
- cookies and `X-Set-Cookie` authentication;
- local user CRUD, groups, lock/unlock, and password change;
- Engine TOTP setup/validation;
- Keycloak-specific code, admin APIs, and configuration;
- Consul-backed authentication.

Only Dex access tokens cross the Engine authentication boundary.
