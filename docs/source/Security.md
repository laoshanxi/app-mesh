# Security

App Mesh acts as enterprise middleware, implementing security at multiple levels to provide a secure platform.

## Security Concepts

### User

App Mesh has built-in user management. Each user can define a process execution OS user for application execution. Each user has:

* Password
* MFA key
* Roles

```bash
$ appm user
{
  "email": "admin@appmesh.com",
  "exec_user": "root",
  "group": "admin",
  "locked": false,
  "mfa_enabled": false,
  "name": "admin",
  "roles": [
    "manage",
    "shell",
    "usermgr",
    "view"
  ]
}
```

### RBAC

App Mesh implements role-based access control (RBAC). Users are assigned roles, each containing specific permissions. Every API request undergoes user password verification and permission checks.

### Multi-tenant Applications

Applications managed by App Mesh can define access permissions for other users and groups. You can:

* Register an application visible only to yourself.
* Register an application for your user group.

## Security Data Storage

### Local YAML File

App Mesh uses a local YAML file `security.yaml` to persist all user definitions. This file can only be read and written by the root user.

### Consul User/Role

App Mesh supports storing security content in Consul, enabling all App Mesh instances to share centralized user information.

### OAuth2

App Mesh supports Keycloak OIDC authentication. When enabled, App Mesh validates the
Keycloak-issued access token (signature, issuer, expiry, and client binding) on every
request. Authorization is driven entirely by Keycloak: the **client roles carried in the
token are used directly as App Mesh permissions** — there is no local role-to-permission
mapping in OAuth2 mode.

#### Setup

1. **Start Keycloak**

   ```bash
   docker run --restart=always -d -p 8080:8080 \
     -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
     --name keycloak quay.io/keycloak/keycloak:latest start-dev
   ```

2. **Configure the realm and client** (Keycloak admin console)

   * *Manage realms → Create realm*: create `appmesh-realm`.
   * *Authentication → Required Actions*: disable all required actions.
   * *Users → Add user*: create a user (e.g. `mesh`) with a permanent password.
   * *Clients → Create client*: create `appmesh-client`; enable **Client authentication**
     and **Direct access grants**.
   * *Users → Add user*: as above.

3. **Create permission roles on the client** (this is what grants access)

   App Mesh authorizes each request against a permission key. In OAuth2 mode every
   permission key must exist as a **client role on `appmesh-client`**, named *exactly* as
   the key below, and be assigned to the user (directly or via a composite role / group).
   A user without the matching client role is denied that operation.

   The full permission-key set (use these exact strings as client-role names):

   ```text
   app-view            app-output-view     app-view-all        host-resource-view
   app-reg             app-control         app-delete          app-subscribe
   app-run-async       app-run-sync        app-run-async-output app-run-task
   file-download       file-upload
   label-view          label-set           label-delete
   config-view         config-set
   passwd-change-self  passwd-change-user
   user-add            user-delete         user-lock           user-unlock
   user-list           user-totp-active    user-totp-disable   user-token-renew
   role-view           role-set            role-delete         permission-list
   ```

   Recommended: instead of assigning ~30 roles per user, create **composite client roles**
   that bundle a set, e.g.:

   * `appmesh-admin` → composite of all keys above.
   * `appmesh-operator` → `app-view`, `app-view-all`, `app-output-view`, `app-control`,
     `app-run-sync`, `app-run-async`, `app-run-async-output`, `app-run-task`,
     `host-resource-view`, `passwd-change-self`, `user-token-renew`.
   * `appmesh-viewer` → `app-view`, `app-view-all`, `app-output-view`, `host-resource-view`.

   Then *Users → Role Mappings → Assign client roles*: assign the composite role to the user.
   (Composite roles expand to their member roles in the token, so App Mesh sees the
   individual permission keys.)

4. **Enable OAuth2 in App Mesh**

   * Set `SecurityInterface: oauth2` in `config.yaml`.
   * Configure `oauth2.yaml` with `auth_server_url`, `realm`, and `client_id`.
   * Provide the client secret via the environment variable
     `APPMESH_Keycloak_client_secret` — **do not** commit it to `oauth2.yaml`. Leave the
     YAML value empty for a public client.
   * The local `security.yaml` role/permission definitions are **not used** for
     authorization in OAuth2 mode and can be ignored.

#### Token validation rules

* **Client binding (mandatory):** the token must target `client_id` via its `azp` or `aud`
  claim. Tokens issued for another client in the same realm are rejected.
* **Audience isolation:** appmesh audiences encode a target host (used for remote-run
  isolation). A Keycloak access token cannot carry that claim, so requests asking for a
  specific non-default audience are rejected under OAuth2.
* **Authorization:** the client roles found under this client's `resource_access` entry in
  the token are taken as the user's permission set and matched directly against the
  permission key the requested API requires. Roles granted on *other* clients in the realm
  are ignored.

#### Verifying the setup

After assigning roles, decode a freshly issued access token (e.g. paste it into a JWT
viewer) and confirm the permission keys appear under
`resource_access["appmesh-client"].roles`. If an API returns `403`/permission-denied,
the corresponding key is missing from that list — add the client role in Keycloak and
re-login to pick it up.

#### Token lifecycle

The login response includes a `refresh_token` in OAuth2 mode. Clients that proxy through
the daemon (rather than talking to Keycloak directly) use it as follows:

* **Renewal:** `POST /appmesh/token/renew` with the refresh token in the `X-Refresh-Token`
  header. The daemon exchanges it with Keycloak (`grant_type=refresh_token`) and returns a
  fresh access/refresh token pair.
* **Logoff:** `POST /appmesh/self/logoff` with the refresh token in `X-Refresh-Token`
  revokes the Keycloak session server-side (end-session endpoint) in addition to the local
  blacklist. Without the header, only the local session is revoked.

#### User profile resolution (admin API)

Some operations need a user *profile* object (not just authorization), e.g. resolving an
application owner, deciding the run-as OS user, and serving `GET /appmesh/user/self`. A
Keycloak identity is resolved through the Keycloak **admin API**, so users do **not** need to
be duplicated in the local `security.yaml`.

* **Resolution order:** a user also defined locally in `security.yaml` wins (this lets you keep
  a local `exec_user` override for that name); otherwise the profile is fetched from Keycloak
  and cached (~5 min).
* **What is populated (display only):** `email`, the first Keycloak `group`, and this client's
  role-mappings as `roles`. Per-request **authorization still uses the token** (`resource_access`),
  never this profile — so the profile is informational (it drives `user/self` and owner/group
  fields), and stale/empty roles here cannot grant or deny access.
* **Run-as user:** unless a matching local user defines `exec_user`, apps run as the configured
  default OS user (`DefaultExecUser`), not a per-Keycloak-user mapping.

To enable the admin lookups the client must be usable as a service account:

1. **Client authentication = On** (confidential client) and **Service accounts roles = On**
   (enables the `client_credentials` grant).
2. Grant the client's **service account** these `realm-management` client roles:
   * `view-users` — read the user, their groups, and their client role-mappings.
   * `view-clients` — resolve the client's internal id used for the role-mapping lookup.
3. Provide the client secret via `APPMESH_Keycloak_client_secret` (see below).

**Graceful degradation:** if no client secret is configured or the service account lacks the
roles above, profile resolution falls back to a **name-only** user (so an authenticated
identity never breaks owner/exec-user resolution). A username that genuinely does not exist in
Keycloak still returns `404`.

> **Secret injection:** the client secret is read from the `APPMESH_Keycloak_client_secret`
> environment variable (it overrides the `client_secret` value in `oauth2.yaml`). Leave the
> YAML value empty and inject the secret via the environment so it is not committed.

#### Limitations

* **Signing algorithms:** asymmetric RS/ES/PS families (RS256/384/512, ES256/384/512,
  PS256/384/512) are accepted. HMAC (`HS*`) and `none` are rejected by design to prevent
  algorithm-confusion forgery.
* **User management in OAuth2 mode:** `add/delete/lock/unlock/change-password` and TOTP setup
  act on the interim local store, not Keycloak. Manage those in Keycloak; the local endpoints
  are not authoritative for Keycloak identities.
* **Secured env encryption:** a Keycloak-owned application's encrypted environment variables are
  keyed from local password material, which a Keycloak-only user does not have. Prefer a
  locally-defined owner for apps that rely on encrypted env vars.

## REST

### SSL

SSL is enabled by default for REST services to ensure secure communication. You can configure custom SSL certificate files.

### JWT Authentication

All REST methods require authentication by default. JWT authentication protects APIs, with each user having role-based permissions to access corresponding methods.

#### JWT Sign Algorithm

App Mesh supports three JWT signing algorithms:

* HS256 - Uses JWTSalt as the secret key
* RS256 - Uses public and private PEM key files for signing
* ES256 - Uses public and private PEM key files with ECDSA algorithm


### Cookie Authentication & CSRF

Browsers may authenticate with a cookie: sending `X-Set-Cookie: true` on login makes the
server issue the JWT as an `appmesh_auth_token` cookie (HttpOnly, Secure, SameSite=Strict).
Programmatic SDK clients use the `Authorization: Bearer` header instead and are not affected by
anything in this section.

CSRF protection for cookie auth is enforced **in the daemon**, uniformly across all transports
(HTTP, WebSocket, and agent-proxied TCP) — the agent/SDKs need no special CSRF handling:

* **Baseline:** `SameSite=Strict` keeps the auth cookie off cross-site requests.
* **Origin check:** a cookie-authenticated state-changing request (POST/PUT/DELETE) must be
  same-origin, or carry an `Origin` listed in `REST.CsrfAllowedOrigins` (config.yaml, or the
  `APPMESH_REST_CsrfAllowedOrigins` env override). Cross-origin cookie requests are rejected
  with `403`. The `Origin` header is set by the browser and cannot be forged by cross-site
  page script, which makes it a reliable CSRF signal; non-browser clients send no cookie and
  are exempt.

**When to configure `CsrfAllowedOrigins`:** only when the browser UI runs on a *different origin*
than the API but the *same site* — e.g. the UI is served from a sibling subdomain or a different
port (`https://ui.example.com` calling `https://api.example.com`). In that case add the UI's origin
to the list (multiple values supported). You do **not** need it when:

* UI and API share one origin (e.g. both behind a single nginx domain) — same-origin is always allowed; or
* the UI is on a completely different domain — `SameSite=Strict` stops the browser from sending the
  cookie at all, so cookie auth can't be used there regardless.

### PSK (Pre-Shared Key)

Non-user client requests are authenticated through PSK verification.

## Encryption

### Encrypt Application Environment

For applications requiring confidential information, encrypted environment variables can be used to store sensitive data.

### Encrypt User Password

Password encryption is supported, allowing storage of encrypted passwords in YAML or Consul.

## Reference

* [User Role](https://app-mesh.readthedocs.io/en/latest/USER_ROLE.html)
* [JWT](https://app-mesh.readthedocs.io/en/latest/JWT.html)
* [MFA](https://app-mesh.readthedocs.io/en/latest/MFA.html)
