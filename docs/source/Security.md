# Security

App Mesh acts as enterprise middleware, implementing security at multiple levels to provide a secure platform.

## Security Concepts

### User

App Mesh has built-in user management. Each user can define a process execution OS user for application execution. Each user has:

* Password
* MFA key
* Roles

```bash
$ appc user
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

#### Limitations

* **Signing algorithms:** asymmetric RS/ES/PS families (RS256/384/512, ES256/384/512,
  PS256/384/512) are accepted. HMAC (`HS*`) and `none` are rejected by design to prevent
  algorithm-confusion forgery.

## REST

### SSL

SSL is enabled by default for REST services to ensure secure communication. You can configure custom SSL certificate files.

### JWT Authentication

All REST methods require authentication by default. JWT authentication protects APIs, with each user having role-based permissions to access corresponding methods.

#### JWT Sign Algorithm

App Mesh supports two JWT signing algorithms:

* HS256 - Uses JWTSalt as the secret key
* RS256 - Uses public and private PEM key files for signing
* ES256 - Uses public and private PEM key files with ECDSA algrithom


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
