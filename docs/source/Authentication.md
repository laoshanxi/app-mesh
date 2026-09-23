# Built-in authentication: passwords and tokens

This document answers common operational questions about passwords and tokens in
the built-in authentication mode (`APPMESH_AUTH_MODE=builtin`, see
[ADR 0009](../adr/0009-authentication-service.md)). In `external` mode passwords
belong to the external identity provider and this document does not apply.

See [Security](Security.md) for the trust model, [CLI](CLI.md) for sign-in
commands, and [Install](Install.md) for deployment procedures.

## Questions at a glance

| I want to ... | Do this | Details |
| --- | --- | --- |
| Sign in for the first time | Read the generated password with `print-initial-password` | [First sign-in](#first-sign-in) |
| Choose my own administrator password | Pipe it to `set-initial-password`, then restart | [Choosing your own password](#choosing-your-own-administrator-password) |
| Set the password when a container starts | Mount a secret file and set `APPMESH_ADMIN_PASSWORD_FILE` | [Container first start](#container-first-start) |
| Replace a leaked or lost password | `rotate-initial-password`, then restart | [Rotating and forgetting](#rotating-recovering-and-forgetting) |
| Get a token for CI or an SDK | `automation-token` (machine) or `user-token` (user) | [Getting a token](#getting-a-token-for-sdk-and-ci) |
| Manage users, clients, and sessions | Open the administration UI on `http://127.0.0.1:6064` | [Administration UI](#administration-ui) |
| Add another user | `add-user` with the password on standard input | [Adding a user](#adding-a-user) |
| Delete a user | `delete-user` with the address | [Deleting a user](#deleting-a-user) |
| Use a password from the Python SDK | Custom `TokenProvider`, or exchange the token first | [Python SDK password sign-in](#using-a-password-from-the-python-sdk) |

All examples use the packaged helper `appmesh-auth.sh` (`appmesh-auth.ps1` on
Windows, same actions) and the Linux install root `/opt/appmesh`.

## First sign-in

The first bootstrap generates a random administrator password
(`openssl rand -hex 24`, 48 hex characters). There is intentionally no
command-line argument or environment variable to preset it: environment values
leak into `docker inspect`, compose files, CI logs, and `/proc/<pid>/environ`.

Read the password on the authentication owner host:

```shell
sudo /opt/appmesh/script/appmesh-auth.sh print-initial-password

# Without a terminal, pipe it straight into the CLI:
sudo /opt/appmesh/script/appmesh-auth.sh print-initial-password \
  | appm logon --username admin@appmesh.local --password-stdin
```

Bootstrap state lives in `work/auth/secrets/`. Every file is mode `600`, owned
by the directory owner, and single-linked; the daemon validates all three
properties at startup.

| File | Content |
| --- | --- |
| `initial-admin-credentials` | Administrator `username` / `email` / `user_id` / `password_hash` / `password` |
| `initial-viewer-credentials` | Read-only viewer (`guest@appmesh.local`), same format |
| `automation-client` | Secret of the `appmesh-automation` confidential client |
| `secret-master-key` | Encryption key for protected environment values. Include it in every backup of the work directory. |

The `password=` line (plaintext) exists only so that `print-initial-password`
can display it. The authentication service reads only `password_hash=`.

## Choosing your own administrator password

### `set-initial-password` (recommended)

Pipe the new password to the helper, then restart App Mesh. The password comes
from standard input — never from an argument or environment variable — and the
helper applies the same hashing, file-permission, and validation path as
bootstrap and rotation.

```shell
# Linux package
echo 'your-password' | sudo /opt/appmesh/script/appmesh-auth.sh set-initial-password
sudo systemctl restart appmesh

# Windows package (elevated PowerShell)
'your-password' | & 'C:\local\appmesh\script\appmesh-auth.ps1' set-initial-password
Restart-Service AppMeshService

# Container already running (docker exec uses the container user, so file
# ownership is correct)
echo 'your-password' | docker exec -i appmesh /opt/appmesh/script/appmesh-auth.sh set-initial-password
docker restart appmesh
```

Rules:

- The password is a single line, at most 72 bytes (the bcrypt input limit).
- A restart is required: the Dex configuration is re-rendered from the
  credential file at every startup, so the old password stays valid until the
  restart. Editing `work/auth/dex/dex.yaml` directly never works — it is
  overwritten.
- The helper keeps the plaintext `password=` line, so
  `print-initial-password` still works afterwards.

### Container first start

For a declarative container deployment, mount the password as a file and point
`APPMESH_ADMIN_PASSWORD_FILE` at it. The variable carries a **path**, not the
password itself, so the secret stays out of `docker inspect` and compose files.
This matches the Docker secrets pattern:

```shell
docker run -d --name appmesh \
  -v appmesh-work:/opt/appmesh/work \
  -v /path/to/admin-password:/run/secrets/admin-password:ro \
  -e APPMESH_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
  -p 6060:6060 \
  laoshanxi/appmesh:latest
```

The entrypoint applies the file only while no administrator credential exists —
the first boot. Later `set-initial-password` and `rotate-initial-password`
changes survive container restarts even when the variable stays set. In
`external` authentication mode the variable is ignored.

An equivalent pre-seed alternative runs the helper against the volume before
the first start; bootstrap then keeps the credential instead of generating a
random one:

```shell
echo 'your-password' | docker run --rm -i --user 482:482 \
  -v appmesh-work:/opt/appmesh/work \
  --entrypoint /opt/appmesh/script/appmesh-auth.sh laoshanxi/appmesh:latest set-initial-password
```

### Editing the credential file directly (advanced)

Manual editing is what the helper does internally. If you do it by hand, all
four constraints apply; violating any of them makes the daemon refuse to start:

| Constraint | Value |
| --- | --- |
| bcrypt format | `^\$2[aby]\$10\$[./A-Za-z0-9]{53}$` — the cost must be **10** (Python `bcrypt` defaults to 12 and fails validation). Use `/opt/appmesh/bin/passhash`. |
| Plaintext length | ≤ 72 bytes |
| File metadata | mode `600`, owner identical to the directory owner, exactly one hard link. In the container the owner is uid/gid **482**. |
| Identity fields | `username` / `email` / `user_id` must match the [constants](#identities-and-clients) verbatim. |

Write through a temporary file in the same directory and `mv` it into place to
preserve ownership.

## Rotating, recovering, and forgetting

| Command | Semantics |
| --- | --- |
| `rotate-initial-password` | Generates a new random password and writes hash and plaintext. **Until the restart the old password still works and the new one does not;** after the restart they switch. This is the only recovery path for a lost password. |
| `forget-initial-password` | Removes only the plaintext line. The hash is unchanged, so the existing password keeps working; `print-initial-password` stops working. |

Two points are easy to get backwards:

- `forget` does **not** change the password. It only makes the plaintext
  unrecoverable. Use `rotate` (or `set-initial-password`) to change it.
- The leftover hash is not a credential. Using it as a password returns `401`,
  although it corresponds to the same password. Plaintext and hash are not
  cross-validated, so if they disagree only `print-initial-password` lies.

## Administration UI

App Mesh has no user directory. The authentication service owns identities; App
Mesh stores only the authorization record of a verified subject. Both are
managed in the bundled administration UI — the `dexuser` System App, served by
`bin/dexuser` — which covers users, OAuth clients, connectors, sessions, and
MFA.

The UI listens on loopback only (`http://127.0.0.1:6064`), because it has **no
authentication of its own** — the same posture as the administrative gRPC API
it drives. Open it through SSH port forwarding:

```shell
ssh -L 6064:127.0.0.1:6064 <host>
```

Key facts:

- Users are created under **Passwords → Create a password** and can sign in
  immediately. The packaged `admin@appmesh.local` and `guest@appmesh.local`
  identities are static and cannot be changed here.
- A user created in the UI has no App Mesh role. Use
  [`add-user`](#adding-a-user) to create and bind in one step, or set the role
  through the REST API: `POST /appmesh/principal/<principal-id>` with
  `{"roles": ["appmesh-viewer"]}`.
- Set `APPMESH_AUTH_ADMIN_UI=off` to disable the UI. The App is a **system**
  App, so once disabled it cannot be re-enabled through the application API.
- On Windows the authentication service runs with memory storage: identities
  created here do not survive a restart.
- The UI's demonstration pages (Flows, Token tools) use an unregistered
  `example-app` OAuth client; only the administration pages are supported.
- `APPMESH_AUTH_ADMIN_LISTEN` changes the UI listener; the underlying gRPC API
  listens on `127.0.0.1:5557` (`APPMESH_AUTH_GRPC_LISTEN`).

## Adding a user

`add-user` creates the identity (through the administration UI, which must be
running) and binds its authorization role in one step:

```shell
printf '%s' 'Alice-Pw-2026' | sudo /opt/appmesh/script/appmesh-auth.sh add-user alice@corp.local appmesh-viewer
```

The password comes from standard input so it never appears in `ps` or CI logs.
The command prints the Principal ID to standard output; the role argument
defaults to `appmesh-viewer` and must exist in the authorization policy.

The command rejects the static `admin@appmesh.local` / `guest@appmesh.local`
identities and requires built-in mode on the authentication owner. The Engine
reads the authorization policy only at startup: restart App Mesh before the new
user's first request, or apply the role through the REST API — the command
prints the exact `POST /appmesh/principal/<principal-id>` request when the
Engine is running.

## Deleting a user

```shell
sudo /opt/appmesh/script/appmesh-auth.sh delete-user alice@corp.local
```

Removes the identity and its role binding, and prints the Principal ID. The
user can no longer sign in. The same Engine restart caveat as `add-user`
applies.

## Getting a token for SDK and CI

Every client accepts the access token through `APPMESH_BEARER_TOKEN`. Pick one
of two sources depending on the identity you need.

### Password grant — user identity (administrator permissions)

On the authentication owner host, pipe the password to `user-token`; only the
access token is printed:

```shell
echo 'your-password' | sudo /opt/appmesh/script/appmesh-auth.sh user-token
export APPMESH_BEARER_TOKEN=$(echo 'your-password' | sudo /opt/appmesh/script/appmesh-auth.sh user-token)

# Another built-in identity, or a container:
echo 'guest-password' | sudo /opt/appmesh/script/appmesh-auth.sh user-token guest@appmesh.local
echo 'your-password' | docker exec -i appmesh /opt/appmesh/script/appmesh-auth.sh user-token
```

The command wraps the password grant against the local authentication service
(public client `appmesh-cli`, scope `openid audience:server:client_id:appmesh-api`).
From a remote machine, run the same grant against the agent endpoint
`https://<host>:6060/auth/token` — the agent proxies the issuer path, so the
client never needs to resolve the internal issuer address:

```shell
export APPMESH_BEARER_TOKEN=$(curl -s -u "appmesh-cli:" -X POST \
    https://<host>:6060/auth/token \
    --data-urlencode grant_type=password \
    --data-urlencode "username=admin@appmesh.local" \
    --data-urlencode "password=your-password" \
    --data-urlencode "scope=openid audience:server:client_id:appmesh-api" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
```

- Port 6062 is the loopback authentication service; remote clients use the
  agent port 6060 instead.
- The audience scope is colon-separated: `audience:server:client_id:appmesh-api`.
  Writing `...client_id=appmesh-api` returns
  `400 invalid_request: Unrecognized scope(s)` — that error means the scope is
  misspelled.

### `automation-token` — machine identity (unattended)

```shell
export APPMESH_BEARER_TOKEN=$(sudo /opt/appmesh/script/appmesh-auth.sh automation-token)
```

- Uses the `appmesh-automation` confidential client with the
  `client_credentials` grant; no human password is involved.
- The principal carries the `appmesh-maintenance` role (4 permissions; see
  [Roles](#roles)). Application registration and `run_task` return `403`.
- Available only on the built-in authentication **owner** node.
- Access tokens live 15 minutes, so refresh them periodically. The packaged
  Prometheus stack re-mints every 5 minutes.

### Sign-in capabilities by entry point

| Entry point | Password grant | Client credentials | PKCE / device | Refresh |
| --- | --- | --- | --- | --- |
| `appmesh-auth.sh user-token` | ✅ | — | — | — |
| `appmesh-auth.sh automation-token` | — | ✅ | — | — |
| CLI `appm logon` | ✅ | — | ✅ `--device` / `--browser` | ✅ (session file) |
| Rust SDK `OAuthClient` | ✅ `password_login()` | — | ✅ | ✅ |
| Python SDK `OAuthClient` | — | — | ✅ | ✅ |
| Go / Java / JS / C++ SDK | — | — | — | — (`SetToken` only) |

The CLI never prints tokens: `appm loginfo` shows the principal and the expiry
only. Use the grant or `automation-token` when you need the raw token. With
`APPMESH_BEARER_TOKEN` set, the CLI uses the token as-is until it expires — no
session file, no refresh.

## Using a password from the Python SDK

The Python SDK has no password grant; `AppMeshClient` accepts a
`bearer_token` or a `token_provider`. To sign in with a password, put the grant
inside a `TokenProvider` subclass — the rest of the SDK code does not change:

```python
import requests
from appmesh import AppMeshClient
from appmesh.token_provider import TokenProvider


class PasswordProvider(TokenProvider):
    """Exchange a password for an access token inside the SDK.

    A production implementation should re-authenticate on 401 because the
    access token lives only 15 minutes.
    """

    def __init__(self, token_url, username, password):
        self.token_url, self.username, self.password, self._tok = token_url, username, password, None

    def get_access_token(self):
        if self._tok:
            return self._tok
        r = requests.post(
            self.token_url,
            auth=("appmesh-cli", ""),
            data={"grant_type": "password", "username": self.username,
                  "password": self.password,
                  "scope": "openid audience:server:client_id:appmesh-api"},
            verify=False, timeout=10,  # verify=False is for test environments only
        )
        r.raise_for_status()
        self._tok = r.json()["access_token"]
        return self._tok


c = AppMeshClient(base_url="https://host:6060",
                  token_provider=PasswordProvider("http://127.0.0.1:6062/auth/token",
                                                  "admin@appmesh.local", "your-password"),
                  ssl_verify=False)
print(c.get_current_principal()["roles"])  # ['appmesh-admin']
```

The simpler equivalent is to run the password grant outside the SDK and pass
the result as `bearer_token`. Both approaches are verified.

Other SDKs take the token directly: Go `client.SetToken(...)`, Rust
`client.set_token(...)`, Java `setBearerToken(...)`, JavaScript
`client.set_bearer_token(...)`.

## Reference

### Identities and clients

| Item | Value |
| --- | --- |
| Administrator | `admin@appmesh.local` / username `admin` / user ID `2d1c8c38-3898-4c89-a78b-3caa42f203c1` |
| Read-only viewer | `guest@appmesh.local` / username `guest` / user ID `93ad39b4-eb6f-4945-97a1-3366451867fb` |
| Automation client | `appmesh-automation` (confidential; the principal is derived from the client ID and stays stable across secret regeneration) |

OAuth clients defined in `src/auth/dex.yaml`:

| Client ID | Type | Purpose |
| --- | --- | --- |
| `appmesh-api` | public | Audience target |
| `appmesh-cli` | public | CLI and native clients (RFC 8252) |
| `appmesh-web` | public | Browser authorization code + PKCE |
| `appmesh-mcp-user` | public | MCP clients (Dex has no dynamic registration) |
| `appmesh-automation` | confidential | `client_credentials` for CI and unattended jobs |

### Lifetimes

| Item | Value |
| --- | --- |
| Access token | 15 minutes (JWT `exp - iat` = 900 seconds) |
| Signing keys | 6 hours |
| Refresh token | Rotates on every use; `reuseInterval: 5m`; idle expiry `validIfNotUsedFor: 168h` |

SDKs without refresh support (Go, Java, JS, C++) must re-mint the token in
long-running processes.

### Roles

| Role | Permissions |
| --- | --- |
| `appmesh-admin` | All 27 permissions, including `app-reg`, `app-run-task`, `principal-set`, `role-set`, `workflow-admin` |
| `appmesh-maintenance` | `app-control`, `app-manage-all`, `app-view-all`, `host-resource-view` |

The full permission list lives in `src/daemon/security/authorization.yaml`.

### Ports

| Port | Owner | Purpose |
| --- | --- | --- |
| 6060 | agent | HTTPS entry; proxies REST/WSS and the issuer path (main client endpoint) |
| 6059 | daemon | TCP API (msgpack) |
| 6058 | daemon | uWS: HTTPS REST + WSS |
| 5557 | authentication service | Administrative gRPC API, mutual TLS, loopback only (drives the administration UI) |
| 6062 | authentication service | Issuer and token endpoint |
| 6063 | authentication service | Telemetry (`/healthz`) |
| 6064 | administration UI | `dexuser` System App web UI, loopback only |
| 6061 | agent | Prometheus exporter (off by default) |
