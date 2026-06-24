# App Mesh MCP Server

A standalone [MCP](https://modelcontextprotocol.io) server that exposes App Mesh
daemon operations as tools over **Streamable HTTP**, so MCP clients (Claude, etc.)
can manage applications remotely.

- **Transport:** Streamable HTTP (`/mcp`) — clients connect to a URL.
- **Auth:** OAuth 2.1 bridge. The client runs a browser login once; the server
  exchanges the App Mesh username/password for a JWT and hands it back as the OAuth
  access token. The client stores and **auto-refreshes** it. This server holds **no
  credentials** — every tool forwards the caller's JWT to the daemon, so the daemon's
  RBAC stays the single source of truth.
- **Hosting:** designed to run **as an App Mesh App** (`appmesh_mcp_app.yaml`) so it
  can be enabled / disabled / removed at any time, independently of the daemon.
- **SDK-only:** all daemon interaction goes through the App Mesh Python SDK
  (`appmesh.AppMeshClient`) — no hand-rolled HTTP.

## Files

| File | Purpose |
|------|---------|
| `appmesh_server.py` | FastMCP server + all tool definitions. |
| `auth.py` | `AppMeshOAuthProvider` — the OAuth 2.1 ↔ App Mesh login bridge + login page. |
| `appmesh_mcp_app.yaml` | App Mesh App definition to host the server. |
| `requirements.txt` | `fastmcp`, `appmesh`, deps. |

## Quick start

Requires **Python 3.10+** (FastMCP 3.x).

```bash
cd src/sdk/mcp_server            # run from this directory (the server imports auth.py)
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Point at your App Mesh REST endpoint and choose a listen port.
export APPMESH_URL=https://127.0.0.1:6060
export APPMESH_MCP_PORT=6071
# Loopback dev only — verify the daemon's TLS cert in production (set APPMESH_CA).
export APPMESH_SSL_VERIFY=false

python3 appmesh_server.py
```

### Configuration (environment variables)

| Variable | Default | Meaning |
|----------|---------|---------|
| `APPMESH_URL` | `https://127.0.0.1:6060` | App Mesh REST endpoint tool calls are forwarded to. |
| `APPMESH_CA` | — | CA file/dir to verify the daemon's TLS cert. **Takes precedence over `APPMESH_SSL_VERIFY` when set.** |
| `APPMESH_SSL_VERIFY` | `true` | Set `false` to disable daemon TLS verification (dev only). Ignored if `APPMESH_CA` is set. |
| `APPMESH_MCP_HOST` | `0.0.0.0` | MCP listener bind host. |
| `APPMESH_MCP_PORT` | `6071` | MCP listener port. |
| `APPMESH_MCP_PUBLIC_URL` | derived | Public base URL advertised in OAuth metadata. |
| `APPMESH_MCP_TLS_CERT` / `APPMESH_MCP_TLS_KEY` | — | Serve the MCP endpoint over HTTPS (recommended for remote clients). |
| `APPMESH_MCP_ACCESS_TTL` / `APPMESH_MCP_REFRESH_TTL` | `3600` / `604800` | OAuth access/refresh token lifetimes (seconds). |

## Connecting Claude

Add it as a remote MCP server (no static token — OAuth handles login):

```bash
claude mcp add --transport http appmesh https://<host>:6071/mcp
```

On first use the client runs OAuth: it discovers the auth server, registers
(Dynamic Client Registration), and opens the **App Mesh login page** — enter your
App Mesh username/password (and TOTP code if 2FA is enabled). The client then stores
the issued token and refreshes it automatically.

> ⚠️ **Use HTTPS off loopback.** The OAuth access token *is* a live App Mesh JWT
> (full daemon RBAC), sent on every request. Over plain HTTP a network observer can
> capture and replay it against the daemon. For anything beyond loopback set
> `APPMESH_MCP_TLS_CERT` / `APPMESH_MCP_TLS_KEY` (e.g. the App Mesh server cert) and an
> `https://` `APPMESH_MCP_PUBLIC_URL`.

> **Token lifecycle:** the access token (the App Mesh JWT) lasts ~1h and the client
> auto-refreshes it. Sessions are kept in memory, so restarting the server (or
> `appc disable`/`enable`) drops them — clients transparently re-run the browser login.

## Hosting as an App Mesh App

Deploy this directory (default `/opt/appmesh/sdk/mcp_server`), `pip install -r
requirements.txt`, then edit `appmesh_mcp_app.yaml`. **You must set
`APPMESH_MCP_PUBLIC_URL` to a real, client-reachable hostname** (the shipped
`https://your-host:6071` is a placeholder — leaving it breaks OAuth redirects). Also
review `owner`/`permission` (must match an existing App Mesh user). Then:

```bash
appc add -s appmesh_mcp_app.yaml   # register & start (behavior: keepalive)
appc disable -n mcp-server         # stop serving MCP
appc enable  -n mcp-server         # resume
appc rm   -n mcp-server            # remove entirely
```

## Tools (36)

All map 1:1 to App Mesh Python SDK methods; RBAC is enforced by the daemon per the
caller's token.

- **Applications:** `list_apps`, `get_app`, `add_app`, `delete_app`, `enable_app`,
  `disable_app`, `check_app_health`, `get_app_output`, `run_app_sync`, `run_app_async`
- **Tasks:** `run_task`, `cancel_task`
- **Host / metrics:** `get_host_resources`, `get_metrics`
- **Config / labels:** `get_config`, `set_config`, `set_log_level`, `list_labels`,
  `add_label`, `delete_label`
- **Users / RBAC:** `get_current_user`, `list_users`, `add_user`, `delete_user`,
  `lock_user`, `unlock_user`, `list_groups`, `list_permissions`,
  `get_user_permissions`, `list_roles`, `update_role`, `delete_role`
- **Sensitive** (forwarded as-is; arguments are never logged): `update_password`,
  `get_totp_secret`, `enable_totp`, `disable_totp`

### Intentionally **not** exposed

- `upload_file` / `download_file` — operate on the *server's* local filesystem, which
  is meaningless to a remote client.
- `login` / `authenticate` / `logout` / `renew_token` / `set_token` / token-refresh —
  handled by the OAuth layer.
- `subscribe` / event callbacks / `task_fetch` / `task_return` / `wait` /
  `send`/`receive_message` — long-lived / server-side semantics unsuited to stateless
  tool calls.

> The sibling `../mcp_bridge` directory is a separate, pre-existing MCP **client/bridge**
> (a stdio demo server plus `mcp_pipe.py`, a stdio↔WebSocket tunnel). It is unrelated
> to this standalone OAuth Streamable-HTTP server.
