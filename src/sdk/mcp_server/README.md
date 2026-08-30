# App Mesh MCP Server

This Streamable HTTP MCP server exposes App Mesh operations while keeping Dex as
the only authentication authority.

- The MCP endpoint is an OAuth protected resource.
- FastMCP validates the caller's Dex-signed access token against Dex JWKS.
- The same bearer token is forwarded to App Mesh; the MCP server never mints,
  exchanges, refreshes, or persists tokens.
- Passwords, MFA, and identity-provider administration are not exposed here.
- App Mesh remains the source of authorization policy for applications, roles,
  principals, execution mapping, and ownership.

## Install and run

Python 3.10+ is required.

```bash
cd src/sdk/mcp_server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export APPMESH_URL=https://127.0.0.1:6060
export APPMESH_CA=/opt/appmesh/ssl/ca.pem
export APPMESH_DEX_ISSUER=https://appmesh.example.com/dex
export APPMESH_DEX_ACCESS_URL=http://127.0.0.1:6062/dex
export APPMESH_DEX_AUDIENCE=appmesh-api
export APPMESH_MCP_PUBLIC_URL=https://appmesh.example.com:6071
python3 appmesh_server.py
```

`APPMESH_DEX_ISSUER` is the canonical issuer and must exactly match the token
`iss` claim. `APPMESH_DEX_ACCESS_URL` is only the route this MCP process uses for
Dex JWKS; it may point to loopback, a service name, or a cluster VIP. Changing the
access URL never changes the trusted issuer.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APPMESH_URL` | `https://127.0.0.1:6060` | Engine host used for forwarded tool calls. |
| `APPMESH_DAEMON_PUBLIC_URL` | `APPMESH_URL` | Client-reachable Engine URL in file-transfer recipes. |
| `APPMESH_CA` | unset | CA file or directory for Engine TLS. |
| `APPMESH_SSL_VERIFY` | `true` | Engine TLS verification fallback when no CA is set. |
| `APPMESH_DEX_ISSUER` | required | Canonical and sole trusted Dex issuer. |
| `APPMESH_DEX_ACCESS_URL` | required | MCP-to-Dex discovery/JWKS route, independent of the Engine host. |
| `APPMESH_DEX_CA_PATH` | unset | CA file or directory for Dex discovery TLS, separate from `APPMESH_CA`. |
| `APPMESH_DEX_TLS_VERIFY` | `true` | Dex discovery TLS verification fallback when no Dex CA is set. |
| `APPMESH_DEX_AUDIENCE` | `appmesh-api` | Required access-token audience. |
| `APPMESH_MCP_HOST` | `0.0.0.0` | MCP bind host. |
| `APPMESH_MCP_PORT` | `6071` | MCP bind port. |
| `APPMESH_MCP_PUBLIC_URL` | derived | Public resource URL in OAuth metadata. |
| `APPMESH_MCP_TLS_CERT` / `APPMESH_MCP_TLS_KEY` | unset | MCP HTTPS certificate and key. |

Use HTTPS whenever the MCP endpoint is reachable beyond loopback. Access tokens
are bearer credentials and must not be placed in configuration files or command
history.

## Dex client registration

Dex does not provide OAuth Dynamic Client Registration. The bundled Dex config
therefore defines the public client `appmesh-mcp-user` as a trusted peer of the
`appmesh-api` audience. MCP clients must be explicitly configured with that client
ID (or another pre-registered Dex public client) and an allowed redirect URI.

The requested scopes are:

```text
openid profile email groups offline_access audience:server:client_id:appmesh-api
```

No OAuth proxy is inserted in front of Dex because that would introduce a second
token issuer, contrary to the Dex-only trust model.

## Hosting under App Mesh

Edit the public placeholders in `appmesh_mcp_app.yaml`, then register it using a
Dex-authenticated App Mesh client. App Mesh assigns the registering principal as
the application owner; the file intentionally contains no legacy `owner` user.

The process depends only on App Mesh, Dex, and packaged Python dependencies. It
does not require a separately managed authentication service.

## Exposed authorization surface

The MCP tools expose App Mesh application/task/file/config/label operations plus:

- current principal and effective permissions;
- authorization-principal overlays;
- roles and permission definitions.

They intentionally do not expose identity-provider user CRUD, passwords, MFA, connectors,
local login/logout, token renewal, or upstream IdP APIs.

File tools return a direct client-to-Engine transfer command. Set the caller's
Dex access token in the local `APPMESH_TOKEN` environment variable; file bytes do
not pass through MCP or model context.
