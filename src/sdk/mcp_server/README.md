# App Mesh MCP server

The MCP server exposes App Mesh operations over Streamable HTTP. It is an OAuth 2.1 protected resource.

The MCP server validates the caller access token. It forwards the same token to the Engine. The Engine validates the token again and makes the App Mesh authorization decision.

The MCP server does not receive a password. It does not issue or exchange a token.

## Install

```shell
python3 -m pip install -r requirements.txt
```

## Configure

Set these values:

```shell
export APPMESH_URL=https://127.0.0.1:6060
export APPMESH_CA=/opt/appmesh/ssl/ca.pem
export APPMESH_AUTH_ISSUER=https://appmesh.example.com/auth
export APPMESH_AUTH_ACCESS_URL=http://127.0.0.1:6062/auth
export APPMESH_AUTH_AUDIENCE=appmesh-api
export APPMESH_MCP_PUBLIC_URL=https://appmesh.example.com:6071
```

| Variable | Default | Purpose |
| --- | --- | --- |
| `APPMESH_URL` | `https://127.0.0.1:6060` | Engine REST URL. |
| `APPMESH_CA` | unset | CA file or directory for Engine TLS. |
| `APPMESH_SSL_VERIFY` | `true` | Engine TLS verification when no CA path is set. |
| `APPMESH_AUTH_ISSUER` | required | Canonical issuer in the token `iss` claim. |
| `APPMESH_AUTH_ACCESS_URL` | required | Route for discovery and signing keys. |
| `APPMESH_AUTH_CA_PATH` | unset | CA file or directory for the authentication route. |
| `APPMESH_AUTH_TLS_VERIFY` | `true` | TLS verification when no authentication CA path is set. |
| `APPMESH_AUTH_AUDIENCE` | `appmesh-api` | Required resource audience. |
| `APPMESH_MCP_HOST` | `0.0.0.0` | Listener address. |
| `APPMESH_MCP_PORT` | `6071` | Listener port. |
| `APPMESH_MCP_PUBLIC_URL` | derived | Public MCP base URL in metadata. |
| `APPMESH_MCP_TLS_CERT` | unset | MCP HTTPS certificate. |
| `APPMESH_MCP_TLS_KEY` | unset | MCP HTTPS private key. |

The issuer and access URL must refer to the same authentication service. Discovery must publish the configured issuer.

## Run

```shell
python3 appmesh_server.py
```

To run the server as an App Mesh application, update `appmesh_mcp_app.yaml` and register it:

```shell
appm add --stdin appmesh_mcp_app.yaml
```

## Client registration

Use a pre-registered public OAuth client. Configure its redirect URI for your MCP client. The built-in deployment includes the `appmesh-mcp-user` public client.

The MCP server publishes protected-resource metadata at:

```text
/.well-known/oauth-protected-resource/mcp
```

## File transfer

File tools return a `curl` command. The MCP server does not read file bytes. The client transfers bytes directly to or from the Engine.

Set `APPMESH_TOKEN` to an App Mesh access token before you run a returned command.

## Authorization

The Engine uses the authenticated principal for ownership and RBAC. Register the MCP application with a principal that has only the required permissions.

See [SDK Behavioral Contract](../../../docs/source/SDKContract.md) for bearer behavior. See [Security](../../../docs/source/Security.md) for trust boundaries.
