# Development

![block-diagram](https://github.com/laoshanxi/app-mesh/raw/main/docs/source/block_diagram.png)

## REST API source of truth

The normative API description is `src/daemon/rest/openapi.yaml`. App Mesh is an
OAuth protected resource: except for discovery/readiness endpoints, requests use
a Dex access token in the `Authorization: Bearer` header.

Authentication and Principal endpoints:

| Method | URI | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| GET | `/appmesh/auth/config` | public Dex issuer/audience/client/flow hints |
| GET | `/appmesh/principal/self` | current verified Principal and permissions |
| GET | `/appmesh/principal/self/permissions` | current effective permission IDs |
| GET | `/appmesh/principals` | list App Mesh authorization overlays |
| POST | `/appmesh/principal/{principal_id}` | create or update an overlay |
| DELETE | `/appmesh/principal/{principal_id}` | delete an authorization overlay, not an IdP user |
| GET | `/appmesh/roles` | list App Mesh roles |
| POST | `/appmesh/role/{role}` | update a permission set |
| DELETE | `/appmesh/role/{role}` | delete an unbound role |
| GET | `/appmesh/permissions` | list known permission IDs |

Application, task, event, file, label, configuration, metrics, and resource
endpoints remain documented in OpenAPI. Applications use
`owner_principal_id`; REST input cannot create `system: true` applications or
choose an arbitrary process user.

There are no Engine endpoints for username/password login, token renewal,
logout/blacklist, TOTP, directory users, password changes, groups, or upstream
identity-provider administration. Those operations belong to Dex or its
operator-managed upstream identity provider.

## Python SDK authentication

`AppMeshClient` accepts only a caller-supplied `bearer_token` and has no local
login or cookie persistence; `DexOAuthClient` implements the OAuth flows
(PKCE, Device Authorization, refresh, revocation, Client Credentials) against an
independently configured Dex route. See [Security](Security.md) for an example.

## Build

See [Build App Mesh guidance](Build.md).

## Integrations

- [Remote Execution Skill](https://github.com/laoshanxi/app-mesh/tree/main/.agents/skills/appmesh-remote)
- [MCP Server](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk/mcp_server) — Dex-protected Streamable HTTP resource server
- [MCP Bridge](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk/mcp_bridge)
- [MQTT Bridge](https://github.com/laoshanxi/app-mesh/tree/main/src/sdk/mqtt)

## Diagrams

![mind-diagram](https://github.com/laoshanxi/picture/raw/master/appmesh/mind.png)
