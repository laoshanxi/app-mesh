# REST API

## Source of truth

The normative API description is `src/daemon/rest/openapi.yaml`
([browse interactively](https://petstore.swagger.io/?url=https://raw.githubusercontent.com/laoshanxi/app-mesh/main/src/daemon/rest/openapi.yaml)).
App Mesh is an OAuth protected resource: except for discovery/readiness
endpoints, requests use an OAuth access token in the
`Authorization: Bearer` header.

## Discovery and authentication

| Method | URI | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-protected-resource` | RFC 9728 resource metadata |
| GET | `/appmesh/auth/config` | Public issuer, audience, client, and flow hints |
| GET | `/oauth/callback` | Static OAuth callback relay page |
| POST | `/appmesh/auth/enroll-first-admin` | Enroll the first built-in App Mesh administrator |
| GET | `/appmesh/logo.svg` | Branding logo for the authentication-service login page |
| GET | `/appmesh/favicon.png` | Branding favicon for the authentication-service login page |

## Principals, roles, and permissions

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/principal/self` | Current verified principal and App Mesh authorization |
| GET | `/appmesh/principal/self/permissions` | Current principal effective permissions |
| GET | `/appmesh/principals` | List App Mesh authorization principals |
| POST | `/appmesh/principal/{principal_id}` | Update an App Mesh principal policy |
| DELETE | `/appmesh/principal/{principal_id}` | Delete an App Mesh authorization principal |
| GET | `/appmesh/roles` | List App Mesh roles |
| POST | `/appmesh/role/{role}` | Create or replace a role |
| DELETE | `/appmesh/role/{role}` | Delete an unused role |
| GET | `/appmesh/permissions` | List available permission identifiers |

## Applications

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/applications` | List visible applications |
| GET | `/appmesh/app/{name}` | Get an application |
| PUT | `/appmesh/app/{name}` | Register or update a non-system application |
| DELETE | `/appmesh/app/{name}` | Delete a non-system application |
| POST | `/appmesh/app/{name}/enable` | Enable a non-system application |
| POST | `/appmesh/app/{name}/disable` | Disable a non-system application |
| GET | `/appmesh/app/{name}/output` | Read application output |
| GET | `/appmesh/app/{name}/health` | Get application health |

Applications use `owner_principal_id`; REST input cannot create
`system: true` applications or choose an arbitrary process user.

## Run and tasks

| Method | URI | Purpose |
|---|---|---|
| POST | `/appmesh/app/run` | Start an asynchronous command |
| POST | `/appmesh/app/syncrun` | Run a command synchronously |
| POST | `/appmesh/app/{name}/task` | Send a task request to a managed application |
| GET | `/appmesh/app/{name}/task` | Fetch the next task payload for a managed application process |
| PUT | `/appmesh/app/{name}/task` | Return the task result from a managed application process |
| DELETE | `/appmesh/app/{name}/task` | Cancel the pending task request for a managed application |

## Event subscription

| Method | URI | Purpose |
|---|---|---|
| POST | `/appmesh/app/{name}/subscribe` | Subscribe to events from one application |
| DELETE | `/appmesh/app/{name}/subscribe` | Remove an event subscription |
| POST | `/appmesh/subscribe` | Subscribe to events from all applications |
| DELETE | `/appmesh/subscribe` | Remove an event subscription |

## Files, labels, and configuration

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/file/download` | Download a file |
| POST | `/appmesh/file/upload` | Upload a file |
| GET | `/appmesh/labels` | List host labels |
| PUT | `/appmesh/label/{label}` | Set a host label |
| DELETE | `/appmesh/label/{label}` | Delete a host label |
| GET | `/appmesh/config` | Get runtime configuration |
| POST | `/appmesh/config` | Update runtime configuration |

## Resources and metrics

| Method | URI | Purpose |
|---|---|---|
| GET | `/appmesh/resources` | Get host resources |
| GET | `/appmesh/metrics` | Get Prometheus metrics |
| GET | `/metrics` | Get Prometheus metrics |

## Out of scope

There are no Engine endpoints for username/password login, token renewal,
logout/blacklist, TOTP, directory users, password changes, groups, or upstream
identity-provider administration. Those operations belong to the
authentication service or its operator-managed upstream identity provider.

## Related

- [Authentication](Authentication.md) — OAuth flows and a worked Python SDK example
- [Event subscription](EventSubscription.md)
- [Build App Mesh](Build.md) — build guidance and integrations
