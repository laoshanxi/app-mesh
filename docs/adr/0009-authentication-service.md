# ADR 0009: Use one authentication service

- Status: Accepted
- Date: 2026-08-20
- Updated: 2026-08-28

## Context

The old Engine mixed authentication and authorization. It verified passwords, issued JWTs, managed TOTP, stored users, and enforced App Mesh roles. Some clients also depended on provider-specific behavior.

This design created multiple trust roots. It also made cluster identity difficult to keep stable.

The product needs a self-contained first start. It must also support an external identity deployment. Users must not need to know which provider implements the authentication service.

## Decision

Dex is the internal implementation of the App Mesh authentication service. App Mesh trusts one logical OpenID Connect issuer. The built-in public issuer path is `/auth`.

The Engine is an OAuth resource server. It validates access tokens with OpenID Connect discovery and signing keys. It requires an exact issuer and the `appmesh-api` audience.

App Mesh authorization uses the immutable issuer and subject. A token group, role, email address, or display name does not grant an App Mesh permission.

The Engine does not manage an identity password, MFA method, or directory group. An external deployment can configure upstream systems as Dex connectors.

The default package includes Dex. The service runs as the protected `auth-service` System App. External mode disables this System App and uses an operator-managed issuer.

The CLI and SDK use provider-neutral language. Their public names are `OAuthClient`, `OAuthConfig`, and `OAuthError`. SDK 3.0 provider-specific names remain compatibility aliases. New documentation and examples do not use those aliases.

The CLI supports three interactive flows:

- built-in password exchange;
- authorization code with PKCE;
- device authorization.

The password method reads the password from the terminal. The CLI has no password argument. The CLI sends the password to the authentication service. It sends only the access token to the Engine.

The first packaged administrator has no App Mesh role. After normal authentication, the CLI requests one local role assignment. The Engine accepts it only for the immutable packaged-administrator subject. The request must use a direct loopback connection on the built-in owner. The durable enrollment state must be open.

The first-administrator operation is not a login flow. It does not use a second enrollment secret. It cannot use forwarding or a direct remote connection.

A cluster has one logical issuer and one active built-in authentication owner. Followers use the same issuer and authorization data. Followers do not run another built-in database writer.

The CLI sends forwarded discovery to the target Engine. It gets tokens directly from the shared authentication service. It reuses a session only when issuer, client ID, and audience match.

The forwarding gateway validates the caller bearer before it opens a target connection. The target validates the same bearer again. This rule applies to HTTP, TCP, and WSS. WSS includes the bearer in each forwarded frame. Forwarded subscriptions use a persistent TCP or WSS route.

## Consequences

- The Engine login, password, TOTP, local user, token renewal, and blacklist APIs are removed.
- Existing Engine-issued JWTs and direct upstream-provider tokens stop working at cutover.
- Application ownership uses principal IDs instead of usernames.
- The authentication service is a startup dependency.
- A built-in installation needs one local administrator sign-in.
- Normal remote and forwarded sign-in work after the local assignment.
- The built-in SQLite state supports one active writer.
- Active-active deployments need an external service with replicated storage.
- Operator documents can describe Dex implementation and supply-chain details.
- User-facing CLI and SDK output does not expose the provider name.

## Compatibility

The implementation accepts the legacy `APPMESH_DEX_*` environment variables and SDK aliases during migration. New configuration uses `APPMESH_AUTH_*`, `access_url`, `tls_verify`, and `ca_path`.

An upgrade migrates the old initial credential file names to provider-neutral names. It keeps the password hashes and identity subjects unchanged.
