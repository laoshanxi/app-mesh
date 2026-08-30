# ADR 0009: Dex-only authentication with a minimal built-in password profile

- Status: Accepted
- Date: 2026-08-20

## Context

App Mesh currently mixes local password verification, JWT issuance, Keycloak-specific OAuth,
user profiles, application ownership, encryption, and authorization in one `Security` facade.
Clients can also use App Mesh password APIs and locally issued special-purpose tokens. This
creates multiple trust roots and prevents a consistent cluster identity.

## Decision

Dex is the only authentication entry point and the only access-token issuer trusted by App
Mesh. The built-in v1 profile enables Dex's password database with one
randomly generated static bootstrap credential. Keycloak, Entra, Okta, SAML,
LDAP, or other enterprise identity systems are configured only as connectors
in an externally operated Dex deployment.

App Mesh is an OAuth Resource Server. It validates Dex access tokens using OIDC Discovery and
JWKS, requiring an exact issuer and the `appmesh-api` audience. Authorization remains local or
cluster-shared and is keyed by `(issuer, subject)`. Token role/group/display claims do not grant
permissions directly.

Identity user management is not an engine responsibility: user creation,
password lifecycle, MFA, and directory groups belong to the external identity
deployment. The engine stores only App Mesh principals, roles, role bindings,
execution policy, resource ownership, and audit state.

Browser login uses Authorization Code with PKCE directly in the browser client; Agent does not
exchange authorization codes, hold a client secret, or maintain an OAuth session. Agent and MCP
are transparent gateways that forward the caller bearer unchanged and rely on Engine for the
authoritative token validation and authorization decision. The Python and Rust SDKs implement reusable
Dex token providers for Authorization Code with PKCE, Device Authorization, refresh,
and revocation. The Rust CLI performs browser/loopback login
by default and Device Authorization when requested. App Mesh does not collect passwords, proxy
refresh tokens, mint identity tokens, or expose an upstream IdP directly.

The cluster runs one logical Dex instance in a single-active auth-owner topology.
Followers trust the same stable Dex issuer and share authorization data. Dex
ships with App Mesh and runs as a protected System App, not an external service.

## Consequences

- The legacy `/appmesh/login`, renew, logoff-blacklist, TOTP, password, and local user APIs are
  removed in a major release.
- Existing App Mesh JWTs and direct Keycloak tokens stop working at cutover.
- Application owner identities migrate from usernames to stable Principal IDs.
- Secret encryption moves from user password material to a node/cluster `SecretProtector`.
- Dex readiness becomes part of App Mesh startup and cluster readiness.
- The launcher renders Dex's public deployment settings into a mode-0600 runtime
  file; only connector-secret environment expansion supported by Dex is used.
- A System App with a custom health command stays unready until its first
  successful probe, so dependency edges are readiness barriers, not PID ordering.
- Installed code stays root-owned; a configured daemon account owns only mutable
  runtime state and its PID file. TLS private keys are never world-readable, and
  the Python SDK requires explicit opt-in certificates for mTLS instead of
  reusing the installation's client identity.
- The pinned Dex Apache-2.0 license, provenance, and prepared-binary checksums
  ship with the package alongside the App Mesh/helper MIT and BSD-3-Clause
  notices. No GPL binary or assets are distributed.
