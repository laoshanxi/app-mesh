#!/usr/bin/python3
# pylint: disable=line-too-long,broad-exception-caught
"""App Mesh OAuth2 (Keycloak) SDK example and smoke test.

Exercises ``AppMeshClientOAuth`` against a real Keycloak instance:

  1. Password-grant login (Direct Access Grant)
  2. Access-token signature verification via the realm JWKS endpoint
  3. OIDC userinfo — direct from Keycloak vs the daemon's ``/appmesh/user/self``
  4. Daemon API access with the Keycloak token (RBAC via client roles)
  5. Token renew (refresh-token rotation) and logout
  6. OAuth 2.0 Device Authorization Grant, RFC 8628 (``--device``, interactive)

Setup
-----
Keycloak side — one command (starts a container if needed; idempotent):

    bash src/sdk/python/test/keycloak-init.sh

It creates realm ``appmesh-realm``, confidential client ``appmesh-client`` (direct
access grants + device grant enabled), all App Mesh permission keys as client roles,
and user ``mesh``/``mesh123`` with every role. Export the printed client secret as
``APPMESH_Keycloak_client_secret`` (do not commit it).

App Mesh daemon side (optional — enables the daemon API section):

    config.yaml:  REST.JWT.SecurityInterface: oauth2
    oauth2.yaml:  auth_server_url/realm/client_id pointing at the SAME Keycloak URL
                  (token issuer must match; see docs/source/Security.md, OAuth2 section)

Usage
-----
    python3 test_oauth2.py            # password grant flow
    python3 test_oauth2.py --device   # device authorization grant (approve in browser)

Configuration via environment (defaults match keycloak-init.sh):
    KEYCLOAK_URL   KEYCLOAK_REALM   KEYCLOAK_CLIENT_ID   APPMESH_Keycloak_client_secret
    TEST_USER      TEST_PWD         APPMESH_URL
"""

import argparse
import json
import os
import sys

import jwt
import requests
from jwt.algorithms import RSAAlgorithm

# For source code env:
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from appmesh import AppMeshClientOAuth
from appmesh.exceptions import AppMeshError


def step(title: str) -> None:
    """Print a section header."""
    print(f"\n=== {title} ===")


class KeycloakTokenVerifier:
    """Verify Keycloak-issued JWT access tokens against the realm's JWKS endpoint."""

    def __init__(self, auth_server_url: str, realm: str):
        self.jwks_uri = f"{auth_server_url}/realms/{realm}/protocol/openid-connect/certs"
        self.public_keys = {}
        self.fetch_public_keys()

    def fetch_public_keys(self) -> None:
        """Fetch and cache the realm's RS256 public keys, indexed by key ID."""
        response = requests.get(self.jwks_uri, timeout=10)
        response.raise_for_status()
        for key_data in response.json().get("keys", []):
            kid = key_data.get("kid")
            if kid and key_data.get("alg") == "RS256":
                self.public_keys[kid] = RSAAlgorithm.from_jwk(json.dumps(key_data))

    def verify(self, access_token: str) -> dict:
        """Verify signature/expiry and return the decoded claims (raises on failure)."""
        kid = jwt.get_unverified_header(access_token).get("kid")
        if kid not in self.public_keys:
            self.fetch_public_keys()  # key rotation
        if kid not in self.public_keys:
            raise ValueError(f"Unable to find public key for kid: {kid}")
        # Keycloak puts "account" in aud by default; adjust to your audience mappers.
        return jwt.decode(access_token, key=self.public_keys[kid], algorithms=["RS256"], audience="account", options={"verify_exp": True})


def keycloak_config_from_env() -> dict:
    """Build the AppMeshClientOAuth ``oauth2`` config from environment variables."""
    return {
        "auth_server_url": os.environ.get("KEYCLOAK_URL", "http://localhost:8080"),
        "realm": os.environ.get("KEYCLOAK_REALM", "appmesh-realm"),
        "client_id": os.environ.get("KEYCLOAK_CLIENT_ID", "appmesh-client"),
        "client_secret": os.environ.get("APPMESH_Keycloak_client_secret", ""),  # confidential clients; set via env, never commit
    }


def make_client(keycloak_config: dict, auto_refresh_token: bool = True) -> AppMeshClientOAuth:
    """Create an AppMeshClientOAuth pointed at the local daemon."""
    return AppMeshClientOAuth(
        oauth2=keycloak_config,
        base_url=os.environ.get("APPMESH_URL", "https://127.0.0.1:6060"),
        ssl_verify=False,  # test env only — the daemon uses a self-signed cert
        auto_refresh_token=auto_refresh_token,
    )


def verify_token_signature(client: AppMeshClientOAuth, keycloak_config: dict) -> None:
    """Validate the current access token offline against the realm JWKS."""
    step("Verify access-token signature (JWKS)")
    access_token = client._token.get("access_token")  # pylint: disable=protected-access
    verifier = KeycloakTokenVerifier(keycloak_config["auth_server_url"], keycloak_config["realm"])
    claims = verifier.verify(access_token)
    roles = claims.get("resource_access", {}).get(keycloak_config["client_id"], {}).get("roles", [])
    print(f"signature OK — iss={claims.get('iss')} user={claims.get('preferred_username')}")
    print(f"{keycloak_config['client_id']} roles in token: {len(roles)}")
    assert roles, "token carries no client roles — App Mesh RBAC would deny everything"


def show_userinfo(client: AppMeshClientOAuth) -> None:
    """OIDC userinfo straight from Keycloak (needs the client's profile/email scopes)."""
    step("OIDC userinfo (direct from Keycloak)")
    userinfo = client.get_oauth_userinfo()
    print(f"userinfo: {userinfo}")
    assert userinfo.get("preferred_username") or userinfo.get("sub"), "userinfo returned no identity claim"


def daemon_api_demo(client: AppMeshClientOAuth) -> None:
    """Call daemon APIs with the Keycloak token; skipped gracefully when no daemon runs.

    Requires the daemon in oauth2 mode against the SAME Keycloak URL — otherwise the
    token's ``iss`` claim will not match and the daemon rejects it.
    """
    step("Daemon API with Keycloak token")
    try:
        me = client.get_current_user()  # daemon /appmesh/user/self (userinfo shape in oauth2 mode)
        print(f"daemon user/self: {me}")
        apps = [app.name for app in client.list_apps()]
        print(f"daemon apps: {apps}")
    except AppMeshError as exc:
        print(f"SKIPPED — daemon not reachable or not in oauth2 mode: {exc}")


def token_lifecycle_demo(client: AppMeshClientOAuth) -> None:
    """Renew (refresh-token rotation) then logout (revokes the Keycloak session)."""
    step("Token renew + logout")
    before = client._token.get("access_token")  # pylint: disable=protected-access
    client.renew_token()
    after = client._token.get("access_token")  # pylint: disable=protected-access
    assert before != after, "renew_token did not rotate the access token"
    print("renew: OK (token rotated)")
    print(f"logout: {client.logout()}")


def password_grant_demo(keycloak_config: dict) -> None:
    """Password-grant (Direct Access Grant) end-to-end demo."""
    user = os.environ.get("TEST_USER", "mesh")
    pwd = os.environ.get("TEST_PWD", "mesh123")

    client = make_client(keycloak_config)
    try:
        step(f"Password-grant login as '{user}'")
        client.login(user, pwd)
        print("login: OK")

        verify_token_signature(client, keycloak_config)
        show_userinfo(client)
        daemon_api_demo(client)
        token_lifecycle_demo(client)
    finally:
        client.close()


def device_flow_demo(keycloak_config: dict) -> None:
    """OAuth 2.0 Device Authorization Grant (RFC 8628) demo.

    Interactive: prints a verification URL, then polls until you approve the login in a
    browser (any device). Requires "OAuth 2.0 Device Authorization Grant" enabled on the
    Keycloak client (keycloak-init.sh sets it).
    """
    client = make_client(keycloak_config, auto_refresh_token=False)
    try:
        step("Device authorization grant (RFC 8628)")
        client.login_device_flow()  # default prompt prints the verification URL + user code
        print("device flow login: OK")

        show_userinfo(client)
        daemon_api_demo(client)
        token_lifecycle_demo(client)
    finally:
        client.close()


def main() -> None:
    """Entry point: password grant by default, device flow with --device."""
    parser = argparse.ArgumentParser(description="App Mesh OAuth2 (Keycloak) SDK example")
    parser.add_argument("--device", action="store_true", help="use the interactive RFC 8628 device flow instead of the password grant")
    args = parser.parse_args()

    keycloak_config = keycloak_config_from_env()
    if args.device:
        device_flow_demo(keycloak_config)
    else:
        password_grant_demo(keycloak_config)
    print("\nALL DONE")


if __name__ == "__main__":
    main()
