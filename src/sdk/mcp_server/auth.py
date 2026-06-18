"""
App Mesh OAuth bridge for the MCP server
========================================

App Mesh authenticates with its own JWT (username/password -> JWT via
``/appmesh/login``); it is **not** an OAuth provider. MCP clients such as Claude,
however, speak OAuth 2.1 for remote (Streamable HTTP) servers: clicking "Connect"
runs a browser login, then the client stores and auto-refreshes a token.

This module bridges the two. ``AppMeshOAuthProvider`` is a FastMCP
``OAuthProvider`` (a full OAuth 2.1 authorization server) whose token lifecycle is
backed by App Mesh login/renew:

* The OAuth **access token IS the App Mesh JWT**. Tool handlers read it back
  (via ``CurrentAccessToken``) and forward it to the daemon, so the daemon's
  RBAC remains the single source of truth.
* ``load_access_token`` validates the JWT by calling the daemon's ``/appmesh/auth``
  endpoint, so this process never needs the daemon's JWT signing secret.
* The refresh token is minted locally and mapped to the App Mesh JWT; refresh
  calls the daemon's ``/appmesh/token/renew``.

No credentials are hardcoded or persisted: the App Mesh username/password is only
seen at the moment the user submits the login form, and is never logged.

Storage is in-memory (single-process App): on restart, clients transparently
re-run the OAuth flow.

NOTE: import paths and the ``OAuthProvider`` abstract-method set are tied to the
installed ``fastmcp`` / ``mcp`` versions. Verified against fastmcp 3.x. If imports
fail on your version, adjust the import block below to match.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import html
import json
import logging
import os
import secrets
import time
from typing import Optional, Tuple
from urllib.parse import urlparse

from appmesh import AppMeshClient

from fastmcp.server.auth.auth import OAuthProvider

# Types provided by the underlying MCP Python SDK that FastMCP builds on.
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

logger = logging.getLogger("AppMesh-MCP.auth")

# Token lifetimes (seconds). The access token's real authority comes from the
# embedded App Mesh JWT; these only govern how often the OAuth layer refreshes.
ACCESS_TOKEN_TTL = int(os.environ.get("APPMESH_MCP_ACCESS_TTL", str(3600)))
REFRESH_TOKEN_TTL = int(os.environ.get("APPMESH_MCP_REFRESH_TTL", str(7 * 24 * 3600)))
AUTH_CODE_TTL = 300
LOGIN_TXN_TTL = 600

DEFAULT_SCOPES = ["appmesh"]


# --------------------------------------------------------------------------- #
# App Mesh client factory (shared by the auth bridge and the tool handlers)
# --------------------------------------------------------------------------- #
def appmesh_url() -> str:
    """Base URL of the App Mesh REST endpoint the MCP server talks to."""
    return os.environ.get("APPMESH_URL", "https://127.0.0.1:6060")


def _ssl_verify():
    """SSL verification setting for the App Mesh client.

    ``APPMESH_CA`` may be a CA file/dir path; ``APPMESH_SSL_VERIFY=false`` disables
    verification (loopback / dev only).
    """
    ca = os.environ.get("APPMESH_CA")
    if ca:
        return ca
    if os.environ.get("APPMESH_SSL_VERIFY", "true").lower() in ("false", "0", "no"):
        return False
    return True


def make_appmesh_client(jwt_token: Optional[str] = None) -> AppMeshClient:
    """Create an App Mesh SDK client, optionally pre-authenticated with ``jwt_token``."""
    return AppMeshClient(base_url=appmesh_url(), ssl_verify=_ssl_verify(), jwt_token=jwt_token)


_COOKIE_TOKEN = getattr(AppMeshClient, "_COOKIE_TOKEN", "appmesh_auth_token")


def _seed_token(client: AppMeshClient, jwt: str) -> None:
    """Seed the SDK client's session with an existing JWT for an authenticated call.

    ``AppMeshClient.set_token`` stores the cookie with a blank domain; when the daemon
    then returns its own Set-Cookie (host domain) the jar ends up with two same-named
    cookies and ``_get_access_token`` raises ``CookieConflictError``. Seeding with the
    server's host domain lets the daemon's cookie *replace* ours, keeping a single entry.
    """
    host = urlparse(appmesh_url()).hostname
    client.session.cookies.set(_COOKIE_TOKEN, jwt, domain=host, path="/")


def _login_to_appmesh(username: str, password: str, totp_code: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Authenticate against App Mesh via the SDK.

    Returns ``(jwt, None)`` on success, ``(None, challenge)`` when TOTP is required,
    and raises on failure. The password/TOTP are never logged.
    """
    client = make_appmesh_client()
    challenge = client.login(username, password, totp_code=totp_code, token_expire=REFRESH_TOKEN_TTL)
    if challenge and not totp_code:
        # HTTP 428: server wants a TOTP code for this challenge.
        return None, challenge
    jwt = client._get_access_token()  # noqa: SLF001 - SDK accessor for the issued token
    if not jwt:
        raise RuntimeError("login succeeded but no token was issued")
    return jwt, None


def _validate_totp_to_appmesh(username: str, challenge: str, totp_code: str) -> str:
    """Complete a TOTP (HTTP 428) challenge via the SDK and return the issued JWT.

    Uses the stored challenge so the user does not have to re-enter their password
    on the second step. The TOTP code is never logged.
    """
    client = make_appmesh_client()
    client.validate_totp(username, challenge, totp_code, token_expire=REFRESH_TOKEN_TTL)
    jwt = client._get_access_token()  # noqa: SLF001
    if not jwt:
        raise RuntimeError("TOTP validation succeeded but no token was issued")
    return jwt


def _logout_appmesh(jwt: str) -> None:
    """Best-effort: invalidate a JWT on the daemon via ``/appmesh/self/logoff``."""
    make_appmesh_client(jwt_token=jwt).logout()


def _decode_jwt_unverified(token: str) -> dict:
    """Decode a JWT payload WITHOUT verifying its signature (verification is the
    daemon's job via /appmesh/auth). Used only to read the ``exp`` claim so the
    OAuth layer can assist with proactive refresh. Returns {} on any parse error.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)  # restore base64 padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, binascii.Error, json.JSONDecodeError):
        return {}


def _renew_appmesh_jwt(old_jwt: str) -> str:
    """Renew an App Mesh JWT via the SDK's ``renew_token()`` and return the new token."""
    client = make_appmesh_client()
    _seed_token(client, old_jwt)
    client.renew_token(token_expire=REFRESH_TOKEN_TTL)
    jwt = client._get_access_token()  # noqa: SLF001
    if not jwt:
        raise RuntimeError("token renew returned no token")
    return jwt


def _verify_appmesh_jwt(jwt: str) -> bool:
    """Verify a JWT server-side via ``/appmesh/auth`` (no local signing secret needed)."""
    client = make_appmesh_client()
    ok, _ = client.authenticate(jwt, update_session=False)
    return ok


# --------------------------------------------------------------------------- #
# In-memory records
# --------------------------------------------------------------------------- #
class _LoginTxn:
    """A pending authorization while the user completes the login form."""

    __slots__ = ("client_id", "redirect_uri", "redirect_uri_provided_explicitly", "state", "code_challenge", "scopes", "expires_at", "username", "challenge")

    def __init__(self, params: AuthorizationParams, client_id: str):
        self.client_id = client_id
        self.redirect_uri = str(params.redirect_uri)
        self.redirect_uri_provided_explicitly = bool(getattr(params, "redirect_uri_provided_explicitly", True))
        self.state = params.state
        self.code_challenge = params.code_challenge
        self.scopes = params.scopes or list(DEFAULT_SCOPES)
        self.expires_at = time.time() + LOGIN_TXN_TTL
        # Set when a first-step login returns a TOTP challenge (HTTP 428).
        self.username: Optional[str] = None
        self.challenge: Optional[str] = None


# --------------------------------------------------------------------------- #
# The provider
# --------------------------------------------------------------------------- #
class AppMeshOAuthProvider(OAuthProvider):
    """OAuth 2.1 authorization server bridging Claude <-> App Mesh login."""

    def __init__(self, base_url: str, required_scopes: Optional[list] = None):
        super().__init__(
            base_url=base_url,
            issuer_url=base_url,
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=DEFAULT_SCOPES, default_scopes=DEFAULT_SCOPES),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=required_scopes or [],
        )
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._txns: dict[str, _LoginTxn] = {}
        # auth code -> (AuthorizationCode, appmesh_jwt)
        self._codes: dict[str, Tuple[AuthorizationCode, str]] = {}
        # refresh token string -> (RefreshToken, appmesh_jwt)
        self._refresh: dict[str, Tuple[RefreshToken, str]] = {}

    # ---- Dynamic Client Registration ----
    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self._clients[client_info.client_id] = client_info

    # ---- Authorization: hand off to our login page ----
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        self._gc()
        txn_id = secrets.token_urlsafe(32)
        self._txns[txn_id] = _LoginTxn(params, client.client_id)
        # Redirect the user-agent to our login form; it will finish the flow.
        return f"{str(self.base_url).rstrip('/')}/login?txn_id={txn_id}"

    # ---- Authorization code ----
    async def load_authorization_code(self, client: OAuthClientInformationFull, authorization_code: str) -> Optional[AuthorizationCode]:
        rec = self._codes.get(authorization_code)
        if not rec:
            return None
        code_obj, _ = rec
        if code_obj.client_id != client.client_id or code_obj.expires_at < time.time():
            return None
        return code_obj

    async def exchange_authorization_code(self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode) -> OAuthToken:
        rec = self._codes.pop(authorization_code.code, None)
        if not rec:
            raise TokenError("invalid_grant", "authorization code not found")
        _, appmesh_jwt = rec
        return self._issue_tokens(client.client_id, list(authorization_code.scopes), appmesh_jwt)

    # ---- Refresh ----
    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> Optional[RefreshToken]:
        rec = self._refresh.get(refresh_token)
        if not rec:
            return None
        rt, _ = rec
        if rt.client_id != client.client_id or (rt.expires_at is not None and rt.expires_at < time.time()):
            return None
        return rt

    async def exchange_refresh_token(self, client: OAuthClientInformationFull, refresh_token: RefreshToken, scopes: list) -> OAuthToken:
        rec = self._refresh.pop(refresh_token.token, None)
        if not rec:
            raise TokenError("invalid_grant", "refresh token not found")
        _, old_jwt = rec
        try:
            new_jwt = await asyncio.to_thread(_renew_appmesh_jwt, old_jwt)
        except Exception as exc:  # noqa: BLE001
            raise TokenError("invalid_grant", f"App Mesh token renew failed: {exc}") from exc
        granted = list(scopes) if scopes else list(refresh_token.scopes)
        return self._issue_tokens(client.client_id, granted, new_jwt)

    # ---- Access token verification (called on every MCP request) ----
    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        try:
            ok = await asyncio.to_thread(_verify_appmesh_jwt, token)
        except Exception as exc:  # noqa: BLE001
            logger.warning("access token verification error: %s", exc)
            return None
        if not ok:
            return None
        claims = _decode_jwt_unverified(token)
        exp = claims.get("exp")
        return AccessToken(
            token=token,
            client_id="appmesh",
            scopes=list(DEFAULT_SCOPES),
            expires_at=int(exp) if isinstance(exp, (int, float)) else None,
        )

    # ---- Revocation ----
    async def revoke_token(self, token) -> None:
        """Revoke a token (RFC 7009). Accepts either the refresh token or the access
        token (the App Mesh JWT). Drops local refresh state AND invalidates the JWT on
        the daemon so a revoked session cannot keep using the raw token until expiry.
        """
        tok = getattr(token, "token", None)
        if tok is None:
            return
        # If it's a refresh token, drop it and recover the bound JWT to log it off.
        rec = self._refresh.pop(tok, None)
        jwt = rec[1] if rec else tok  # access-token revocation passes the JWT directly
        try:
            await asyncio.to_thread(_logout_appmesh, jwt)
        except Exception as exc:  # noqa: BLE001 - best-effort; the token still expires on its own
            logger.warning("daemon logout during revoke failed: %s", exc)

    # ---- helpers ----
    def _issue_tokens(self, client_id: str, scopes: list, appmesh_jwt: str) -> OAuthToken:
        # Access token IS the App Mesh JWT, so tool handlers can forward it directly.
        refresh_value = secrets.token_urlsafe(48)
        self._refresh[refresh_value] = (
            RefreshToken(token=refresh_value, client_id=client_id, scopes=scopes, expires_at=int(time.time()) + REFRESH_TOKEN_TTL),
            appmesh_jwt,
        )
        return OAuthToken(
            access_token=appmesh_jwt,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            refresh_token=refresh_value,
            scope=" ".join(scopes),
        )

    def _create_code(self, txn: _LoginTxn, appmesh_jwt: str) -> str:
        code_value = secrets.token_urlsafe(32)
        code_obj = AuthorizationCode(
            code=code_value,
            client_id=txn.client_id,
            scopes=list(txn.scopes),
            expires_at=int(time.time()) + AUTH_CODE_TTL,
            code_challenge=txn.code_challenge or "",
            redirect_uri=txn.redirect_uri,
            redirect_uri_provided_explicitly=txn.redirect_uri_provided_explicitly,
        )
        self._codes[code_value] = (code_obj, appmesh_jwt)
        return code_value

    def _gc(self) -> None:
        now = time.time()
        stores = (
            (self._txns, lambda v: v.expires_at),
            (self._codes, lambda v: v[0].expires_at),
            # Refresh tokens have an expiry too; prune expired ones so the dict
            # does not grow without bound for clients that never revoke.
            (self._refresh, lambda v: v[0].expires_at if v[0].expires_at is not None else (now + 1)),
        )
        for store, getter in stores:
            for k in [k for k, v in store.items() if getter(v) < now]:
                store.pop(k, None)

    # ---- Login page (registered as a custom route on the FastMCP app) ----
    async def login_page(self, request: Request) -> Response:
        """GET renders the login form; POST authenticates against App Mesh."""
        if request.method == "GET":
            txn_id = request.query_params.get("txn_id", "")
            if txn_id not in self._txns:
                return HTMLResponse(_login_html(txn_id, error="Login session expired, please retry."), status_code=400)
            return HTMLResponse(_login_html(txn_id))

        form = await request.form()
        txn_id = str(form.get("txn_id", ""))
        username = str(form.get("username", ""))
        password = str(form.get("password", ""))
        totp_code = str(form.get("totp_code", "")) or None

        txn = self._txns.get(txn_id)
        if not txn or txn.expires_at < time.time():
            return HTMLResponse(_login_html(txn_id, error="Login session expired, please retry."), status_code=400)

        try:
            if txn.challenge:
                # Second step: complete the stored TOTP challenge (no password re-entry).
                if not totp_code:
                    return HTMLResponse(_login_html(txn_id, username=txn.username or "", need_totp=True, error="Enter your TOTP code."), status_code=401)
                jwt = await asyncio.to_thread(_validate_totp_to_appmesh, txn.username, txn.challenge, totp_code)
                challenge = None
            else:
                # First step: username/password (TOTP-enabled users get a challenge back).
                jwt, challenge = await asyncio.to_thread(_login_to_appmesh, username, password, totp_code)
        except Exception:  # noqa: BLE001 - surface auth failure to the form; never log creds or raw errors
            logger.info("App Mesh login failed for user %s", username or txn.username)
            need = bool(txn.challenge)
            return HTMLResponse(
                _login_html(txn_id, username=(txn.username or username), need_totp=need, error="Login failed. Check your credentials and try again."),
                status_code=401,
            )

        if challenge:
            # TOTP required: remember the challenge + user and re-render asking only for the code.
            txn.username = username
            txn.challenge = challenge
            return HTMLResponse(_login_html(txn_id, username=username, need_totp=True))

        self._txns.pop(txn_id, None)
        code = self._create_code(txn, jwt)
        redirect = construct_redirect_uri(txn.redirect_uri, code=code, state=txn.state)
        return RedirectResponse(url=redirect, status_code=302)


def _login_html(txn_id: str, username: str = "", error: str = "", need_totp: bool = False) -> str:
    err = f'<p style="color:#c00">{html.escape(error)}</p>' if error else ""
    user_val = html.escape(username)
    if need_totp:
        # Second step: we already hold the password challenge, so ask only for the code.
        hint = '<p>Two-factor authentication is enabled. Enter the 6-digit code from your authenticator app.</p>'
        fields = (
            f'<input type="hidden" name="username" value="{user_val}">'
            '<label>TOTP code<input name="totp_code" inputmode="numeric" autocomplete="one-time-code" autofocus></label>'
        )
    else:
        hint = ""
        fields = (
            f'<label>Username<input name="username" value="{user_val}" autofocus></label>'
            '<label>Password<input name="password" type="password"></label>'
        )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>App Mesh Login</title>
<style>body{{font-family:system-ui;max-width:360px;margin:8vh auto;padding:0 1rem}}
label{{display:block;margin:.75rem 0}}input{{width:100%;padding:.5rem;box-sizing:border-box}}
button{{margin-top:1rem;padding:.6rem 1.2rem}}</style></head>
<body><h2>App Mesh Login</h2>{err}{hint}
<form method="post" action="/login">
<input type="hidden" name="txn_id" value="{html.escape(txn_id)}">
{fields}
<button type="submit">Sign in</button>
</form></body></html>"""
