"""Dex-only OAuth resource-server configuration for the App Mesh MCP server."""

import os
from typing import Optional
from urllib import parse

import requests
from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl

from appmesh import AppMeshClient


def appmesh_url() -> str:
    return _absolute_base_url(os.environ.get("APPMESH_URL", "https://127.0.0.1:6060"), "APPMESH_URL")


def _ssl_verify():
    ca = os.environ.get("APPMESH_CA")
    if ca:
        return ca
    return os.environ.get("APPMESH_SSL_VERIFY", "true").lower() not in ("false", "0", "no")


def dex_issuer() -> str:
    value = os.environ.get("APPMESH_DEX_ISSUER")
    if not value:
        raise RuntimeError("APPMESH_DEX_ISSUER is required")
    return _absolute_base_url(value, "APPMESH_DEX_ISSUER")


def dex_access_url() -> str:
    """Network address this MCP process uses for Dex JWKS; issuer remains canonical."""
    value = os.environ.get("APPMESH_DEX_ACCESS_URL")
    if not value:
        raise RuntimeError("APPMESH_DEX_ACCESS_URL is required")
    return _absolute_base_url(value, "APPMESH_DEX_ACCESS_URL")


def _absolute_base_url(value: str, name: str) -> str:
    candidate = value.strip().rstrip("/") if isinstance(value, str) else ""
    parsed = parse.urlsplit(candidate)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError(name + " has an invalid port") from exc
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 0 < port < 65536)
    ):
        raise RuntimeError(name + " must be an absolute HTTP(S) URL without credentials, query, or fragment")
    return candidate


def _dex_ssl_verify():
    ca = os.environ.get("APPMESH_DEX_CA_PATH")
    if ca:
        if not os.path.exists(ca):
            raise RuntimeError("APPMESH_DEX_CA_PATH does not exist")
        return ca
    return os.environ.get("APPMESH_DEX_TLS_VERIFY", "true").lower() not in ("false", "0", "no")


def _access_endpoint(published_url: str, issuer: str, access_url: str) -> str:
    if not isinstance(published_url, str) or not published_url:
        raise RuntimeError("Dex discovery published an invalid endpoint")
    published = parse.urlsplit(published_url)
    canonical = parse.urlsplit(issuer)
    try:
        port = published.port
    except ValueError as exc:
        raise RuntimeError("Dex discovery endpoint has an invalid port") from exc
    if (
        published.scheme not in ("http", "https")
        or not published.hostname
        or published.username is not None
        or published.password is not None
        or published.fragment
        or (port is not None and not 0 < port < 65536)
        or (published.scheme, published.netloc) != (canonical.scheme, canonical.netloc)
    ):
        raise RuntimeError("Dex discovery endpoint is outside the configured issuer")
    issuer_path = canonical.path.rstrip("/")
    if issuer_path and published.path != issuer_path and not published.path.startswith(issuer_path + "/"):
        raise RuntimeError("Dex discovery endpoint is outside the configured issuer path")
    suffix = published.path[len(issuer_path) :]
    target = access_url + suffix
    if published.query:
        target += "?" + published.query
    return target


def _dex_jwks_uri(issuer: str, access_url: str) -> str:
    discovery_url = access_url + "/.well-known/openid-configuration"
    try:
        response = requests.get(discovery_url, verify=_dex_ssl_verify(), timeout=(10, 30))
        response.raise_for_status()
        metadata = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise RuntimeError("Dex OIDC discovery failed") from exc
    if metadata.get("issuer") != issuer:
        raise RuntimeError("Dex discovery issuer does not exactly match APPMESH_DEX_ISSUER")
    return _access_endpoint(metadata.get("jwks_uri"), issuer, access_url)


def make_auth_provider(base_url: str) -> RemoteAuthProvider:
    issuer = dex_issuer()
    access_url = dex_access_url()
    audience = os.environ.get("APPMESH_DEX_AUDIENCE", "appmesh-api")
    verifier = JWTVerifier(
        jwks_uri=_dex_jwks_uri(issuer, access_url),
        issuer=issuer,
        audience=audience,
        algorithm="RS256",
    )
    scopes = ["openid", "profile", "email", "groups", "offline_access", "audience:server:client_id:" + audience]
    return RemoteAuthProvider(
        token_verifier=verifier,
        authorization_servers=[AnyHttpUrl(issuer)],
        base_url=base_url,
        scopes_supported=scopes,
    )


def make_appmesh_client(bearer_token: Optional[str] = None) -> AppMeshClient:
    """Create a daemon client that forwards the caller's Dex access token unchanged."""
    return AppMeshClient(base_url=appmesh_url(), ssl_verify=_ssl_verify(), bearer_token=bearer_token)
