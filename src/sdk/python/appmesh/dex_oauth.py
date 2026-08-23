"""Standards-based Dex OAuth 2.0 and OpenID Connect client support.

Identity authentication happens directly at Dex. App Mesh receives only the Dex-signed
access token as an RFC 6750 bearer token; it never receives passwords, MFA challenges, or
directory-management requests.
"""

import base64
import hashlib
import os
import secrets
import threading
import time
from typing import Any, Callable, Dict, Iterable, Optional, Tuple, Union
from urllib import parse

import requests

from .client_http import AppMeshClient
from .exceptions import AppMeshAuthError, AppMeshRequestError
from .token_provider import TokenProvider


class DexOAuthError(AppMeshAuthError):
    """Dex rejected an OAuth/OIDC request or returned an invalid response."""


class DexOAuthClient(TokenProvider):
    """Acquire Dex tokens and attach their access token to an :class:`AppMeshClient`.

    The implementation supports OAuth authorization code with PKCE (RFC 7636), device
    authorization (RFC 8628), refresh tokens, and token revocation (RFC 7009).
    """

    _DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
    _DEFAULT_SCOPES = ("openid", "profile", "email", "groups", "offline_access")
    _AUTHORIZATION_REQUEST_LIFETIME = 600

    def __init__(
        self,
        appmesh_client: AppMeshClient,
        issuer: str,
        dex_access_url: str,
        client_id: str,
        audience: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        dex_ssl_verify: Union[bool, str] = True,
        timeout: Optional[Tuple[float, float]] = None,
    ):
        if not client_id:
            raise ValueError("client_id is required")

        self.appmesh_client = appmesh_client
        self.issuer = self._normalize_base_url(issuer, "issuer")
        self.dex_access_url = self._normalize_base_url(dex_access_url, "dex_access_url")
        self.client_id = client_id
        self.audience = audience
        selected_scopes = self._DEFAULT_SCOPES if scopes is None else scopes
        self.scopes = tuple(selected_scopes.split() if isinstance(selected_scopes, str) else selected_scopes)
        # Dex and Engine are independent TLS peers. Never inherit the Engine CA
        # from appmesh_client.ssl_verify: callers select the Dex trust roots here.
        self.dex_ssl_verify = self._validate_ssl_verify(dex_ssl_verify)
        self.timeout = timeout or appmesh_client.request_timeout
        self._lock = threading.RLock()
        self.session = requests.Session()
        self.metadata = self._discover()
        self._tokens: Dict[str, Any] = {}
        self._refresh_at: Optional[float] = None
        self._grant_kind: Optional[str] = None
        self._pending_authorizations: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def from_appmesh(
        cls,
        appmesh_client: AppMeshClient,
        dex_access_url: str,
        client_id: Optional[str] = None,
        scopes: Optional[Iterable[str]] = None,
        dex_ssl_verify: Union[bool, str] = True,
    ) -> "DexOAuthClient":
        """Construct from App Mesh's public ``/appmesh/auth/config`` response.

        ``appmesh_client.base_url`` selects the Engine host. ``dex_access_url``
        independently selects how this SDK process reaches Dex, including when the
        Engine itself is local. The canonical issuer still comes from the Engine and
        must exactly match Dex discovery and token claims.
        """
        config = appmesh_client.get_auth_config()
        return cls(
            appmesh_client=appmesh_client,
            issuer=config["issuer"],
            client_id=client_id or config["public_client_id"],
            dex_access_url=dex_access_url,
            audience=config.get("audience"),
            scopes=scopes or config.get("scopes"),
            dex_ssl_verify=dex_ssl_verify,
        )

    @property
    def tokens(self) -> Dict[str, Any]:
        """Return a copy of the in-memory Dex token response."""
        with self._lock:
            return dict(self._tokens)

    @staticmethod
    def _normalize_base_url(value: str, name: str) -> str:
        """Validate and normalize an absolute HTTP(S) service base URL."""
        if not isinstance(value, str) or not value.strip():
            raise ValueError(name + " is required")
        candidate = value.strip().rstrip("/")
        parsed = parse.urlsplit(candidate)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError(name + " has an invalid port") from exc
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port is not None and not 0 < port < 65536
        ):
            raise ValueError(name + " must be an absolute HTTP(S) URL without credentials, query, or fragment")
        return candidate

    @staticmethod
    def _validate_ssl_verify(value: Union[bool, str]) -> Union[bool, str]:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value and os.path.exists(value):
            return value
        raise ValueError("dex_ssl_verify must be true, false, or an existing Dex CA path")

    def _discover(self) -> Dict[str, Any]:
        url = self.dex_access_url + "/.well-known/openid-configuration"
        try:
            response = self.session.get(url, verify=self.dex_ssl_verify, timeout=self.timeout)
            response.raise_for_status()
            metadata = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise AppMeshRequestError("Dex OIDC discovery failed") from exc

        discovered_issuer = metadata.get("issuer")
        if discovered_issuer != self.issuer:
            raise DexOAuthError("Dex discovery issuer does not match the configured issuer")
        for endpoint in ("authorization_endpoint", "token_endpoint"):
            if not metadata.get(endpoint):
                raise DexOAuthError("Dex discovery metadata is missing " + endpoint)
            self._access_endpoint(metadata[endpoint])
        return metadata

    def _access_endpoint(self, published_url: str) -> str:
        """Map a canonical Dex endpoint to this client's selected network address."""
        if not isinstance(published_url, str) or not published_url:
            raise DexOAuthError("Dex metadata published an invalid endpoint")
        published = parse.urlsplit(published_url)
        issuer = parse.urlsplit(self.issuer)
        try:
            published_port = published.port
        except ValueError as exc:
            raise DexOAuthError("Dex metadata published an endpoint with an invalid port") from exc
        if (
            published.scheme not in ("http", "https")
            or not published.hostname
            or published.username is not None
            or published.password is not None
            or published.fragment
            or published_port is not None and not 0 < published_port < 65536
            or (published.scheme, published.netloc) != (issuer.scheme, issuer.netloc)
        ):
            raise DexOAuthError("Dex metadata published an endpoint outside the configured issuer")
        issuer_path = issuer.path.rstrip("/")
        if issuer_path and published.path != issuer_path and not published.path.startswith(issuer_path + "/"):
            raise DexOAuthError("Dex metadata endpoint is outside the configured issuer path")
        suffix = published.path[len(issuer_path):]
        target = self.dex_access_url + suffix
        if published.query:
            target += "?" + published.query
        return target

    def _scope(
        self,
        scopes: Optional[Iterable[str]] = None,
        include_audience: bool = True,
        require_openid: bool = True,
    ) -> str:
        selected = self.scopes if scopes is None else scopes
        requested = selected.split() if isinstance(selected, str) else list(selected)
        if require_openid and "openid" not in requested:
            requested.insert(0, "openid")
        if include_audience and self.audience:
            audience_scope = "audience:server:client_id:" + self.audience
            if audience_scope not in requested:
                requested.append(audience_scope)
        return " ".join(dict.fromkeys(requested))

    @staticmethod
    def _oauth_error(response: requests.Response) -> DexOAuthError:
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        code = payload.get("error") or "oauth_request_failed"
        description = payload.get("error_description")
        message = str(code) if not description else "{}: {}".format(code, description)
        return DexOAuthError(message, response.status_code)

    def _post_form(self, endpoint: str, form: Dict[str, Any]) -> Dict[str, Any]:
        try:
            with self._lock:
                if self.session is None:
                    raise AppMeshRequestError("Dex OAuth client is closed")
                response = self.session.post(
                    endpoint,
                    data=form,
                    verify=self.dex_ssl_verify,
                    timeout=self.timeout,
                )
        except requests.RequestException as exc:
            raise AppMeshRequestError("Dex token request failed") from exc
        if not response.ok:
            raise self._oauth_error(response)
        try:
            return response.json()
        except ValueError as exc:
            raise DexOAuthError("Dex returned a non-JSON token response", response.status_code) from exc

    def _install(
        self,
        tokens: Dict[str, Any],
        grant_kind: Optional[str] = None,
    ) -> Dict[str, Any]:
        access_token = tokens.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise DexOAuthError("Dex token response did not include an access token")
        token_type = tokens.get("token_type", "Bearer")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise DexOAuthError("Dex returned an unsupported access-token type")

        refresh_at = None
        if tokens.get("expires_in") is not None:
            try:
                lifetime = float(tokens["expires_in"])
            except (TypeError, ValueError) as exc:
                raise DexOAuthError("Dex returned an invalid access-token lifetime") from exc
            if lifetime <= 0:
                raise DexOAuthError("Dex returned an expired access token")
            margin = min(lifetime / 2.0, max(5.0, min(60.0, lifetime * 0.1)))
            refresh_at = time.monotonic() + lifetime - margin

        with self._lock:
            self._tokens = dict(tokens)
            self._refresh_at = refresh_at
            if grant_kind is not None:
                self._grant_kind = grant_kind
            self.appmesh_client.set_token_provider(self)
            return dict(self._tokens)

    @property
    def can_refresh(self) -> bool:
        """Return whether Dex can replace the current access token."""
        with self._lock:
            return bool(self._tokens.get("refresh_token"))

    def get_access_token(self) -> Optional[str]:
        """Return a Dex access token, refreshing it shortly before expiry."""
        with self._lock:
            token = self._tokens.get("access_token")
            if token and self._refresh_at is not None and time.monotonic() >= self._refresh_at and self.can_refresh:
                return self._renew_locked()
            return token if isinstance(token, str) else None

    def refresh_access_token(self, rejected_token: Optional[str] = None) -> Optional[str]:
        """Refresh a token rejected by Engine, coalescing concurrent refreshes."""
        with self._lock:
            current = self._tokens.get("access_token")
            if rejected_token and current and current != rejected_token:
                return current
            return self._renew_locked()

    def _renew_locked(self) -> str:
        if self._tokens.get("refresh_token"):
            tokens = self._refresh_with_token_locked()
        else:
            raise DexOAuthError("No Dex credential is available to refresh the access token")
        return tokens["access_token"]

    @staticmethod
    def _pkce_pair() -> Tuple[str, str]:
        verifier = secrets.token_urlsafe(64)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        return verifier, challenge

    def authorization_request(
        self,
        redirect_uri: str,
        scopes: Optional[Iterable[str]] = None,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """Create a browser authorization request using PKCE S256.

        The request is retained in memory so :meth:`complete_authorization_callback`
        can validate the callback state before exchanging the code. This helper consumes
        access tokens for Engine API calls; it does not treat ID-token claims as an
        authenticated identity. Callers that explicitly supply ``nonce`` must also pass
        a standards-compliant ID-token validator when completing the callback.
        """
        verifier, challenge = self._pkce_pair()
        state = state or secrets.token_urlsafe(32)
        if not isinstance(state, str) or not state:
            raise ValueError("state must be a non-empty string")
        if nonce is not None and (not isinstance(nonce, str) or not nonce):
            raise ValueError("nonce must be a non-empty string when supplied")
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": self._scope(scopes),
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if nonce is not None:
            query["nonce"] = nonce

        now = time.monotonic()
        with self._lock:
            self._pending_authorizations = {
                key: value
                for key, value in self._pending_authorizations.items()
                if now - value["created_at"] <= self._AUTHORIZATION_REQUEST_LIFETIME
            }
            if state in self._pending_authorizations:
                raise DexOAuthError("An authorization request already uses this state")
            self._pending_authorizations[state] = {
                "redirect_uri": redirect_uri,
                "code_verifier": verifier,
                "nonce": nonce,
                "created_at": now,
            }

        authorization_endpoint = self.metadata["authorization_endpoint"]
        # Validate metadata, but preserve the canonical public URL for the browser.
        self._access_endpoint(authorization_endpoint)
        separator = "&" if parse.urlsplit(authorization_endpoint).query else "?"
        return {
            "authorization_url": authorization_endpoint + separator + parse.urlencode(query),
            "code_verifier": verifier,
            "state": state,
            "nonce": nonce or "",
        }

    def complete_authorization_callback(
        self,
        callback_url: str,
        id_token_validator: Optional[Callable[[str, str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Validate a browser callback and install its Dex access token.

        ``id_token_validator`` is required only when the authorization request explicitly
        included a nonce. It must cryptographically validate the ID token according to
        OIDC (signature, issuer, audience, expiry) and compare its nonce with the supplied
        expected value. The SDK itself never consumes ID-token identity claims.
        """
        if not isinstance(callback_url, str) or not callback_url:
            raise ValueError("callback_url is required")
        callback = parse.urlsplit(callback_url)
        parameters = parse.parse_qs(callback.query, keep_blank_values=True)
        states = parameters.get("state", [])
        if len(states) != 1 or not states[0]:
            raise DexOAuthError("Authorization callback is missing a single valid state")
        state = states[0]

        with self._lock:
            pending = self._pending_authorizations.pop(state, None)
        if pending is None:
            raise DexOAuthError("Authorization callback state is invalid or already consumed")
        if time.monotonic() - pending["created_at"] > self._AUTHORIZATION_REQUEST_LIFETIME:
            raise DexOAuthError("Authorization callback state has expired")

        expected_redirect = parse.urlsplit(pending["redirect_uri"])
        if (callback.scheme, callback.netloc, callback.path) != (
            expected_redirect.scheme,
            expected_redirect.netloc,
            expected_redirect.path,
        ):
            raise DexOAuthError("Authorization callback does not match the registered redirect URI")

        errors = parameters.get("error", [])
        if errors:
            description = parameters.get("error_description", [""])[0]
            message = errors[0] if not description else "{}: {}".format(errors[0], description)
            raise DexOAuthError(message)
        codes = parameters.get("code", [])
        if len(codes) != 1 or not codes[0]:
            raise DexOAuthError("Authorization callback is missing a single code")

        expected_nonce = pending["nonce"]
        if expected_nonce is not None and id_token_validator is None:
            raise DexOAuthError("An OIDC ID-token validator is required for a nonce-bearing request")

        tokens = self._exchange_authorization_code(
            code=codes[0],
            redirect_uri=pending["redirect_uri"],
            code_verifier=pending["code_verifier"],
        )
        if expected_nonce is not None:
            id_token = tokens.get("id_token")
            if not isinstance(id_token, str) or not id_token:
                raise DexOAuthError("Dex token response did not include the nonce-bound ID token")
            id_token_validator(id_token, expected_nonce, dict(self.metadata))
        return self._install(tokens, grant_kind="authorization_code")

    def _exchange_authorization_code(self, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        return self._post_form(
            self._access_endpoint(self.metadata["token_endpoint"]),
            {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            },
        )

    def exchange_authorization_code(self, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        """Low-level code exchange after the caller has independently validated state.

        Prefer :meth:`complete_authorization_callback` for browser callbacks. Do not use
        this method to consume a nonce-bearing OIDC response without independently
        validating the ID token.
        """
        tokens = self._exchange_authorization_code(code, redirect_uri, code_verifier)
        return self._install(tokens, grant_kind="authorization_code")

    def device_authorization(self, scopes: Optional[Iterable[str]] = None) -> Dict[str, Any]:
        """Start RFC 8628 device authorization and return the user-facing prompt data."""
        endpoint = self.metadata.get("device_authorization_endpoint")
        if not endpoint:
            raise DexOAuthError("Dex does not advertise a device authorization endpoint")
        device = self._post_form(
            self._access_endpoint(endpoint),
            {"client_id": self.client_id, "scope": self._scope(scopes)},
        )
        for key in ("verification_uri", "verification_uri_complete"):
            if device.get(key):
                # Validate the URL, but preserve Dex's canonical public front-channel URL.
                self._access_endpoint(device[key])
        return device

    def wait_for_device_authorization(
        self,
        device: Dict[str, Any],
        on_prompt: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Poll Dex until a device request is approved, denied, or expires."""
        if on_prompt:
            on_prompt(dict(device))
        interval = max(int(device.get("interval", 5)), 1)
        deadline = time.monotonic() + int(device.get("expires_in", 600))
        while time.monotonic() < deadline:
            time.sleep(min(interval, max(deadline - time.monotonic(), 0)))
            try:
                tokens = self._post_form(
                    self._access_endpoint(self.metadata["token_endpoint"]),
                    {
                        "grant_type": self._DEVICE_GRANT,
                        "client_id": self.client_id,
                        "device_code": device["device_code"],
                    },
                )
            except DexOAuthError as exc:
                error = str(exc).split(":", 1)[0]
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval += 5
                    continue
                raise
            return self._install(tokens, grant_kind="device_code")
        raise DexOAuthError("Device authorization expired before approval")

    def refresh(self) -> Dict[str, Any]:
        """Refresh at Dex and atomically replace the App Mesh bearer access token."""
        with self._lock:
            return self._refresh_with_token_locked()

    def _refresh_with_token_locked(self) -> Dict[str, Any]:
        refresh_token = self._tokens.get("refresh_token")
        if not refresh_token:
            raise DexOAuthError("No Dex refresh token is available")
        previous_refresh_token = refresh_token
        tokens = self._post_form(
            self._access_endpoint(self.metadata["token_endpoint"]),
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": refresh_token,
            },
        )
        if not tokens.get("refresh_token"):
            tokens["refresh_token"] = previous_refresh_token
        return self._install(tokens, grant_kind=self._grant_kind)

    def revoke(self) -> bool:
        """Revoke held Dex refresh/access tokens, then clear all local authentication state.

        Each token is revoked independently: a failure on one (network error or non-2xx) is
        recorded in the return value but does not prevent the other from being revoked.
        """
        success = True
        try:
            endpoint = self.metadata.get("revocation_endpoint")
            tokens = self.tokens
            if endpoint:
                for hint in ("refresh_token", "access_token"):
                    token = tokens.get(hint)
                    if not token:
                        continue
                    try:
                        response = self.session.post(
                            self._access_endpoint(endpoint),
                            data={"token": token, "token_type_hint": hint, "client_id": self.client_id},
                            verify=self.dex_ssl_verify,
                            timeout=self.timeout,
                        )
                        success = response.ok and success
                    except (requests.RequestException, DexOAuthError, AttributeError):
                        success = False
            else:
                success = not tokens
        except (requests.RequestException, DexOAuthError, AttributeError):
            success = False
        finally:
            self.clear()
        return success

    def clear(self) -> None:
        """Forget local tokens without making a network request."""
        with self._lock:
            self._tokens = {}
            self._refresh_at = None
            self._grant_kind = None
            self._pending_authorizations = {}
            if self.appmesh_client.token_provider is self:
                self.appmesh_client.clear_bearer_token()

    def close(self) -> None:
        """Close only local HTTP resources; call :meth:`revoke` for Dex revocation."""
        with self._lock:
            if self.session:
                self.session.close()
                self.session = None
            if self.appmesh_client.token_provider is self:
                access_token = self._tokens.get("access_token")
                if access_token:
                    self.appmesh_client.set_bearer_token(access_token)
                else:
                    self.appmesh_client.clear_bearer_token()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
