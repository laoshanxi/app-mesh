"""Password-grant token provider for unattended App Mesh SDK clients.

The provider exchanges a username/password pair for an access token at the
authentication service and re-authenticates when the token approaches expiry
or the Engine rejects it. Only access tokens cross into the Engine client;
the password never does (see :class:`appmesh.token_provider.TokenProvider`).
"""

import time
from typing import Optional, Tuple, Union

from .client_http import AppMeshClient
from .exceptions import AppMeshRequestError
from .oauth import OAuthClient, OAuthError


class PasswordGrantProvider(OAuthClient):
    """Acquire Engine access tokens with the OAuth resource-owner password grant.

    Unattended processes (containers, CI jobs, host agents) use this provider
    when a bearer token cannot be injected: it mints a token on first use,
    re-mints shortly before expiry, and re-authenticates once after an Engine
    401. With ``password_file`` the file is re-read on every grant, so a
    password rotation on the host takes effect without a process restart.

    The token endpoint must use HTTPS, or plain HTTP only on a loopback host.
    """

    def __init__(
        self,
        token_url: str,
        username: str,
        password: Optional[str] = None,
        password_file: Optional[str] = None,
        client_id: str = "appmesh-cli",
        scope: str = "openid audience:server:client_id:appmesh-api",
        appmesh_client: Optional[AppMeshClient] = None,
        ssl_verify: Union[bool, str] = True,
        timeout: Optional[Tuple[float, float]] = None,
    ):
        endpoint = self._normalize_base_url(token_url, "token_url")
        if not isinstance(username, str) or not username.strip():
            raise ValueError("username is required")
        if (password is None) == (password_file is None):
            raise ValueError("exactly one of password and password_file is required")
        if password is not None and not password:
            raise ValueError("password must be a non-empty string")
        if password_file is not None:
            try:
                self._read_password_file(password_file)
            except AppMeshRequestError as exc:
                raise ValueError(str(exc)) from exc

        self._bootstrap(
            appmesh_client=appmesh_client,
            client_id=client_id,
            ssl_verify=ssl_verify,
            timeout=timeout,
            metadata={"token_endpoint": endpoint},
        )
        self._token_endpoint_override = endpoint
        self.username = username.strip()
        self.scope = scope
        self._password = password
        self._password_file = password_file
        self._grant_dead = False

    @staticmethod
    def _read_password_file(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                password = handle.read().rstrip("\r\n")
        except OSError as exc:
            raise AppMeshRequestError(f"password file is not readable: {path}") from exc
        if not password:
            raise AppMeshRequestError(f"password file is empty: {path}")
        return password

    @property
    def can_refresh(self) -> bool:
        """Whether the credentials can still mint a replacement token."""
        with self._lock:
            return not self._grant_dead

    def get_access_token(self) -> Optional[str]:
        """Return an access token, minting one on first use or near expiry."""
        with self._lock:
            token = self._tokens.get("access_token")
            if token and (self._refresh_at is None or time.monotonic() < self._refresh_at):
                return token
            if self._grant_dead:
                return token if isinstance(token, str) else None
            return self._renew_locked()

    def refresh_access_token(self, rejected_token: Optional[str] = None) -> Optional[str]:
        """Re-authenticate after an Engine 401, coalescing concurrent refreshes."""
        with self._lock:
            current = self._tokens.get("access_token")
            if rejected_token and current and current != rejected_token:
                return current
            return self._renew_locked()

    def _renew_locked(self) -> str:
        if self._grant_dead:
            raise OAuthError("The password grant is dead; create a new provider with valid credentials")
        password = self._password
        if self._password_file is not None:
            password = self._read_password_file(self._password_file)
        try:
            tokens = self._post_form(
                self._token_endpoint_override,
                {
                    "grant_type": "password",
                    "username": self.username,
                    "password": password,
                    "scope": self.scope,
                },
                auth=(self.client_id, ""),
            )
        except OAuthError as exc:
            # invalid_grant means the credentials are dead; drop all token
            # state. Other errors are transient, so the state is kept.
            if str(exc).split(":", 1)[0] == "invalid_grant":
                self._grant_dead = True
                self.clear()
            raise
        return self._install(tokens, grant_kind="password")["access_token"]
